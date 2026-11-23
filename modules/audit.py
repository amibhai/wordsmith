"""HMAC-chained audit log — every action is cryptographically linked.

Trust model: the chain is signed with a random key generated on first use and
persisted locally (see `_key_path()`), alongside a tiny `<session>.head`
anchor recording the last sequence number and HMAC. Together these make the
log tamper-evident against post-hoc edits to the log file on disk — including
**trailing truncation**, which a bare forward-chain cannot detect on its own.

This is NOT a substitute for OS-level access control: anyone who can read the
key file (it sits next to the logs) can forge the whole chain. Verifying a log
on a different machine requires securely transferring the key file — and, for
the truncation check, the `.head` file — the same caveat that applies to any
locally-anchored audit trail. A missing key is reported as "cannot verify",
never as tampering.
"""
from __future__ import annotations

import hashlib
import hmac as _hmac
import json
import logging
import os
import secrets
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

AUDIT_DIR = Path.home() / ".wordsmith" / "audit"

_KEY_LEN = 32
GENESIS = "0" * 64
# Keyed by resolved path (not a single global) so that pointing AUDIT_DIR at
# a different directory — e.g. a tmp_path in tests — can never accidentally
# return a stale key cached from a previous AUDIT_DIR.
_key_cache: dict[str, bytes] = {}


def _key_path() -> Path:
    return AUDIT_DIR / ".hmac_key"


def _load_or_create_key() -> bytes:
    """Return the local HMAC signing key, generating one on first use.

    The key is created with restrictive permissions and never leaves the
    machine. A race between two processes creating it simultaneously is
    resolved by O_EXCL: the loser simply reads back what the winner wrote.
    """
    AUDIT_DIR.mkdir(parents=True, exist_ok=True)
    path = _key_path()
    cache_key = str(path)

    cached = _key_cache.get(cache_key)
    if cached is not None:
        return cached

    if path.exists():
        key = path.read_bytes()
        _key_cache[cache_key] = key
        return key

    new_key = secrets.token_bytes(_KEY_LEN)
    try:
        # O_BINARY (Windows-only) prevents the C runtime from translating
        # 0x0A bytes in the random key into 0x0D 0x0A on write — without it
        # os.open() defaults to text mode on Windows and silently corrupts
        # any key containing a newline byte.
        binary_flag = getattr(os, "O_BINARY", 0)
        fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY | binary_flag, 0o600)
        try:
            os.write(fd, new_key)
        finally:
            os.close(fd)
        try:
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass  # best-effort on platforms without POSIX permission bits
        key = new_key
    except FileExistsError:
        # Lost the creation race — another process wrote it first.
        key = path.read_bytes()

    _key_cache[cache_key] = key
    return key


def _load_key_readonly() -> bytes | None:
    """Return the signing key if it already exists, else None.

    Never creates a key. Used by verify() so a missing key is reported as
    "cannot verify" rather than silently minting a fresh key and then
    declaring every entry tampered.
    """
    path = _key_path()
    cache_key = str(path)
    cached = _key_cache.get(cache_key)
    if cached is not None:
        return cached
    if path.exists():
        key = path.read_bytes()
        _key_cache[cache_key] = key
        return key
    return None


class AuditLogger:
    """
    Append-only HMAC-chained JSON-lines audit log.

    Each entry carries a monotonic ``seq`` and a ``prev_hash`` and is
    HMAC-SHA256 signed over (seq + prev_hash + entry). Tampering with any
    entry breaks all subsequent HMAC checks; reordering or mid-file deletion
    breaks the seq/prev_hash chain; trailing truncation is caught by the
    ``.head`` anchor. Reopening an existing log (resume, or generating a
    report for a past session) **continues** the chain instead of resetting
    it — the previous implementation reset to genesis on every open, which
    made ``verify`` report tampering on perfectly legitimate logs.
    """

    def __init__(self, session_id: str) -> None:
        self.session_id = session_id
        AUDIT_DIR.mkdir(parents=True, exist_ok=True)
        self._path = AUDIT_DIR / f"{session_id}.log"
        self._head_path = AUDIT_DIR / f"{session_id}.head"
        prev_hash, next_seq, resumed = self._recover_tail()
        self._prev_hash = prev_hash
        self._seq = next_seq
        self.log("audit.resume" if resumed else "audit.init", session_id=session_id)

    # ── Public API ────────────────────────────────────────────────────────────

    def log(self, event: str, **data: Any) -> None:
        """Append a signed, chained entry to the audit log."""
        entry: dict[str, Any] = {
            "session_id": self.session_id,
            "seq": self._seq,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "data": data,
            "prev_hash": self._prev_hash,
        }
        mac = self._sign(entry)
        entry["hmac"] = mac

        try:
            with open(self._path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, default=str) + "\n")
        except OSError as exc:
            logger.warning("Audit write failed: %s", exc)
            return  # do not advance the in-memory chain if nothing hit disk

        self._prev_hash = mac
        self._seq += 1
        self._write_head(entry["seq"], mac)

    def close(self, success: bool = False) -> None:
        """Log session termination."""
        self.log("session.end", success=success)

    @property
    def path(self) -> Path:
        return self._path

    @property
    def head_path(self) -> Path:
        return self._head_path

    # ── Internal: tail recovery + head anchor ──────────────────────────────────

    def _recover_tail(self) -> tuple[str, int, bool]:
        """Return (prev_hash, next_seq, resumed) for the current on-disk log.

        Genesis for a new/empty/unreadable file; otherwise continue from the
        last line's hmac + seq so reopening a session never resets the chain.
        """
        if not self._path.exists():
            return GENESIS, 0, False
        last = None
        try:
            with open(self._path, encoding="utf-8") as fh:
                for raw in fh:
                    raw = raw.strip()
                    if raw:
                        last = raw
        except OSError:
            return GENESIS, 0, False
        if last is None:
            return GENESIS, 0, False
        try:
            entry = json.loads(last)
            prev = str(entry["hmac"])
            seq = int(entry.get("seq", -1)) + 1
            return prev, seq, True
        except (json.JSONDecodeError, KeyError, ValueError, TypeError):
            # Corrupt tail: keep chaining from genesis so verify() surfaces the
            # discontinuity rather than us silently papering over it.
            return GENESIS, 0, True

    def _write_head(self, seq: int, mac: str) -> None:
        """Atomically record the latest (seq, hmac) so trailing truncation of
        the log becomes detectable at verify time."""
        try:
            payload = json.dumps({"last_seq": seq, "last_hmac": mac}).encode("utf-8")
            fd, tmp = tempfile.mkstemp(dir=str(AUDIT_DIR), prefix=".head.", suffix=".tmp")
            try:
                os.write(fd, payload)
            finally:
                os.close(fd)
            os.replace(tmp, self._head_path)
        except OSError as exc:
            logger.warning("Audit head write failed: %s", exc)

    # ── Verification ──────────────────────────────────────────────────────────

    @staticmethod
    def verify(session_id: str) -> tuple[bool, int, str]:
        """
        Replay the HMAC chain from genesis.
        Returns (ok, entry_count, message).
        """
        path = AUDIT_DIR / f"{session_id}.log"
        head_path = AUDIT_DIR / f"{session_id}.head"
        if not path.exists():
            return False, 0, f"Log not found: {path}"

        key = _load_key_readonly()
        if key is None:
            return False, 0, (
                f"Signing key not found at {_key_path()} — cannot verify this "
                "log. This is NOT evidence of tampering: copy the key file from "
                "the machine that created the log and re-run verification."
            )

        prev_hash = GENESIS
        count = 0
        expected_seq = 0
        last_hmac = GENESIS
        seq_mode = False  # enforce seq only for logs that carry it (new format)

        try:
            with open(path, encoding="utf-8") as fh:
                for raw in fh:
                    raw = raw.strip()
                    if not raw:
                        continue
                    try:
                        entry = json.loads(raw)
                    except json.JSONDecodeError:
                        return False, count, f"JSON parse error at entry {count + 1}"

                    stored_hmac = entry.pop("hmac", None)
                    if stored_hmac is None:
                        return False, count, f"Missing HMAC at entry {count + 1}"

                    if count == 0:
                        seq_mode = "seq" in entry

                    if entry.get("prev_hash") != prev_hash:
                        return False, count, (
                            f"Chain broken at entry {count + 1}: "
                            f"prev_hash mismatch (expected {prev_hash[:16]}…)"
                        )

                    if seq_mode and entry.get("seq") != expected_seq:
                        return False, count, (
                            f"Sequence broken at entry {count + 1}: "
                            f"expected seq {expected_seq}, found {entry.get('seq')!r}"
                        )

                    expected = AuditLogger._sign_dict_with_key(entry, key)
                    if not _hmac.compare_digest(stored_hmac, expected):
                        return False, count, (
                            f"HMAC mismatch at entry {count + 1}: "
                            "log may have been tampered with"
                        )

                    prev_hash = stored_hmac
                    last_hmac = stored_hmac
                    count += 1
                    expected_seq += 1
        except OSError as exc:
            return False, count, f"Read error: {exc}"

        if count == 0:
            return False, 0, "Log is empty"

        # Trailing-truncation check against the head anchor (new-format logs).
        final_seq = count - 1
        if head_path.exists():
            try:
                head = json.loads(head_path.read_text(encoding="utf-8"))
                h_seq = int(head["last_seq"])
                h_hmac = str(head["last_hmac"])
            except (OSError, json.JSONDecodeError, KeyError, ValueError, TypeError):
                return True, count, (
                    f"Chain intact — {count} entries verified "
                    "(head anchor unreadable; trailing-truncation check skipped)"
                )
            if h_seq > final_seq:
                return False, count, (
                    f"Trailing truncation detected: head records seq {h_seq} but "
                    f"log ends at seq {final_seq} ({h_seq - final_seq} entr"
                    f"{'y' if h_seq - final_seq == 1 else 'ies'} removed from the end)"
                )
            if h_seq == final_seq and not _hmac.compare_digest(h_hmac, last_hmac):
                return False, count, (
                    "Head/log mismatch at the final entry — log may have been altered"
                )
            return True, count, f"Chain intact — {count} entries verified (head anchor OK)"

        return True, count, (
            f"Chain intact — {count} entries verified "
            "(no head anchor; trailing truncation not checkable)"
        )

    # ── Internal ──────────────────────────────────────────────────────────────

    def _sign(self, entry: dict[str, Any]) -> str:
        return self._sign_dict(entry)

    @staticmethod
    def _sign_dict(entry: dict[str, Any]) -> str:
        return AuditLogger._sign_dict_with_key(entry, _load_or_create_key())

    @staticmethod
    def _sign_dict_with_key(entry: dict[str, Any], key: bytes) -> str:
        payload = json.dumps(entry, sort_keys=True, default=str).encode()
        return _hmac.new(key, payload, hashlib.sha256).hexdigest()


# ── Module-level convenience ──────────────────────────────────────────────────

_active: dict[str, AuditLogger] = {}


def get_logger(session_id: str) -> AuditLogger:
    """Return (creating if needed) the AuditLogger for this session."""
    if session_id not in _active:
        _active[session_id] = AuditLogger(session_id)
    return _active[session_id]
