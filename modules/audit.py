"""HMAC-chained audit log — every action is cryptographically linked.

Trust model: the chain is signed with a random key generated on first use
and persisted locally (see `_key_path()`). This makes the log tamper-evident
against post-hoc edits to the log file on disk — it is NOT a substitute for
OS-level access control, and verifying a log on a different machine requires
securely transferring that key file too (the same caveat that applies to any
locally-anchored audit trail).
"""
from __future__ import annotations

import hashlib
import hmac as _hmac
import json
import logging
import os
import secrets
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

AUDIT_DIR = Path.home() / ".wordsmith" / "audit"

_KEY_LEN = 32
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


class AuditLogger:
    """
    Append-only HMAC-chained JSON-lines audit log.

    Each entry is HMAC-SHA256 signed over (prev_hash + entry_json),
    creating an unforgeable chain. Tampering with any entry breaks
    all subsequent HMAC checks.
    """

    def __init__(self, session_id: str) -> None:
        self.session_id = session_id
        AUDIT_DIR.mkdir(parents=True, exist_ok=True)
        self._path = AUDIT_DIR / f"{session_id}.log"
        self._prev_hash = "0" * 64  # genesis sentinel
        self.log("audit.init", session_id=session_id)

    # ── Public API ────────────────────────────────────────────────────────────

    def log(self, event: str, **data: Any) -> None:
        """Append a signed, chained entry to the audit log."""
        entry: dict[str, Any] = {
            "session_id": self.session_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "data": data,
            "prev_hash": self._prev_hash,
        }
        mac = self._sign(entry)
        entry["hmac"] = mac
        self._prev_hash = mac

        try:
            with open(self._path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, default=str) + "\n")
        except OSError as exc:
            logger.warning("Audit write failed: %s", exc)

    def close(self, success: bool = False) -> None:
        """Log session termination."""
        self.log("session.end", success=success)

    @property
    def path(self) -> Path:
        return self._path

    # ── Verification ──────────────────────────────────────────────────────────

    @staticmethod
    def verify(session_id: str) -> tuple[bool, int, str]:
        """
        Replay the HMAC chain from genesis.
        Returns (ok, entry_count, message).
        """
        path = AUDIT_DIR / f"{session_id}.log"
        if not path.exists():
            return False, 0, f"Log not found: {path}"

        prev_hash = "0" * 64
        count = 0

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

                    if entry.get("prev_hash") != prev_hash:
                        return False, count, (
                            f"Chain broken at entry {count + 1}: "
                            f"prev_hash mismatch (expected {prev_hash[:16]}…)"
                        )

                    expected = AuditLogger._sign_dict(entry)
                    if not _hmac.compare_digest(stored_hmac, expected):
                        return False, count, (
                            f"HMAC mismatch at entry {count + 1}: "
                            "log may have been tampered with"
                        )

                    prev_hash = stored_hmac
                    count += 1
        except OSError as exc:
            return False, count, f"Read error: {exc}"

        return True, count, f"Chain intact — {count} entries verified"

    # ── Internal ──────────────────────────────────────────────────────────────

    def _sign(self, entry: dict[str, Any]) -> str:
        return self._sign_dict(entry)

    @staticmethod
    def _sign_dict(entry: dict[str, Any]) -> str:
        payload = json.dumps(entry, sort_keys=True, default=str).encode()
        return _hmac.new(_load_or_create_key(), payload, hashlib.sha256).hexdigest()


# ── Module-level convenience ──────────────────────────────────────────────────

_active: dict[str, AuditLogger] = {}


def get_logger(session_id: str) -> AuditLogger:
    """Return (creating if needed) the AuditLogger for this session."""
    if session_id not in _active:
        _active[session_id] = AuditLogger(session_id)
    return _active[session_id]
