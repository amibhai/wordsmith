"""HMAC-chained audit log — every action is cryptographically linked."""
from __future__ import annotations

import hashlib
import hmac as _hmac
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

AUDIT_DIR = Path.home() / ".wordsmith" / "audit"
_SECRET = b"wordsmith-audit-chain-v1"


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
        return _hmac.new(_SECRET, payload, hashlib.sha256).hexdigest()


# ── Module-level convenience ──────────────────────────────────────────────────

_active: dict[str, AuditLogger] = {}


def get_logger(session_id: str) -> AuditLogger:
    """Return (creating if needed) the AuditLogger for this session."""
    if session_id not in _active:
        _active[session_id] = AuditLogger(session_id)
    return _active[session_id]
