"""Session state management — persist and resume wordsmith sessions."""
from __future__ import annotations

import json
import logging
import signal
import sys
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

SESSIONS_DIR = Path.home() / ".wordsmith" / "sessions"


@dataclass
class WordsmithSession:
    """Full state for one wordsmith engagement."""

    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    target_domain: str = ""
    target_name: str = ""
    target_emails: list[str] = field(default_factory=list)
    target_employees: list[str] = field(default_factory=list)
    target_keywords: list[str] = field(default_factory=list)
    target_products: list[str] = field(default_factory=list)
    target_location: str = ""
    target_founded_year: str = ""
    osint_data: dict = field(default_factory=dict)
    scraped_words: list[str] = field(default_factory=list)
    base_words: list[str] = field(default_factory=list)
    mutated_words: list[str] = field(default_factory=list)
    final_wordlist_path: str = ""
    final_wordlist_size: int = 0
    strategies_used: list[str] = field(default_factory=list)
    policy: dict = field(default_factory=dict)
    scope_file: str = ""

    # ── Convenience helpers ───────────────────────────────────────────────────

    def all_seed_words(self) -> list[str]:
        """Return deduplicated union of all seed word collections."""
        seen: set[str] = set()
        result: list[str] = []
        for src in (
            self.target_keywords,
            self.target_products,
            self.scraped_words,
            self.base_words,
        ):
            for w in src:
                low = w.lower()
                if low not in seen:
                    seen.add(low)
                    result.append(w)
        return result

    def add_keywords(self, words: list[str]) -> None:
        existing = {w.lower() for w in self.target_keywords}
        for w in words:
            if w.lower() not in existing:
                self.target_keywords.append(w)
                existing.add(w.lower())


class SessionManager:
    """Manage lifecycle, persistence and cleanup of a WordsmithSession."""

    def __init__(self) -> None:
        SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
        self.session = WordsmithSession()
        self._register_signals()

    def _register_signals(self) -> None:
        signal.signal(signal.SIGINT, self._handle_signal)
        try:
            signal.signal(signal.SIGTERM, self._handle_signal)
        except (OSError, ValueError):
            pass

    def _handle_signal(self, signum: int, frame: object) -> None:
        logger.info("Signal %d — saving session and exiting", signum)
        self.save()
        sys.exit(0)

    # ── Persistence ───────────────────────────────────────────────────────────

    def save(self) -> Path:
        """Persist session to disk. Returns the file path."""
        path = SESSIONS_DIR / f"{self.session.session_id}.json"
        path.write_text(
            json.dumps(asdict(self.session), indent=2, default=str),
            encoding="utf-8",
        )
        logger.debug("Session saved: %s", path)
        return path

    @classmethod
    def load(cls, session_id: str) -> "SessionManager":
        """Resume a previously-saved session."""
        path = SESSIONS_DIR / f"{session_id}.json"
        if not path.exists():
            raise FileNotFoundError(f"Session not found: {session_id}")
        data = json.loads(path.read_text(encoding="utf-8"))
        mgr = cls.__new__(cls)
        mgr._register_signals = cls._register_signals.__get__(mgr, cls)  # type: ignore[method-assign]
        mgr._register_signals()
        SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
        valid = WordsmithSession.__dataclass_fields__.keys()
        filtered = {k: v for k, v in data.items() if k in valid}
        mgr.session = WordsmithSession(**filtered)
        return mgr

    # ── Discovery ─────────────────────────────────────────────────────────────

    @staticmethod
    def list_sessions() -> list[dict]:
        """Return metadata for all saved sessions."""
        if not SESSIONS_DIR.exists():
            return []
        results: list[dict] = []
        for f in sorted(SESSIONS_DIR.glob("*.json"), reverse=True):
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                results.append({
                    "session_id": data.get("session_id", f.stem),
                    "timestamp": data.get("timestamp", ""),
                    "target_domain": data.get("target_domain", ""),
                    "target_name": data.get("target_name", ""),
                    "final_wordlist_path": data.get("final_wordlist_path", ""),
                    "path": str(f),
                })
            except Exception:
                pass
        return results
