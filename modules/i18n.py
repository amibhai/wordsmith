"""Internationalization — exposes t(key) for all user-facing strings."""
from __future__ import annotations

import json
import locale
import logging
import os
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_LOCALE_DIR = Path(__file__).parent.parent / "locale"
_FALLBACK_LANG = "en"

_strings: dict[str, str] = {}
_active_lang: str = _FALLBACK_LANG


def _load_lang(lang: str) -> dict[str, str]:
    path = _LOCALE_DIR / f"{lang}.json"
    if not path.exists():
        logger.debug("Locale not found for %s, falling back to %s", lang, _FALLBACK_LANG)
        path = _LOCALE_DIR / f"{_FALLBACK_LANG}.json"
    if not path.exists():
        logger.warning("No locale files in %s", _LOCALE_DIR)
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning("Failed to load locale %s: %s", path, exc)
        return {}


def _detect_system_lang() -> str:
    env = os.environ.get("WORDSMITH_LANG", "")
    if env:
        return env[:2].lower()
    try:
        code, _ = locale.getdefaultlocale()
        if code:
            return code[:2].lower()
    except Exception:
        pass
    return _FALLBACK_LANG


def init(lang: Optional[str] = None) -> None:
    """Initialize i18n. Call once at startup."""
    global _strings, _active_lang
    resolved = lang if lang else _detect_system_lang()
    _active_lang = resolved
    _strings = _load_lang(resolved)
    if resolved != _FALLBACK_LANG:
        en = _load_lang(_FALLBACK_LANG)
        en.update(_strings)
        _strings = en
    logger.debug("i18n: lang=%s  %d strings", _active_lang, len(_strings))


def t(key: str, **kwargs: object) -> str:
    """Return translated string for key, falling back to the key itself."""
    raw = _strings.get(key, key)
    if kwargs:
        try:
            return raw.format(**kwargs)
        except (KeyError, IndexError):
            return raw
    return raw


def active_lang() -> str:
    return _active_lang


init()
