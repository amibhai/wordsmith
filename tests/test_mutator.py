"""Tests for modules/mutator.py — individual strategy spot-checks plus the
streaming/bounded orchestration in mutate_all()."""
from __future__ import annotations

from datetime import datetime

from modules.mutator import MutationEngine
from modules.scoring import score_word
from modules.state import WordsmithSession


def _engine(session: WordsmithSession | None = None) -> MutationEngine:
    return MutationEngine(session or WordsmithSession())


# ── Individual strategy spot-checks ─────────────────────────────────────────

def test_case_variants_cover_common_forms():
    variants = _engine()._s1_case_variants("acme")
    assert "acme" in variants
    assert "ACME" in variants
    assert "Acme" in variants


def test_leet_speak_produces_known_substitutions():
    variants = _engine()._s2_leet_speak("acme")
    assert "@cme" in variants  # single 'a' -> '@' from data/leet_map.json


def test_year_suffix_includes_current_year():
    engine = _engine()
    year = str(datetime.now().year)
    variants = engine._s3_year_suffix("acme")
    assert any(v.endswith(year) for v in variants)


def test_number_and_symbol_append():
    engine = _engine()
    assert "acme123" in engine._s5_number_append("acme")
    assert "acme!" in engine._s4_symbol_append("acme")


def test_keyboard_walks_present():
    engine = _engine()
    variants = engine._s7_keyboard_walks("acme")
    assert any("qwerty" in v for v in variants)


# ── Inline policy filtering ─────────────────────────────────────────────────

def test_inline_policy_filter_rejects_short_words():
    session = WordsmithSession()
    session.policy = {"min_length": 8}
    engine = _engine(session)
    assert engine._passes_policy("short") is False
    assert engine._passes_policy("longenough1") is True


def test_inline_policy_filter_enforces_required_charsets():
    session = WordsmithSession()
    session.policy = {"require_upper": True, "require_number": True}
    engine = _engine(session)
    assert engine._passes_policy("alllower") is False
    assert engine._passes_policy("Upper1Only") is True


# ── Streaming / bounded orchestration ───────────────────────────────────────

def test_mutate_all_respects_max_words_cap():
    session = WordsmithSession()
    session.target_domain = "acme-example.com"
    engine = _engine(session)
    result = engine.mutate_all(["acme", "corp", "widgets"], max_words=25, max_scan=None)
    assert len(result) <= 25


def test_mutate_all_scan_ceiling_bounds_output():
    session = WordsmithSession()
    engine = _engine(session)
    result = engine.mutate_all(
        ["acme", "corporation", "widgets", "cloud"], max_words=1000, max_scan=10
    )
    assert len(result) <= 10


def test_mutate_all_orders_by_score_descending():
    session = WordsmithSession()
    session.target_name = "Acme"
    engine = _engine(session)
    result = engine.mutate_all(["acme", "xyz"], max_words=500, max_scan=None)
    assert result  # non-empty
    scores = [score_word(w, session) for w in result]
    assert scores == sorted(scores, reverse=True)


def test_mutate_all_empty_input_returns_empty():
    engine = _engine()
    assert engine.mutate_all([]) == []
    assert engine.mutate_all(["a"]) == []  # below the 2-char minimum


def test_disabled_strategies_are_not_applied():
    session = WordsmithSession()
    engine = _engine(session)
    engine.enable_strategies([1])  # case variants only
    result = engine.mutate_all(["acme"], max_words=1000, max_scan=None)
    # Strategy 5 (number append) should not have fired.
    assert "acme123" not in result
    assert "Acme" in result or "ACME" in result
