"""Tests for modules/rules.py — the hashcat rule-file export ("beast"
feature). Validates both rule syntax and *faithfulness*: that simulating a
handful of emitted rules reproduces what the corresponding mutator
strategy actually produces, not just something superficially plausible.
"""
from __future__ import annotations

import pytest

from modules.mutator import MutationEngine
from modules.rules import RuleExporter, _append_chain, _escape, _prepend_chain, _sub_rule
from modules.state import WordsmithSession


def _apply_rule(rule: str, word: str) -> str:
    """Minimal hashcat-rule interpreter covering exactly the opcode subset
    RuleExporter emits (: l u c C t $ ^ s) — enough to check faithfulness
    without requiring a real hashcat binary in CI."""
    w = word
    i = 0

    def _read_char(pos: int) -> tuple[str, int]:
        if rule[pos] == "\\":
            return rule[pos + 1], pos + 2
        return rule[pos], pos + 1

    while i < len(rule):
        op = rule[i]
        i += 1
        if op == ":":
            continue
        elif op == "l":
            w = w.lower()
        elif op == "u":
            w = w.upper()
        elif op == "c":
            w = w[:1].upper() + w[1:].lower() if w else w
        elif op == "C":
            w = w[:1].lower() + w[1:].upper() if w else w
        elif op == "t":
            w = w.swapcase()
        elif op == "$":
            ch, i = _read_char(i)
            w = w + ch
        elif op == "^":
            ch, i = _read_char(i)
            w = ch + w
        elif op == "s":
            src, i = _read_char(i)
            dst, i = _read_char(i)
            w = w.replace(src, dst)
        else:
            raise AssertionError(f"test interpreter can't handle opcode {op!r} in rule {rule!r}")
    return w


# ── Low-level token builders ────────────────────────────────────────────────

def test_escape_only_touches_non_alnum():
    assert _escape("a") == "a"
    assert _escape("9") == "9"
    assert _escape("@") == "\\@"
    assert _escape("$") == "\\$"


def test_append_chain_round_trips_through_interpreter():
    rule = _append_chain("2024!")
    assert _apply_rule(rule, "acme") == "acme2024!"


def test_prepend_chain_round_trips_through_interpreter():
    rule = _prepend_chain("Hi")
    assert _apply_rule(rule, "word") == "Hiword"


def test_sub_rule_round_trips_through_interpreter():
    rule = _sub_rule("a", "@")
    assert _apply_rule(rule, "acme") == "@cme"


def test_sub_rule_rejects_multichar_operands():
    assert _sub_rule("a", "ab") is None
    assert _sub_rule("ab", "a") is None


# ── Faithfulness: rule output must match the real mutator strategy ────────

def test_case_rules_match_mutator_case_variants():
    engine = MutationEngine(WordsmithSession())
    word = "acme"
    variants = set(engine._s1_case_variants(word))
    assert _apply_rule("l", word) in variants
    assert _apply_rule("u", word) in variants
    assert _apply_rule("c", word) in variants


def test_leet_sub_rule_matches_mutator_leet_speak():
    engine = MutationEngine(WordsmithSession())
    word = "acme"  # exactly one 'a' -> substitute-all/substitute-one coincide
    variants = set(engine._s2_leet_speak(word))
    assert _apply_rule("sa@", word) in variants


# ── Rule-set generation ──────────────────────────────────────────────────────

def test_build_rules_tiers_are_capped_deduped_and_start_with_noop():
    exporter = RuleExporter(WordsmithSession())
    for tier in ("basic", "standard", "exhaustive"):
        rules = exporter.build_rules(tier)
        assert rules, f"{tier} tier produced no rules"
        assert len(rules) == len(set(rules)), f"{tier} tier has duplicate lines"
        assert rules[0] == ":"  # noop first, so the raw base word is always tried
        assert all(" " not in line for line in rules), "rule lines must not contain spaces"


def test_build_rules_unknown_tier_raises():
    exporter = RuleExporter(WordsmithSession())
    with pytest.raises(ValueError):
        exporter.build_rules("ultra")


def test_higher_tiers_are_supersets_in_spirit_and_not_smaller():
    exporter = RuleExporter(WordsmithSession())
    basic = exporter.build_rules("basic")
    standard = exporter.build_rules("standard")
    exhaustive = exporter.build_rules("exhaustive")
    assert len(standard) >= len(basic)
    assert len(exhaustive) >= len(standard)


# ── Seed words ────────────────────────────────────────────────────────────

def test_build_seeds_pulls_target_context():
    s = WordsmithSession()
    s.target_name = "Acme"
    s.target_domain = "acme-example.com"
    s.target_employees = ["Rahul Sharma"]
    s.target_products = ["AcmeCloud"]
    s.target_location = "Mumbai"

    seeds = RuleExporter(s).build_seeds()
    assert "Acme" in seeds
    assert "acme-example" in seeds
    assert "Rahul" in seeds and "Sharma" in seeds
    assert "AcmeCloud" in seeds
    assert "Mumbai" in seeds


def test_build_seeds_deduplicates_case_insensitively():
    s = WordsmithSession()
    s.target_name = "Acme"
    s.target_keywords = ["acme", "ACME", "cloud"]
    seeds = RuleExporter(s).build_seeds()
    assert seeds.count("Acme") + seeds.count("acme") + seeds.count("ACME") == 1


# ── File export ──────────────────────────────────────────────────────────

def test_export_writes_both_files(tmp_path):
    s = WordsmithSession()
    s.target_domain = "acme-example.com"
    exporter = RuleExporter(s)
    paths = exporter.export(tmp_path, "acme-example.com", "20260731_000000", tier="basic")

    assert paths["rules"].exists()
    assert paths["seeds"].exists()
    assert paths["rules"].suffix == ".rule"
    assert len(paths["rules"].read_text(encoding="utf-8").splitlines()) > 0
