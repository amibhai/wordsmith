"""Tests for modules/rules.py — the hashcat rule-file export.

Validates both rule SYNTAX (valid hashcat — no John-style backslash escapes)
and FAITHFULNESS of the subset that is faithfully rule-expressible: case ops
and lower/title-cased appends reproduce what the corresponding mutator
strategy produces.
"""
from __future__ import annotations

import pytest

from modules.mutator import MutationEngine
from modules.rules import RuleExporter, _append_chain, _escape, _prepend_chain, _sub_rule
from modules.state import WordsmithSession


def _apply_rule(rule: str, word: str) -> str:
    """Minimal hashcat-rule interpreter for the opcode subset RuleExporter
    emits (: l u c C $ ^ s). Uses REAL hashcat semantics: arguments are taken
    literally (no backslash escape — that is a John convention), `s` is
    substitute-ALL, and the only escape is hashcat's `\\xNN` hex form."""
    w = word
    i = 0

    def _read_char(pos: int) -> tuple[str, int]:
        # hashcat's only escape is \xNN; everything else is literal.
        if rule[pos] == "\\" and pos + 3 < len(rule) + 1 and rule[pos + 1] == "x":
            return chr(int(rule[pos + 2:pos + 4], 16)), pos + 4
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
        elif op == "$":
            ch, i = _read_char(i)
            w = w + ch
        elif op == "^":
            ch, i = _read_char(i)
            w = ch + w
        elif op == "s":
            src, i = _read_char(i)
            dst, i = _read_char(i)
            w = w.replace(src, dst)  # substitute-ALL
        else:
            raise AssertionError(f"interpreter can't handle opcode {op!r} in rule {rule!r}")
    return w


# ── Low-level token builders ────────────────────────────────────────────────

def test_escape_passes_printable_through_unchanged():
    # Regression for the critical bug: printable args must NOT be backslashed.
    assert _escape("a") == "a"
    assert _escape("9") == "9"
    assert _escape("@") == "@"
    assert _escape("$") == "$"
    assert _escape(" ") == "\\x20"  # only space/control uses the hex form


def test_append_chain_round_trips_through_interpreter():
    rule = _append_chain("2024!")
    assert rule == "$2$0$2$4$!"
    assert _apply_rule(rule, "acme") == "acme2024!"


def test_prepend_chain_round_trips_through_interpreter():
    rule = _prepend_chain("Hi")
    assert _apply_rule(rule, "word") == "Hiword"


def test_sub_rule_round_trips_through_interpreter():
    rule = _sub_rule("a", "@")
    assert rule == "sa@"  # no backslash
    assert _apply_rule(rule, "acme") == "@cme"


def test_sub_rule_rejects_multichar_operands():
    assert _sub_rule("a", "ab") is None
    assert _sub_rule("ab", "a") is None


# ── Valid hashcat syntax (the headline fix) ──────────────────────────────────

def test_no_emitted_rule_contains_a_backslash_escape():
    """hashcat has no `\\` escape; any backslash (outside a \\xNN form) means a
    line real hashcat would silently drop. The old `_escape` emitted `$\\!`
    etc. for every symbol/leet rule."""
    exporter = RuleExporter(_session_with_context())
    for tier in ("basic", "standard", "exhaustive"):
        for line in exporter.build_rules(tier):
            assert "\\" not in line, f"{tier}: backslash in rule {line!r}"


def test_symbol_append_is_literal_dollar_bang():
    exporter = RuleExporter(WordsmithSession())
    rules = exporter.build_rules("basic")
    assert "$!" in rules       # append '!' — valid hashcat
    assert "$\\!" not in rules  # the old broken form


# ── Faithfulness: rule output must match the real mutator strategy ────────

def _session_with_context() -> WordsmithSession:
    s = WordsmithSession()
    s.target_domain = "acme.com"
    s.target_founded_year = "2011"
    return s


def test_case_rules_drop_toggle_and_match_mutator():
    assert "t" not in RuleExporter._case_rules()  # swapcase was unfaithful
    engine = MutationEngine(WordsmithSession())
    word = "acme"
    variants = set(engine._s1_case_variants(word))
    assert _apply_rule("l", word) in variants
    assert _apply_rule("u", word) in variants
    assert _apply_rule("c", word) in variants
    assert _apply_rule("C", word) in variants


def test_lowercased_append_is_faithful_to_mutator_year_suffix():
    engine = MutationEngine(_session_with_context())
    word = "Acme"
    rule = "l" + _append_chain("2024")  # lowercase, then append 2024
    produced = _apply_rule(rule, word)
    assert produced == "acme2024"
    assert produced in set(engine._s3_year_suffix(word))


def test_leet_substitute_all_semantics_match_mutator_simple_leet():
    engine = MutationEngine(WordsmithSession())
    # "banana" has only 'a' among the simple-leet chars, so substitute-all a->@
    # coincides with the mutator's simple-leet output.
    assert _apply_rule("sa@", "banana") == "b@n@n@"
    assert "b@n@n@" in set(engine._s2_leet_speak("banana"))


# ── Rule-set generation ──────────────────────────────────────────────────────

def test_build_rules_tiers_are_capped_deduped_and_start_with_noop():
    exporter = RuleExporter(_session_with_context())
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


def test_higher_tiers_are_real_supersets():
    exporter = RuleExporter(_session_with_context())
    basic = set(exporter.build_rules("basic"))
    standard = set(exporter.build_rules("standard"))
    exhaustive = set(exporter.build_rules("exhaustive"))
    assert basic <= standard, "standard must contain every basic rule"
    assert standard <= exhaustive, "exhaustive must contain every standard rule"


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

def test_rules_accepted_by_real_hashcat_if_available(tmp_path):
    """If a real hashcat binary is present, every emitted rule must be
    accepted (no 'unsupported'/'syntax' complaints) and the symbol-append
    must actually fire. Skipped when hashcat isn't installed."""
    import shutil
    import subprocess

    hc = shutil.which("hashcat")
    if not hc:
        pytest.skip("hashcat binary not on PATH")

    exporter = RuleExporter(_session_with_context())
    rule_file = tmp_path / "t.rule"
    rule_file.write_text("\n".join(exporter.build_rules("standard")) + "\n", encoding="utf-8")
    words = tmp_path / "w.txt"
    words.write_text("password\n", encoding="utf-8")

    proc = subprocess.run(
        [hc, "--stdout", "-r", str(rule_file), str(words)],
        capture_output=True, text=True, timeout=60,
    )
    out = proc.stdout.splitlines()
    err = proc.stderr.lower()
    assert "unsupported" not in err and "syntax" not in err, proc.stderr
    assert "password!" in out  # the $! rule applied to 'password'


def test_export_writes_both_files(tmp_path):
    s = WordsmithSession()
    s.target_domain = "acme-example.com"
    exporter = RuleExporter(s)
    paths = exporter.export(tmp_path, "acme-example.com", "20260731_000000", tier="basic")

    assert paths["rules"].exists()
    assert paths["seeds"].exists()
    assert paths["rules"].suffix == ".rule"
    assert len(paths["rules"].read_text(encoding="utf-8").splitlines()) > 0
