"""Hashcat rule-file export — turn wordsmith's mutation logic into a
`.rule` file usable with `hashcat -a 0 -r <file> <any-base-wordlist>`.

This is the difference between wordsmith only ever producing a fixed-size
flat wordlist, and wordsmith producing a *transformation* that can be
applied to any base dictionary an operator already has (rockyou, SecLists,
a client-specific corpus, ...) at hashcat-native speed, without ever
materializing millions of lines in Python.

Hashcat rules only *transform* lines of a base wordlist — they cannot
invent target-specific words from nothing. `RuleExporter.export()`
therefore always writes a companion `_seeds.txt` file alongside the
`.rule` file, containing just the target-specific seed words (org name,
domain fragment, employee name parts, products, location). Pair the two:

    cat wordsmith_acme_seeds.txt rockyou.txt > combined.txt
    hashcat -a 0 -r wordsmith_acme.rule combined.txt hash.txt

Rule syntax reference: https://hashcat.net/wiki/doku.php?id=rule_based_attack
"""
from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path

from .state import WordsmithSession

logger = logging.getLogger(__name__)

_DATA_DIR = Path(__file__).parent.parent / "data"

RULE_TIERS = ("basic", "standard", "exhaustive")

# Upper bound on emitted rule lines per tier — a safety cap, not a target;
# real output is normally well under this for a reviewable, high-signal
# rule file rather than padded-out noise.
_TIER_CEILING: dict[str, int] = {
    "basic": 150,
    "standard": 1000,
    "exhaustive": 4000,
}


def _escape(ch: str) -> str:
    """Return a hashcat-safe single-character argument for the $, ^ and s
    functions.

    CRITICAL: hashcat takes the byte after an opcode LITERALLY and has **no
    backslash escaping** — `\\` is a John the Ripper convention. The old code
    emitted `$\\!`, `$\\@`, `sa\\@` etc., which real hashcat rejects as
    malformed (it reads `$\\` = append backslash, then `!` as a reject
    opcode) and silently drops the whole line — so essentially every
    symbol/leet rule was dead on arrival.

    Printable characters therefore pass through unchanged: append '!' is
    `$!`, append '$' is `$$`, substitute a->@ is `sa@`. Only space / control
    bytes need hashcat's `\\xNN` hex form, which none of wordsmith's data
    tables currently contain.
    """
    if ch == " " or not ch.isprintable():
        return f"\\x{ord(ch):02x}"
    return ch


def _append_chain(suffix: str) -> str:
    """'2024!' -> '$2$0$2$4$!' — one $ (append-to-end) token per character,
    left to right, matching normal suffix reading order."""
    return "".join(f"${_escape(c)}" for c in suffix)


def _prepend_chain(prefix: str) -> str:
    """'Hi' -> '^i^H' — ^ pushes a character onto the FRONT of the current
    word, so the chain must be built in reverse for the final prefix to
    read left-to-right: applying '^i' then '^H' yields 'Hi' + word."""
    return "".join(f"^{_escape(c)}" for c in reversed(prefix))


def _sub_rule(src: str, dst: str) -> str | None:
    """'a', '@' -> 'sa@' — substitute-ALL occurrences. Only valid for
    single-character src/dst pairs; hashcat's sXY takes exactly one char
    each (so multi-char leet like n->'|\\|' is correctly skipped)."""
    if len(src) != 1 or len(dst) != 1:
        return None
    return f"s{_escape(src)}{_escape(dst)}"


def _load_json(filename: str):
    try:
        return json.loads((_DATA_DIR / filename).read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning("rules: failed to load %s: %s", filename, exc)
        return {}


class RuleExporter:
    """Builds a hashcat-compatible .rule file (+ companion seeds file) from
    the current session's OSINT context and wordsmith's data tables. Kept
    independent of MutationEngine — it re-derives its own small rule set
    directly from data/leet_map.json and data/suffixes.json rather than
    trying to "compile" all 13 mutator strategies (several of them, like
    word_combinator or scraped-corpus-driven ones, don't have a faithful
    fixed-length hashcat rule equivalent)."""

    def __init__(self, session: WordsmithSession) -> None:
        self.session = session
        self._leet_map: dict = _load_json("leet_map.json")
        self._suffixes: dict = _load_json("suffixes.json")
        self._current_year = datetime.now().year

    # ── Rule line generation ────────────────────────────────────────────

    @staticmethod
    def _case_rules() -> list[str]:
        # No `t` (toggle/swapcase): the mutator's _s1 never emits swapcase, so
        # it was an unfaithful token. The remaining five map exactly onto
        # _s1's lower / upper / capitalize / "first-lower-rest-upper" variants.
        # _s1's alternating-case ("aLtErNaTiNg") has no position-independent
        # rule form and is intentionally left as wordlist-only enrichment.
        return [":", "l", "u", "c", "C"]

    def _leet_sub_rules(self) -> list[str]:
        rules: list[str] = []
        for src, subs in self._leet_map.items():
            for dst in subs:
                r = _sub_rule(src, dst)
                if r:
                    rules.append(r)
        return rules

    def _suffix_strings(self, tier: str) -> list[str]:
        suf = self._suffixes
        strings = list(suf.get("priority_suffixes", [])) + list(suf.get("symbols", []))
        if tier in ("standard", "exhaustive"):
            strings += list(suf.get("common_endings", []))
        return list(dict.fromkeys(strings))

    def _prefix_strings(self) -> list[str]:
        return list(dict.fromkeys(self._suffixes.get("prepend_symbols", [])))

    def _year_strings(self, tier: str) -> list[str]:
        years: list[str] = []
        if self.session.target_founded_year:
            years.append(self.session.target_founded_year)
        span = 2 if tier == "basic" else 5
        for yr in range(self._current_year, self._current_year - span, -1):
            years.append(str(yr))

        out: list[str] = []
        for y in years:
            out.append(y)
            if len(y) >= 2:
                out.append(y[-2:])
        return list(dict.fromkeys(out))

    def build_rules(self, tier: str = "standard") -> list[str]:
        """Return the deduplicated, tier-capped list of hashcat rule lines."""
        if tier not in RULE_TIERS:
            raise ValueError(f"Unknown rules tier: {tier!r} (expected one of {RULE_TIERS})")

        lines: list[str] = list(self._case_rules())

        # Appends: raw (for already-lowercase base lists like rockyou), plus
        # l- and c-prefixed to faithfully match the mutator, which appends to
        # word.lower() (_s4/_s5) and word.title() (c) respectively.
        suffixes = self._suffix_strings(tier)
        for case_op in ("", "l", "c"):
            for suf in suffixes:
                lines.append(f"{case_op}{_append_chain(suf)}")

        # Prepends: raw + l-prefixed (the mutator prepends to word.lower()).
        for pre in self._prefix_strings():
            chain = _prepend_chain(pre)
            lines.append(chain)
            lines.append(f"l{chain}")

        if tier in ("standard", "exhaustive"):
            # Single-char leet substitutions (substitute-ALL), applied raw and
            # on the lowercased word. Standard hashcat leet — a complement to,
            # not a 1:1 mirror of, the wordlist's positional leet.
            leet = self._leet_sub_rules()
            lines.extend(leet)
            for r in leet:
                lines.append(f"l{r}")

            for yr in self._year_strings(tier):
                chain = _append_chain(yr)
                lines.append(chain)
                lines.append(f"l{chain}")
                lines.append(f"c{chain}")

        if tier == "exhaustive":
            literal_words = ["admin", "root", "pass", "password", "welcome", "test", "hello"]
            for w in literal_words:
                lines.append(_append_chain(w))
                lines.append(_prepend_chain(w))

        # Dedup preserving first-seen order, then cap to the tier ceiling.
        seen: set[str] = set()
        deduped: list[str] = []
        for ln in lines:
            if ln not in seen:
                seen.add(ln)
                deduped.append(ln)

        ceiling = _TIER_CEILING[tier]
        if len(deduped) > ceiling:
            logger.info("rules: %s tier generated %d lines, capping to %d", tier, len(deduped), ceiling)
            deduped = deduped[:ceiling]

        return deduped

    # ── Seed words (paired base-wordlist material) ──────────────────────

    def build_seeds(self) -> list[str]:
        """Target-specific words meant to be concatenated with an external
        base wordlist before the .rule file is applied to it."""
        s = self.session
        seeds: list[str] = []
        if s.target_name:
            seeds.append(s.target_name)
        if s.target_domain:
            seeds.append(s.target_domain.split(".")[0])
        for emp in s.target_employees:
            seeds.extend(p for p in emp.split() if p)
        seeds.extend(s.target_products)
        if s.target_location:
            seeds.append(s.target_location)
        seeds.extend(s.target_keywords)

        seen: set[str] = set()
        out: list[str] = []
        for w in seeds:
            w = w.strip()
            key = w.lower()
            if w and key not in seen:
                seen.add(key)
                out.append(w)
        return out

    # ── File export ──────────────────────────────────────────────────────

    def export(
        self, output_dir: Path, target: str, ts: str, tier: str = "standard"
    ) -> dict[str, Path]:
        """Write the .rule and _seeds.txt files. Returns their paths."""
        output_dir.mkdir(parents=True, exist_ok=True)
        rule_path  = output_dir / f"wordsmith_{target}_{ts}.rule"
        seeds_path = output_dir / f"wordsmith_{target}_{ts}_seeds.txt"

        rules = self.build_rules(tier)
        seeds = self.build_seeds()

        with open(rule_path, "w", encoding="utf-8", newline="\n") as fh:
            for line in rules:
                fh.write(line)
                fh.write("\n")

        with open(seeds_path, "w", encoding="utf-8", newline="\n") as fh:
            for line in seeds:
                fh.write(line)
                fh.write("\n")

        logger.info(
            "rules: exported %d rules (%s tier) + %d seed words -> %s",
            len(rules), tier, len(seeds), rule_path,
        )
        return {"rules": rule_path, "seeds": seeds_path}
