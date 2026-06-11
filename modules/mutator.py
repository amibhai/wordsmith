"""Mutation engine — applies 13 strategies to base words to generate password candidates."""
from __future__ import annotations

import json
import logging
import os
import re
import string
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console
from .banner import console as _banner_console
from rich.table import Table
from rich import box

from .state import WordsmithSession

logger = logging.getLogger(__name__)
console = _banner_console

_DATA_DIR = Path(__file__).parent.parent / "data"

KEYBOARD_WALKS_TOP = [
    "qwerty", "qwertyuiop", "asdfgh", "asdfghjkl", "zxcvbn",
    "1qaz2wsx", "qazwsx", "1q2w3e4r", "qweasdzxc", "!qaz@wsx",
]

COMMON_STOP_WORDS = frozenset([
    "the", "and", "for", "with", "this", "that", "have", "from",
    "they", "will", "would", "could", "should", "about", "which",
    "their", "there", "what", "when", "where", "who", "how", "why",
    "all", "one", "two", "more", "also", "into", "than", "then",
    "your", "our", "its", "his", "her", "can", "are", "was", "were",
    "has", "had", "been", "being", "have", "not", "but", "out",
    "any", "may", "other", "some", "just", "like", "get", "use",
    "new", "time", "long", "very", "even", "back", "only", "come",
    "its", "over", "after", "these", "those", "both", "much", "many",
])


def _load_json(filename: str) -> dict | list:
    path = _DATA_DIR / filename
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning("Failed to load %s: %s", filename, exc)
        return {} if filename.endswith(".json") and "map" in filename else []


def _load_lines(filename: str) -> list[str]:
    path = _DATA_DIR / filename
    try:
        return [l.strip() for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    except Exception as exc:
        logger.warning("Failed to load %s: %s", filename, exc)
        return []


class MutationEngine:
    """
    Applies up to 13 configurable mutation strategies to a list of base words
    and returns a deduplicated, optionally policy-filtered candidate list.
    """

    def __init__(self, session: WordsmithSession) -> None:
        self.session = session
        self.policy  = session.policy
        self.leet_map: dict[str, list[str]] = _load_json("leet_map.json")  # type: ignore[assignment]
        self.suffixes: dict = _load_json("suffixes.json")  # type: ignore[assignment]
        self.patterns: list[str] = _load_json("patterns.json")  # type: ignore[assignment]
        self.keyboard_walks: list[str] = _load_lines("keyboard_walks.txt")

        self._current_year = datetime.now().year
        self._enabled: set[int] = set(range(1, 14))  # all on by default

        self._stats: dict[str, int] = {}

    # ── Strategy toggle ───────────────────────────────────────────────────────

    def enable_strategies(self, nums: list[int]) -> None:
        self._enabled = set(nums)

    def disable_strategy(self, num: int) -> None:
        self._enabled.discard(num)

    # ── Main entry point ──────────────────────────────────────────────────────

    def mutate_all(self, words: list[str]) -> list[str]:
        """
        Apply all enabled strategies to words.
        Returns deduplicated list. Updates session.strategies_used.
        """
        # Clean input
        cleaned = [w.strip() for w in words if w.strip() and len(w.strip()) >= 2]
        if not cleaned:
            logger.warning("mutate_all: empty word list")
            return []

        results: set[str] = set(cleaned)

        strategy_map = {
            1:  ("case_variants",     self._s1_case_variants),
            2:  ("leet_speak",        self._s2_leet_speak),
            3:  ("year_suffix",       self._s3_year_suffix),
            4:  ("symbol_append",     self._s4_symbol_append),
            5:  ("number_append",     self._s5_number_append),
            6:  ("word_combinator",   self._s6_word_combinator),
            7:  ("keyboard_walks",    self._s7_keyboard_walks),
            8:  ("name_variants",     self._s8_name_variants),
            9:  ("domain_variants",   self._s9_domain_variants),
            10: ("common_patterns",   self._s10_common_patterns),
            11: ("cms_defaults",      self._s11_cms_defaults),
            12: ("temporal_patterns", self._s12_temporal_patterns),
            13: ("location_variants", self._s13_location_variants),
        }

        for num, (name, fn) in strategy_map.items():
            if num not in self._enabled:
                continue
            try:
                before = len(results)
                if num == 6:
                    new_words = fn(cleaned)  # type: ignore[call-arg]
                elif num == 12:
                    new_words = fn()  # type: ignore[call-arg]
                elif num == 9:
                    new_words = fn(self.session.target_domain)
                elif num == 13:
                    new_words = fn(self.session.target_location)
                elif num == 8:
                    new_words = fn(self.session.target_employees)  # type: ignore[call-arg]
                else:
                    batch: list[str] = []
                    for w in cleaned:
                        batch.extend(fn(w))  # type: ignore[call-arg]
                    new_words = batch
                results.update(new_words)
                self._stats[name] = len(results) - before
                self.session.strategies_used.append(name)
            except Exception as exc:
                logger.warning("Strategy %s failed: %s", name, exc)

        # Add common passwords file
        common = _load_lines("common_passwords.txt")
        results.update(common)

        final = self._apply_policy(list(results))
        logger.info("mutate_all: %d words before policy, %d after", len(results), len(final))
        return final

    # ── Strategy 1: Case variants ─────────────────────────────────────────────

    def _s1_case_variants(self, word: str) -> list[str]:
        return [
            word.lower(),
            word.upper(),
            word.title(),
            word.capitalize(),
            "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(word)),
            word[0].lower() + word[1:].upper() if len(word) > 1 else word,
        ]

    # ── Strategy 2: Leet speak ────────────────────────────────────────────────

    def _s2_leet_speak(self, word: str) -> list[str]:
        results: list[str] = []
        word_lower = word.lower()

        # Single character replacement
        for i, ch in enumerate(word_lower):
            if ch in self.leet_map:
                for sub in self.leet_map[ch]:
                    new = word_lower[:i] + sub + word_lower[i+1:]
                    results.append(new)
                    results.append(new.title())

        # All vowel replacement
        vowel_map = {k: v[0] for k, v in self.leet_map.items() if k in "aeiou"}
        vowel_leet = "".join(vowel_map.get(c, c) for c in word_lower)
        if vowel_leet != word_lower:
            results.extend([vowel_leet, vowel_leet.title()])

        # Full leet (replace every char with first substitution)
        full_leet = "".join(self.leet_map.get(c, [c])[0] for c in word_lower)
        if full_leet != word_lower:
            results.append(full_leet)

        # Common combined: @->a, 3->e, 1->i, 0->o
        simple_leet_map = {"a": "@", "e": "3", "i": "1", "o": "0", "s": "$", "t": "7"}
        simple = "".join(simple_leet_map.get(c, c) for c in word_lower)
        if simple != word_lower:
            results.extend([simple, simple.title(), simple.capitalize()])

        return list(dict.fromkeys(results))[:50]

    # ── Strategy 3: Year suffix ───────────────────────────────────────────────

    def _s3_year_suffix(self, word: str) -> list[str]:
        results: list[str] = []
        base = word.lower()
        base_title = word.title()

        # OSINT years first (high priority)
        osint_years: list[str] = []
        if self.session.target_founded_year:
            osint_years.append(self.session.target_founded_year)
        for yr in range(self._current_year, self._current_year - 5, -1):
            osint_years.append(str(yr))

        for year in osint_years:
            yr2 = year[-2:]  # 2-digit
            results += [
                f"{base}{year}",
                f"{base_title}{year}",
                f"{base}{yr2}",
                f"{base}@{year}",
                f"{base_title}@{year}",
                f"{base}#{year}",
                f"{base}{year}!",
                f"{base_title}{year}!",
                f"{base_title}{year}@",
                f"{base}@{yr2}",
            ]

        # Range years (last 30)
        for yr in range(self._current_year - 30, self._current_year + 1):
            results.append(f"{base}{yr}")
            results.append(f"{base_title}{yr}")

        return list(dict.fromkeys(results))

    # ── Strategy 4: Symbol append/prepend ────────────────────────────────────

    def _s4_symbol_append(self, word: str) -> list[str]:
        results: list[str] = []
        base = word.lower()
        base_title = word.title()
        priority = self.suffixes.get("priority_suffixes", ["!", "@", "123", "!@#"])
        symbols   = self.suffixes.get("symbols", ["!", "@", "#"])
        prepend   = self.suffixes.get("prepend_symbols", ["!", "@"])

        for suf in priority:
            results += [f"{base}{suf}", f"{base_title}{suf}"]
        for sym in symbols:
            results += [f"{base}{sym}", f"{base_title}{sym}"]
        for pre in prepend:
            results.append(f"{pre}{base}")

        return list(dict.fromkeys(results))

    # ── Strategy 5: Number append ─────────────────────────────────────────────

    def _s5_number_append(self, word: str) -> list[str]:
        results: list[str] = []
        base  = word.lower()
        title = word.title()

        for n in ["1", "12", "123", "1234", "12345", "01", "001", "007", "99", "00"]:
            results += [f"{base}{n}", f"{title}{n}"]

        # 1-99
        for n in range(1, 100):
            results.append(f"{base}{n}")

        # Common extras
        for n in [100, 111, 123, 321, 456, 789, 999, 1000, 1111, 2000]:
            results.append(f"{base}{n}")

        return list(dict.fromkeys(results))

    # ── Strategy 6: Word combinator ───────────────────────────────────────────

    def _s6_word_combinator(self, words: list[str]) -> list[str]:
        results: list[str] = []
        top = [w.lower() for w in words if w.lower() not in COMMON_STOP_WORDS][:50]

        for i, w1 in enumerate(top):
            for w2 in top[i+1:]:
                results += [
                    f"{w1}{w2}",
                    f"{w2}{w1}",
                    f"{w1}_{w2}",
                    f"{w1.title()}{w2.title()}",
                    f"{w1}{w2}!",
                    f"{w1.title()}{w2}123",
                ]

        # word + year
        for w in top[:20]:
            for yr in range(self._current_year - 3, self._current_year + 1):
                results.append(f"{w}{yr}")

        return list(dict.fromkeys(results))

    # ── Strategy 7: Keyboard walks ────────────────────────────────────────────

    def _s7_keyboard_walks(self, word: str) -> list[str]:
        results: list[str] = []
        base = word.lower()
        walks = self.keyboard_walks or KEYBOARD_WALKS_TOP

        for walk in walks[:20]:
            results += [
                f"{base}{walk}",
                f"{walk}{base}",
                f"{base}{walk[:6]}",
            ]

        return list(dict.fromkeys(results))

    # ── Strategy 8: Name variants ─────────────────────────────────────────────

    def _s8_name_variants(self, names: list[str]) -> list[str]:
        results: list[str] = []
        for name in names:
            parts = name.strip().split()
            if not parts:
                continue
            first = parts[0].lower()
            last  = parts[-1].lower() if len(parts) > 1 else ""

            results += [first, first.title(), first.upper()]
            if last:
                results += [
                    last, last.title(), last.upper(),
                    f"{first}{last}",
                    f"{first}.{last}",
                    f"{first[0]}{last}",
                    f"{first[0]}.{last}",
                    f"{first[0]}{last}".title(),
                    f"{first}{last[0]}",
                ]
                for yr in range(self._current_year - 3, self._current_year + 1):
                    results += [
                        f"{first}{yr}",
                        f"{first.title()}{yr}",
                        f"{last}{yr}",
                        f"{first.title()}{yr}!",
                        f"{first.title()}@{yr}",
                    ]

            for suf in ["123", "1234", "@123", "!", "@", "#1"]:
                results += [f"{first}{suf}", f"{first.title()}{suf}"]

        return list(dict.fromkeys(results))

    # ── Strategy 9: Domain variants ───────────────────────────────────────────

    def _s9_domain_variants(self, domain: str) -> list[str]:
        if not domain:
            return []
        results: list[str] = []
        base = domain.split(".")[0].lower() if "." in domain else domain.lower()

        results += [
            base, base.upper(), base.title(),
            f"{base}123", f"{base}1234",
            f"{base}!", f"{base}@",
            f"{base}admin", f"{base}user",
            f"{base}root", f"{base}pass",
            f"admin{base}", f"root{base}",
            f"{base}2024", f"{base}@2024",
            f"{base}.com", f"@{base}.com",
        ]

        for yr in range(self._current_year - 5, self._current_year + 1):
            results += [f"{base}{yr}", f"{base.title()}{yr}", f"{base}@{yr}"]

        for suf in ["@123", "!@#", "#1", "123!", "@1234"]:
            results += [f"{base}{suf}", f"{base.title()}{suf}"]

        return list(dict.fromkeys(results))

    # ── Strategy 10: Common patterns ──────────────────────────────────────────

    def _s10_common_patterns(self, word: str) -> list[str]:
        results: list[str] = []
        year = str(self._current_year)
        yr2  = year[-2:]
        sym  = "!"

        substitutions = {
            "{word}":   word.lower(),
            "{Word}":   word.title(),
            "{WORD}":   word.upper(),
            "{year}":   year,
            "{yr2}":    yr2,
            "{symbol}": sym,
        }

        for pattern in self.patterns:
            try:
                result = pattern
                for placeholder, value in substitutions.items():
                    result = result.replace(placeholder, value)
                if result != pattern:  # something was substituted
                    results.append(result)
                    # Also with last year
                    result2 = pattern
                    subs2 = dict(substitutions)
                    subs2["{year}"] = str(self._current_year - 1)
                    subs2["{yr2}"]  = str(self._current_year - 1)[-2:]
                    for placeholder, value in subs2.items():
                        result2 = result2.replace(placeholder, value)
                    if result2 != result:
                        results.append(result2)
            except Exception:
                pass

        return list(dict.fromkeys(results))

    # ── Strategy 11: CMS defaults ─────────────────────────────────────────────

    def _s11_cms_defaults(self, word: str) -> list[str]:
        results: list[str] = []
        # Generic defaults independent of word — seeded once
        if word.lower() not in ("admin", "administrator", "root", "test"):
            return []

        cms_defaults = [
            "admin", "administrator", "admin123", "admin@123",
            "Admin@123", "Admin123!", "wp-admin", "cpanel",
            "joomla", "joomlaadmin", "siteadmin",
            "root", "root123", "root@123",
            "default", "guest", "webmaster",
            "sysadmin", "netadmin", "dbadmin",
        ]
        results.extend(cms_defaults)

        # Combine with target name
        base = self.session.target_name.lower() or self.session.target_domain.split(".")[0].lower()
        if base:
            for d in ["admin", "user", "root", "pass"]:
                results += [f"{base}{d}", f"{d}{base}", f"{base}.{d}"]

        return list(dict.fromkeys(results))

    # ── Strategy 12: Temporal patterns ────────────────────────────────────────

    def _s12_temporal_patterns(self) -> list[str]:
        results: list[str] = []
        years = [str(self._current_year), str(self._current_year - 1)]
        if self.session.target_founded_year:
            years.append(self.session.target_founded_year)

        months = [
            "Jan", "Feb", "Mar", "Apr", "May", "Jun",
            "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        ]

        for yr in years:
            yr2 = yr[-2:]
            for m in months:
                results += [f"{m}{yr}", f"{m}{yr2}", f"{m.lower()}{yr}"]
            for q in ["Q1", "Q2", "Q3", "Q4"]:
                results += [f"{q}{yr}", f"{q.lower()}{yr}", f"{q}FY{yr2}"]
            results += [
                f"FY{yr}", f"FY{yr2}", f"fy{yr2}",
                f"FY{yr}!", f"FY{yr2}@",
                f"0101{yr}", f"0101{yr2}",
            ]

        return list(dict.fromkeys(results))

    # ── Strategy 13: Location variants ────────────────────────────────────────

    def _s13_location_variants(self, location: str) -> list[str]:
        if not location:
            return []
        results: list[str] = []
        base = location.strip().lower()

        results += [
            base, base.title(), base.upper(),
            f"{base}123", f"{base}@123",
            f"{base}!", f"{base}@",
            f"{base}office", f"{base}hq",
            f"{base.title()}Office", f"{base.title()}HQ",
        ]

        for yr in range(self._current_year - 3, self._current_year + 1):
            results += [f"{base}{yr}", f"{base.title()}{yr}", f"{base}@{yr}"]

        # City abbreviations for common Indian cities
        abbrevs = {
            "mumbai": ["mum", "bom", "bombay"],
            "delhi": ["del", "nd", "newdelhi"],
            "bangalore": ["blr", "bang", "bengaluru"],
            "hyderabad": ["hyd", "hyder"],
            "chennai": ["chn", "madras"],
            "pune": ["pun"],
            "kolkata": ["kol", "calcutta"],
            "ahmedabad": ["ahm", "amd"],
        }
        if base in abbrevs:
            for abbr in abbrevs[base]:
                results += [abbr, f"{abbr}123", f"{abbr}@123"]

        return list(dict.fromkeys(results))

    # ── Policy filter ─────────────────────────────────────────────────────────

    def _apply_policy(self, words: list[str]) -> list[str]:
        """Filter words against the active password policy."""
        if not self.policy:
            return words

        min_len = self.policy.get("min_length", 0)
        max_len = self.policy.get("max_length", 0)
        req_upper   = self.policy.get("require_upper", False)
        req_number  = self.policy.get("require_number", False)
        req_special = self.policy.get("require_special", False)
        forbidden   = set(self.policy.get("forbidden_chars", []))

        filtered: list[str] = []
        for w in words:
            if min_len and len(w) < min_len:
                continue
            if max_len and len(w) > max_len:
                continue
            if req_upper and not any(c.isupper() for c in w):
                continue
            if req_number and not any(c.isdigit() for c in w):
                continue
            if req_special and not any(c in string.punctuation for c in w):
                continue
            if forbidden and any(c in forbidden for c in w):
                continue
            filtered.append(w)

        return filtered

    # ── Stats display ──────────────────────────────────────────────────────────

    def print_stats(self) -> None:
        """Print a Rich table of mutation statistics."""
        t = Table(
            title="Mutation Statistics",
            box=box.ROUNDED,
            header_style="bold color(214)",
            border_style="dim color(178)",
        )
        t.add_column("Strategy",         style="bold", width=20)
        t.add_column("Words Generated",  justify="right", width=16)
        for name, count in self._stats.items():
            t.add_row(name.replace("_", " ").title(), f"[color(220)]{count:,}[/]")
        console.print(t)
