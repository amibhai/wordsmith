"""Likelihood scoring — shared heuristic used by both the mutation engine
(to rank candidates going into the bounded top-K accumulator) and the
wordlist generator (final sort / report display). Single source of truth so
the two stages can never silently drift apart.
"""
from __future__ import annotations

import re

from .policy import has_special
from .state import WordsmithSession

# Scoring weights
SCORE_WEIGHTS: dict[str, int] = {
    "target_name":    10,
    "employee_name":   8,
    "domain_name":     7,
    "product_name":    6,
    "year_suffix":     5,
    "symbol_end":      5,
    "india_pattern":   4,
    "location_name":   4,
    "length_sweet":    3,
    "mixed_charset":   3,
    "admin_keyword":   2,
    "keyboard_walk":   1,
    "too_long":       -2,
    "all_lower":      -5,
}

KEYBOARD_WALK_SEQS = [
    "qwerty", "asdfgh", "zxcvbn", "qweasd", "asdzxc",
    "1234", "12345", "123456", "654321",
]

ADMIN_KEYWORDS = {"admin", "pass", "password", "root", "user", "login", "default"}

_YEAR_SUFFIX_RE = re.compile(r"(19[89]\d|20[012]\d)$")
_INDIA_PATTERN_RE = re.compile(r"[A-Z][a-z]+@(\d{4}|123|1234)$")


def score_word(word: str, session: WordsmithSession) -> int:
    """Heuristic likelihood score — higher means more plausible as a
    password for this specific target. Pure function of (word, session);
    safe to call repeatedly/concurrently.
    """
    score = 0
    wlow = word.lower()
    s = session

    # target_name only — do NOT fall back to the domain label here, or a
    # --domain-only run would score the SAME token under both target_name
    # (+10) and domain_name (+7), double-counting one concept as +17.
    target_low = s.target_name.lower() if s.target_name else ""
    domain_low = s.target_domain.split(".")[0].lower() if s.target_domain else ""
    employees  = {e.lower() for e in s.target_employees}
    products   = {p.lower() for p in s.target_products}
    location   = s.target_location.lower() if s.target_location else ""

    if target_low and target_low in wlow:
        score += SCORE_WEIGHTS["target_name"]
    if domain_low and domain_low in wlow:
        score += SCORE_WEIGHTS["domain_name"]

    for emp in employees:
        if emp in wlow:
            score += SCORE_WEIGHTS["employee_name"]
            break

    for prod in products:
        if prod in wlow:
            score += SCORE_WEIGHTS["product_name"]
            break

    if location and location in wlow:
        score += SCORE_WEIGHTS["location_name"]

    if _YEAR_SUFFIX_RE.search(word):
        score += SCORE_WEIGHTS["year_suffix"]

    if word.endswith("!") or word.endswith("@"):
        score += SCORE_WEIGHTS["symbol_end"]

    if _INDIA_PATTERN_RE.search(word):
        score += SCORE_WEIGHTS["india_pattern"]

    if 8 <= len(word) <= 16:
        score += SCORE_WEIGHTS["length_sweet"]

    has_upper   = any(c.isupper() for c in word)
    has_lower   = any(c.islower() for c in word)
    has_digit   = any(c.isdigit() for c in word)
    has_sym     = has_special(word)  # Unicode-aware, not ASCII-only
    if sum([has_upper, has_lower, has_digit, has_sym]) >= 3:
        score += SCORE_WEIGHTS["mixed_charset"]

    if any(k in wlow for k in ADMIN_KEYWORDS):
        score += SCORE_WEIGHTS["admin_keyword"]

    if any(kw in wlow for kw in KEYBOARD_WALK_SEQS):
        score += SCORE_WEIGHTS["keyboard_walk"]

    if len(word) > 20:
        score += SCORE_WEIGHTS["too_long"]

    if word.islower() and not has_digit:
        score += SCORE_WEIGHTS["all_lower"]

    return score
