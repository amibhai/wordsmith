"""Shared password-policy predicate.

One definition used by BOTH the mutation engine (inline filter while
streaming) and the final wordlist assembler. Previously only mutations were
policy-filtered, so the generator's merge of raw scraped/base/keyword words
could drop sub-minimum-length or otherwise non-conforming strings straight
into the final list, contradicting the "policy-aware, inline during
generation" contract.
"""
from __future__ import annotations

import unicodedata
from typing import Optional


def is_special_char(ch: str) -> bool:
    """Unicode-aware 'special character' test.

    True for any non-alphanumeric, non-space, non-control character — ASCII
    punctuation AND symbols the old `c in string.punctuation` check missed
    (smart quotes ’ “ ”, currency € £ ¥, etc.), which were mis-scored and
    could be wrongly rejected by a require_special policy.
    """
    if ch.isalnum() or ch.isspace():
        return False
    return not unicodedata.category(ch).startswith("C")  # not control/format


def has_special(word: str) -> bool:
    return any(is_special_char(c) for c in word)


def passes_policy(word: str, policy: Optional[dict]) -> bool:
    """True iff `word` satisfies the active password policy. An empty/None
    policy accepts everything."""
    if not policy:
        return True

    min_len = policy.get("min_length", 0)
    max_len = policy.get("max_length", 0)
    if min_len and len(word) < min_len:
        return False
    if max_len and len(word) > max_len:
        return False
    if policy.get("require_upper", False) and not any(c.isupper() for c in word):
        return False
    if policy.get("require_number", False) and not any(c.isdigit() for c in word):
        return False
    if policy.get("require_special", False) and not has_special(word):
        return False
    forbidden = set(policy.get("forbidden_chars", []))
    if forbidden and any(c in forbidden for c in word):
        return False
    return True
