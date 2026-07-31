"""Tests for modules/generator.py and the shared modules/scoring.py it now
delegates to (previously duplicated inline as WordlistGenerator._score_word).
"""
from __future__ import annotations

from pathlib import Path

from modules.generator import WordlistGenerator
from modules.scoring import score_word
from modules.state import WordsmithSession


def _session() -> WordsmithSession:
    s = WordsmithSession()
    s.target_domain = "acme-example.com"
    s.target_name = "Acme"
    return s


def test_score_word_ranks_target_flavored_candidate_higher():
    s = _session()
    high = score_word("Acme2026!", s)
    low = score_word("xyzxyz", s)
    assert high > low


def test_apply_size_limit_respects_max_count():
    s = _session()
    gen = WordlistGenerator(s)
    words = [f"word{i}" for i in range(100)]
    trimmed = gen._apply_size_limit(words, max_mb=0, max_count=10)
    assert trimmed == words[:10]


def test_apply_size_limit_respects_max_mb():
    s = _session()
    gen = WordlistGenerator(s)
    words = ["a" * 1000 for _ in range(1000)]  # ~1001 bytes/line incl newline
    trimmed = gen._apply_size_limit(words, max_mb=0.01, max_count=0)  # ~10KB budget
    total_bytes = sum(len(w) + 1 for w in trimmed)
    assert total_bytes <= 0.01 * 1024 * 1024
    assert len(trimmed) < len(words)


def test_build_writes_full_top1000_and_names_files():
    s = _session()
    s.target_employees = ["Rahul Sharma"]
    s.mutated_words = ["acme2026", "Rahul123", "sharma!", "randomword"]
    gen = WordlistGenerator(s)
    path = gen.build(max_size_mb=10, max_words=1000)

    full = Path(path)
    assert full.exists()
    lines = full.read_text(encoding="utf-8").splitlines()
    assert set(lines) == {"acme2026", "Rahul123", "sharma!", "randomword"}

    names_path = full.with_name(full.name.replace("_full.txt", "_names.txt"))
    assert names_path.exists()
    name_lines = names_path.read_text(encoding="utf-8").splitlines()
    assert set(name_lines) == {"Rahul123", "sharma!"}

    assert s.final_wordlist_path == str(full)
    assert s.final_wordlist_size == 4


def test_build_bounds_merged_output_to_max_words():
    s = _session()
    s.mutated_words = [f"mutated{i}" for i in range(50)]
    s.scraped_words = [f"scraped{i}" for i in range(50)]
    gen = WordlistGenerator(s)
    gen.build(max_size_mb=100, max_words=10)
    assert s.final_wordlist_size == 10
