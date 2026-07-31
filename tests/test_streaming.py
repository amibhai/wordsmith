"""Tests for modules/streaming.py — the bounded top-K accumulator that
keeps the mutation/generation pipeline's peak memory predictable."""
from __future__ import annotations

import pytest

from modules.streaming import BoundedTopK


def test_keeps_highest_scored_within_capacity():
    topk = BoundedTopK(capacity=3)
    for word, score in [("a", 1), ("b", 5), ("c", 3), ("d", 4), ("e", 2)]:
        topk.offer(word, score)
    assert topk.results() == ["b", "d", "c"]
    assert topk.kept == 3


def test_dedup_first_offer_wins():
    topk = BoundedTopK(capacity=5)
    topk.offer("x", 1)
    topk.offer("x", 100)  # duplicate word — ignored, first score kept
    assert topk.results_with_scores() == [("x", 1)]
    assert topk.scanned == 1


def test_scan_ceiling_stops_intake():
    topk = BoundedTopK(capacity=10, scan_ceiling=3)
    assert topk.offer("a", 1) is True
    assert topk.offer("b", 1) is True
    assert topk.offer("c", 1) is True
    assert topk.limit_hit is False

    # The 4th *unique* word crosses the ceiling.
    assert topk.offer("d", 1) is False
    assert topk.limit_hit is True
    assert topk.scanned == 3
    assert "d" not in topk.results()


def test_capacity_must_be_positive():
    with pytest.raises(ValueError):
        BoundedTopK(capacity=0)


def test_len_and_kept_match_and_respect_capacity():
    topk = BoundedTopK(capacity=2)
    topk.offer("a", 1)
    topk.offer("b", 2)
    topk.offer("c", 3)
    assert len(topk) == 2
    assert topk.kept == 2
    assert set(topk.results()) == {"b", "c"}


def test_ties_broken_by_insertion_order():
    topk = BoundedTopK(capacity=2)
    topk.offer("first", 5)
    topk.offer("second", 5)
    assert topk.results() == ["first", "second"]
