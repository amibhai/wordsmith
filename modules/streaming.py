"""Bounded top-K accumulator — the memory-safety backbone of the streaming
mutation/generation pipeline.

Without this, holding every generated candidate in RAM before trimming does
not scale: a large target (thousands of scraped words + employees) can
produce tens of millions of live strings before any cap is ever applied.
`BoundedTopK` keeps only the best `capacity` candidates seen so far (by an
externally supplied score) using a fixed-size min-heap, so peak memory is
O(capacity) for the kept set. A second, independent `scan_ceiling` bounds
the size of the dedup-tracking set, giving a concrete, documented, testable
upper bound on total memory use even for pathologically large seed lists.
"""
from __future__ import annotations

import heapq
from typing import Iterable


class BoundedTopK:
    """Keep the best `capacity` distinct (word, score) offers seen so far.

    - Dedup: a word offered more than once only counts once (first score
      wins for heap purposes — later duplicate offers are no-ops).
    - Eviction: once at capacity, a new offer only displaces the current
      lowest-scored kept word if it scores strictly higher.
    - Scan ceiling: once `scan_ceiling` *unique* words have been offered,
      further offers are rejected (`offer()` returns False) and
      `limit_hit` is set — callers should stop feeding at that point.
    """

    def __init__(self, capacity: int, scan_ceiling: int | None = None) -> None:
        if capacity <= 0:
            raise ValueError("capacity must be positive")
        self.capacity = capacity
        self.scan_ceiling = scan_ceiling
        self._heap: list[tuple[int, int, str]] = []
        self._seen: set[str] = set()
        self._counter = 0
        self.limit_hit = False

    @property
    def scanned(self) -> int:
        """Number of unique words offered so far (kept or discarded)."""
        return len(self._seen)

    @property
    def kept(self) -> int:
        """Number of words currently retained (<= capacity)."""
        return len(self._heap)

    def offer(self, word: str, score: int) -> bool:
        """Consider `word` for inclusion. Returns False once the scan
        ceiling has been reached — callers should stop calling offer()
        after that (already-offered words remain valid to query)."""
        if word in self._seen:
            return not self.limit_hit

        if self.scan_ceiling is not None and len(self._seen) >= self.scan_ceiling:
            self.limit_hit = True
            return False

        self._seen.add(word)
        self._counter += 1
        entry = (score, self._counter, word)

        if len(self._heap) < self.capacity:
            heapq.heappush(self._heap, entry)
        elif entry > self._heap[0]:
            heapq.heapreplace(self._heap, entry)

        return not self.limit_hit

    def offer_many(self, items: Iterable[tuple[str, int]]) -> bool:
        """Offer a batch of (word, score) pairs. Returns False if the scan
        ceiling was hit partway through (caller should stop producing)."""
        for word, score in items:
            if not self.offer(word, score):
                return False
        return True

    def results(self) -> list[str]:
        """Return kept words sorted by score descending (ties broken by
        insertion order — earlier offers first)."""
        return [w for _, _, w in sorted(self._heap, key=lambda e: (-e[0], e[1]))]

    def results_with_scores(self) -> list[tuple[str, int]]:
        """Same as results(), but also returns each word's score."""
        return [(w, sc) for sc, _, w in sorted(self._heap, key=lambda e: (-e[0], e[1]))]

    def __len__(self) -> int:
        return self.kept
