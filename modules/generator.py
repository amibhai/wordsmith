"""Wordlist generator — assemble, score, and write the final wordlist."""
from __future__ import annotations

import hashlib
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console
from .banner import console as _banner_console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TaskProgressColumn
from rich.table import Table
from rich import box

from .audit import get_logger
from .scoring import score_word
from .state import WordsmithSession
from .streaming import BoundedTopK

logger = logging.getLogger(__name__)
console = _banner_console

OUTPUTS_DIR = Path(__file__).parent.parent / "outputs"


class WordlistGenerator:
    """
    Assemble final wordlist from all sources, score by likelihood,
    apply size constraints, and write three output files.
    """

    def __init__(self, session: WordsmithSession) -> None:
        self.session = session
        self._audit  = get_logger(session.session_id)
        OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)

    def build(
        self,
        max_size_mb: float = 100.0,
        max_words: int = 5_000_000,
        sort_by_likelihood: bool = True,
    ) -> str:
        """
        Build and save the full wordlist. Returns path to main output file.
        Shows a Rich progress bar during assembly.
        """
        console.print()
        console.print("  [color(214)][*][/] Assembling wordlist from all sources...")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
            transient=True,
        ) as prog:
            task = prog.add_task("Merging sources...", total=5)

            # 1. Bounded merge of all sources — mutated_words is already
            # capped from the mutation stage; scraped/base/keyword sources
            # are merged in through the same bounded accumulator so a
            # surprisingly large supplementary source can never blow past
            # the word budget either. Scoring happens inline (streaming),
            # never materializing an unbounded intermediate collection.
            topk = BoundedTopK(capacity=max(1, max_words))
            for src_words in [
                self.session.mutated_words,
                self.session.scraped_words,
                self.session.base_words,
                self.session.target_keywords,
            ]:
                for w in src_words:
                    w = w.strip()
                    if not w:
                        continue
                    sc = score_word(w, self.session) if sort_by_likelihood else 0
                    topk.offer(w, sc)
            prog.advance(task); prog.update(task, description="Merged + scored sources")

            # 2. (scoring already applied inline above)
            prog.advance(task); prog.update(task, description="Scored")

            # 3. Sort by score descending
            prog.update(task, description="Sorting by likelihood...")
            ranked = topk.results_with_scores()
            sorted_words = [w for w, _ in ranked]
            all_words: dict[str, int] = dict(ranked)
            prog.advance(task)

            # 4. Apply size constraints
            prog.update(task, description="Applying size constraints...")
            sorted_words = self._apply_size_limit(sorted_words, max_size_mb, max_words)
            prog.advance(task)

            # 5. Write files
            prog.update(task, description="Writing output files...")
            ts     = datetime.now().strftime("%Y%m%d_%H%M%S")
            target = re.sub(r"[^\w.-]", "_", self.session.target_domain or self.session.target_name or "wordsmith")
            paths  = self._write_outputs(sorted_words, all_words, target, ts)
            prog.advance(task)

        main_path = paths["full"]
        main_sha  = self._sha256(main_path)

        self.session.final_wordlist_path = str(main_path)
        self.session.final_wordlist_size = len(sorted_words)

        self._audit.log(
            "wordlist.generated",
            path=str(main_path),
            total_words=len(sorted_words),
            sha256=main_sha,
        )

        self._display_summary(sorted_words, all_words, paths, main_sha)
        return str(main_path)

    # ── Size control ──────────────────────────────────────────────────────────

    def _apply_size_limit(self, words: list[str], max_mb: float, max_count: int) -> list[str]:
        if max_count > 0:
            words = words[:max_count]

        if max_mb <= 0:
            return words

        # Estimate size: average word ~10 bytes + newline
        estimated_mb = sum(len(w) + 1 for w in words) / (1024 * 1024)
        if estimated_mb <= max_mb:
            return words

        # Progressive cuts
        target_bytes = int(max_mb * 1024 * 1024)
        cut_words: list[str] = []
        total = 0
        for w in words:
            sz = len(w) + 1
            if total + sz > target_bytes:
                break
            cut_words.append(w)
            total += sz

        cut = len(words) - len(cut_words)
        console.print(f"  [yellow][!][/] Size limit {max_mb}MB: removed {cut:,} lowest-scored words")
        return cut_words

    # ── File writing ──────────────────────────────────────────────────────────

    @staticmethod
    def _stream_write(path: Path, lines: list[str]) -> None:
        """Write lines one at a time instead of materializing a single
        giant `"\\n".join(...)` string — keeps peak memory flat regardless
        of how large --max-words is raised."""
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            for line in lines:
                fh.write(line)
                fh.write("\n")

    def _write_outputs(
        self, words: list[str], scores: dict[str, int], target: str, ts: str
    ) -> dict[str, Path]:
        paths: dict[str, Path] = {}

        # Full list
        full_path = OUTPUTS_DIR / f"wordsmith_{target}_{ts}_full.txt"
        self._stream_write(full_path, words)
        paths["full"] = full_path

        # Top 1000
        top_path = OUTPUTS_DIR / f"wordsmith_{target}_{ts}_top1000.txt"
        self._stream_write(top_path, words[:1000])
        paths["top1000"] = top_path

        # Name variants only
        name_words = [w for w in words if self._is_name_based(w)]
        name_path = OUTPUTS_DIR / f"wordsmith_{target}_{ts}_names.txt"
        self._stream_write(name_path, name_words)
        paths["names"] = name_path

        return paths

    def _is_name_based(self, word: str) -> bool:
        """Return True if word is derived from employee names."""
        wlow = word.lower()
        for emp in self.session.target_employees:
            emp_parts = emp.lower().split()
            for part in emp_parts:
                if len(part) >= 3 and part in wlow:
                    return True
        return False

    # ── Hash ──────────────────────────────────────────────────────────────────

    @staticmethod
    def _sha256(path: Path) -> str:
        h = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
        except OSError:
            pass
        return h.hexdigest()

    # ── Display ───────────────────────────────────────────────────────────────

    def _display_summary(
        self, words: list[str], scores: dict[str, int],
        paths: dict[str, Path], main_sha: str,
    ) -> None:
        size_mb = sum(len(w) + 1 for w in words) / (1024 * 1024)

        t = Table(
            title="Wordlist Generation Summary",
            box=box.ROUNDED,
            header_style="bold color(214)",
            border_style="dim color(178)",
        )
        t.add_column("File",       style="bold", width=16)
        t.add_column("Words",      justify="right", width=12)
        t.add_column("Path",       width=55)

        t.add_row("Full list",   f"[color(220)]{len(words):,}[/]", str(paths["full"]))
        t.add_row("Top 1000",    f"[color(220)]{min(1000, len(words)):,}[/]", str(paths["top1000"]))
        t.add_row("Name-based",  f"[color(220)]{len([w for w in words if self._is_name_based(w)]):,}[/]", str(paths["names"]))

        console.print()
        console.print(t)
        console.print()
        console.print(f"  Size: [color(220)]{size_mb:.2f} MB[/]")
        console.print(f"  SHA-256: [dim]{main_sha}[/]")
        console.print()

        if words:
            console.print("  [bold color(214)]Top 20 highest-scored candidates:[/]")
            for i, w in enumerate(words[:20], 1):
                sc = scores.get(w, 0)
                console.print(f"  {i:2d}. [color(220)]{w}[/] [dim](score={sc})[/]")
        console.print()
