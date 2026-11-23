"""Defensive mode — turn the SAME OSINT intelligence into blue-team output.

wordsmith's offensive side shows how an attacker would build a target-specific
wordlist. Defensive mode answers the other half for the client: "given what is
public about us, how guessable are our passwords, and what do we ban to stop
it?" From one engagement's collected intelligence it produces:

  1. A custom **banned-password list**, rendered for the places a defender can
     actually load one:
       - Microsoft Entra ID / Azure AD Password Protection custom banned list
         (base *terms*; Entra fuzzy-matches substrings, l33t and so on),
       - Keycloak / exact-match blocklists (full candidate passwords),
       - pam_pwquality / cracklib dictionaries (one word per line).
  2. An **exposure report** (Markdown + JSON) that quantifies guessability
     from wordsmith's OWN ranked candidates — never invented breach stats —
     with evidence-backed, prioritized hardening recommendations, each tied to
     the public source the stem came from (provenance).

Scope-checked and HMAC-audit-logged like every other action.
"""
from __future__ import annotations

import json
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich import box
from rich.console import Console
from .banner import console as _banner_console
from rich.table import Table

from .audit import get_logger
from .scoring import score_word
from .state import WordsmithSession

logger = logging.getLogger(__name__)
console = _banner_console

DEFEND_FORMATS = ("entra", "ad", "keycloak", "pwquality", "all")

# Entra ID custom banned list: terms are 4–16 chars, case-insensitive, max 1000.
_ENTRA_MIN, _ENTRA_MAX, _ENTRA_CAP = 4, 16, 1000

# Weak-pattern probes for the exposure breakdown (counts over the candidate set).
_PATTERNS: list[tuple[str, str]] = [
    ("ends with a year (e.g. Name2024)",      r"(?:19|20)\d{2}[!@#$]?$"),
    ("ends with a season",                    r"(?i)(spring|summer|autumn|fall|winter)\d*[!@#$]?$"),
    ("ends with trailing digits",             r"\d{1,4}$"),
    ("ends with a single bang/at/hash",       r"[!@#$]$"),
    ("all-lowercase letters only",            r"^[a-z]+$"),
    ("classic '…123' / '…1234'",              r"12345?$"),
]
# "Trivially weak" = a dictionary/name base plus at most a trailing year/number,
# short, no real complexity — the stuff a targeted first pass cracks instantly.
_TRIVIAL_RE = re.compile(r"^[A-Za-z][A-Za-z]{2,}(?:\d{0,4}|(?:19|20)\d{2})[!@#]?$")


class DefenseAnalyzer:
    def __init__(self, session: WordsmithSession, scope_mgr=None, audit=None) -> None:
        self.session = session
        self._scope_mgr = scope_mgr
        self._audit = audit or get_logger(session.session_id)

    # ── Org stems (with provenance) ──────────────────────────────────────────

    def build_stems(self) -> list[tuple[str, str]]:
        """Return (stem, public-source) pairs — the org-specific base terms an
        attacker seeds from. Deduplicated (first source wins)."""
        s = self.session
        candidates: list[tuple[str, str]] = []

        if s.target_name:
            for part in re.split(r"\s+", s.target_name.strip()):
                if part:
                    candidates.append((part, "org name"))
        if s.target_domain:
            candidates.append((s.target_domain.split(".")[0], "domain"))
        for prod in s.target_products:
            candidates.append((prod, "product/brand"))
        if s.target_location:
            candidates.append((s.target_location, "location (WHOIS)"))
        for emp in s.target_employees:
            for part in re.split(r"[\s._-]+", emp.strip()):
                if len(part) >= 3 and part.isalpha():
                    candidates.append((part, "employee name"))
        for kw in s.target_keywords:
            candidates.append((kw, "OSINT keyword"))

        seen: set[str] = set()
        out: list[tuple[str, str]] = []
        for raw, source in candidates:
            stem = raw.strip().lower()
            stem = re.sub(r"[^a-z0-9]", "", stem)
            if len(stem) < 3 or stem in seen:
                continue
            seen.add(stem)
            out.append((stem, source))
        return out

    # ── Attacker candidate set (reuses the offensive engine) ─────────────────

    def candidate_passwords(self, limit: int = 5000) -> list[str]:
        """Top-`limit` likelihood-ranked candidates an attacker would try,
        generated from the org stems with the real mutation engine."""
        from .mutator import MutationEngine

        stems = [s for s, _ in self.build_stems()]
        if not stems:
            return []
        engine = MutationEngine(self.session)
        # Policy-free: we want to see EVERY weak form, not filter to the policy.
        engine.policy = {}
        return engine.mutate_all(stems, max_words=limit, max_scan=limit * 20)

    # ── Exposure metrics (grounded, no invented stats) ───────────────────────

    def exposure(self, candidates: list[str]) -> dict:
        total = len(candidates)
        breakdown: list[dict] = []
        for label, pat in _PATTERNS:
            rx = re.compile(pat)
            n = sum(1 for w in candidates if rx.search(w))
            breakdown.append({
                "pattern": label,
                "count": n,
                "pct": round(100 * n / total, 1) if total else 0.0,
            })
        trivial = [w for w in candidates if _TRIVIAL_RE.match(w)]
        return {
            "total_candidates": total,
            "trivially_weak": len(trivial),
            "trivially_weak_pct": round(100 * len(trivial) / total, 1) if total else 0.0,
            "pattern_breakdown": breakdown,
            "top_examples": candidates[:15],
            "trivial_examples": trivial[:15],
        }

    def recommendations(self, stems: list[tuple[str, str]], metrics: dict) -> list[str]:
        recs: list[str] = []
        if stems:
            terms = ", ".join(s for s, _ in stems[:12])
            recs.append(
                f"Load these org-specific base terms into your Entra ID / Azure AD "
                f"custom banned password list (it fuzzy-matches substrings & l33t): {terms}."
            )
        yr = next((b for b in metrics["pattern_breakdown"] if "year" in b["pattern"]), None)
        if yr and yr["count"]:
            recs.append(
                f"Block year suffixes and enforce a longer minimum length: "
                f"{yr['pct']}% of the org-specific candidate space ends in a year "
                f"(e.g. <OrgName>2024)."
            )
        if metrics["trivially_weak"]:
            recs.append(
                f"{metrics['trivially_weak']} of {metrics['total_candidates']} candidates "
                f"({metrics['trivially_weak_pct']}%) are trivially weak (dictionary/name base "
                f"+ a trailing number/year). Require ≥14-char passphrases to break this pattern."
            )
        if any(src == "employee name" for _, src in stems):
            recs.append(
                "Employee names recovered from public sources are being used as base words — "
                "enforce the banned-terms policy org-wide and require phishing-resistant MFA."
            )
        recs.append(
            "Screen all new passwords against a breach corpus (e.g. HaveIBeenPwned / a local "
            "k-anonymity check) in addition to this org-specific list."
        )
        return recs

    # ── Rendering ────────────────────────────────────────────────────────────

    def _entra_terms(self, stems: list[tuple[str, str]]) -> list[str]:
        terms: list[str] = []
        for stem, _ in stems:
            t = stem[:_ENTRA_MAX]
            if _ENTRA_MIN <= len(t) <= _ENTRA_MAX:
                terms.append(t)
        return list(dict.fromkeys(terms))[:_ENTRA_CAP]

    def export(
        self, output_dir: Path, target: str, ts: str, formats: Optional[list[str]] = None
    ) -> dict[str, str]:
        output_dir.mkdir(parents=True, exist_ok=True)
        fmts = set(formats or ["all"])
        if "all" in fmts:
            fmts = {"entra", "keycloak", "pwquality"}
        if "ad" in fmts:  # Azure AD Password Protection uses the Entra list
            fmts.discard("ad")
            fmts.add("entra")

        stems = self.build_stems()
        passwords = self.candidate_passwords()
        metrics = self.exposure(passwords)
        recs = self.recommendations(stems, metrics)
        paths: dict[str, str] = {}

        def _write(name: str, lines: list[str]) -> Path:
            p = output_dir / f"wordsmith_{target}_{ts}_{name}"
            with open(p, "w", encoding="utf-8", newline="\n") as fh:
                for ln in lines:
                    fh.write(ln + "\n")
            return p

        if "entra" in fmts:
            paths["entra"] = str(_write("banned_entra.txt", self._entra_terms(stems)))
        if "keycloak" in fmts:
            paths["keycloak"] = str(_write("banned_keycloak.txt", passwords))
        if "pwquality" in fmts:
            words = sorted({s for s, _ in stems} | set(passwords))
            paths["pwquality"] = str(_write("banned_pwquality.dict", words))

        # Exposure report (always) — JSON + Markdown.
        report = {
            "target": target,
            "generated": datetime.now().isoformat(timespec="seconds"),
            "stems": [{"term": s, "source": src} for s, src in stems],
            "exposure": metrics,
            "recommendations": recs,
            "banned_list_files": paths,
        }
        jp = output_dir / f"wordsmith_{target}_{ts}_exposure.json"
        jp.write_text(json.dumps(report, indent=2), encoding="utf-8")
        paths["report_json"] = str(jp)
        mp = output_dir / f"wordsmith_{target}_{ts}_exposure.md"
        mp.write_text(self._render_markdown(target, stems, metrics, recs, paths), encoding="utf-8")
        paths["report_md"] = str(mp)

        self._audit.log(
            "defense.exported",
            target=target,
            stems=len(stems),
            candidates=metrics["total_candidates"],
            formats=sorted(fmts),
            paths=paths,
        )
        self._display(target, stems, metrics)
        return paths

    def _render_markdown(self, target, stems, metrics, recs, paths) -> str:
        lines = [
            f"# Password Exposure Report — {target}",
            "",
            f"_Generated by wordsmith (defensive mode) on "
            f"{datetime.now().isoformat(timespec='seconds')}._",
            "",
            "> All figures below are derived from wordsmith's own OSINT-seeded "
            "candidate generation for this organization. They are **estimates over "
            "the org-specific candidate space**, not measured breach statistics.",
            "",
            "## Public intelligence that seeds guesses",
            "",
            "| Base term | Public source |",
            "|-----------|---------------|",
        ]
        lines += [f"| `{s}` | {src} |" for s, src in stems[:30]] or ["| _(none found)_ | |"]
        lines += [
            "",
            "## Exposure",
            "",
            f"- Organization-specific candidates generated from public data: "
            f"**{metrics['total_candidates']:,}**",
            f"- Trivially weak (name/word + trailing number or year): "
            f"**{metrics['trivially_weak']:,} ({metrics['trivially_weak_pct']}%)**",
            "",
            "| Weak pattern | Candidates | % of set |",
            "|--------------|-----------:|---------:|",
        ]
        lines += [
            f"| {b['pattern']} | {b['count']:,} | {b['pct']}% |"
            for b in metrics["pattern_breakdown"]
        ]
        if metrics["top_examples"]:
            lines += ["", "**Highest-likelihood example candidates** (what to ban first):", ""]
            lines += [f"- `{w}`" for w in metrics["top_examples"]]
        lines += ["", "## Prioritized recommendations", ""]
        lines += [f"{i}. {r}" for i, r in enumerate(recs, 1)]
        lines += [
            "",
            "## Banned-list files produced",
            "",
        ]
        for k in ("entra", "keycloak", "pwquality"):
            if k in paths:
                lines.append(f"- **{k}**: `{Path(paths[k]).name}`")
        lines += [
            "",
            "_Load the Entra file as your tenant's custom banned password list; load the "
            "Keycloak/pwquality files into an exact-match blocklist or cracklib dictionary._",
            "",
        ]
        return "\n".join(lines)

    def _display(self, target, stems, metrics) -> None:
        t = Table(
            title=f"Exposure Summary — {target}",
            box=box.ROUNDED,
            header_style="bold color(214)",
            border_style="dim color(178)",
        )
        t.add_column("Metric", style="bold", width=34)
        t.add_column("Value", justify="right", width=14)
        t.add_row("Org base terms (stems)", str(len(stems)))
        t.add_row("Candidate passwords", f"{metrics['total_candidates']:,}")
        t.add_row("Trivially weak", f"{metrics['trivially_weak']:,} ({metrics['trivially_weak_pct']}%)")
        console.print()
        console.print(t)
        console.print()
