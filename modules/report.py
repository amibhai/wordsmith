"""Report generator — produce JSON, Markdown, and terminal summary reports."""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich import box
from rich.console import Console
from .banner import console as _banner_console
from rich.panel import Panel
from rich.table import Table

from .audit import get_logger
from .state import WordsmithSession

logger = logging.getLogger(__name__)
console = _banner_console

REPORTS_DIR = Path(__file__).parent.parent / "outputs"


class ReportGenerator:
    """Generate pentest engagement reports in multiple formats."""

    def __init__(self, session: WordsmithSession) -> None:
        self.session = session
        self._audit  = get_logger(session.session_id)
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    def generate(self, formats: list[str] = ["json", "md"]) -> dict[str, str]:
        """
        Generate reports. Returns dict of format → filepath.
        formats: list containing any of ["json", "md", "all"]
        """
        if "all" in formats:
            formats = ["json", "md"]

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        target = self.session.target_domain or self.session.target_name or "wordsmith"
        target_safe = target.replace(".", "_").replace(" ", "_")

        paths: dict[str, str] = {}

        if "json" in formats:
            json_path = REPORTS_DIR / f"wordsmith_{target_safe}_{ts}_report.json"
            self._write_json(json_path)
            paths["json"] = str(json_path)
            console.print(f"  [green][+][/green] JSON report: [bold]{json_path}[/]")

        if "md" in formats:
            md_path = REPORTS_DIR / f"wordsmith_{target_safe}_{ts}_report.md"
            self._write_markdown(md_path)
            paths["md"] = str(md_path)
            console.print(f"  [green][+][/green] Markdown report: [bold]{md_path}[/]")

        self._display_terminal_summary()

        self._audit.log("report.generated", formats=formats, paths=paths)
        return paths

    # ── JSON report ───────────────────────────────────────────────────────────

    def _write_json(self, path: Path) -> None:
        s = self.session
        wordlist_sha = ""
        if s.final_wordlist_path and Path(s.final_wordlist_path).exists():
            h = hashlib.sha256()
            with open(s.final_wordlist_path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            wordlist_sha = h.hexdigest()

        data = {
            "engagement": s.osint_data.get("engagement", {}),
            "target": {
                "domain":           s.target_domain,
                "organization":     s.target_name,
                "location":         s.target_location,
                "founded_year":     s.target_founded_year,
                "employees_found":  len(s.target_employees),
                "keywords_found":   len(s.target_keywords),
                "products_found":   len(s.target_products),
                "tech_stack":       s.osint_data.get("website", {}).get("tech_stack", []),
            },
            "osint_sources": {
                "whois":        s.osint_data.get("whois", {}),
                "dns":          {
                    "subdomains":    s.osint_data.get("dns", {}).get("subdomains", []),
                    "mail_provider": s.osint_data.get("dns", {}).get("mail_provider", ""),
                    "services":      s.osint_data.get("dns", {}).get("services_from_spf", []),
                },
                "github":       {
                    "repos":        s.osint_data.get("social", {}).get("github_repos", []),
                    "contributors": s.osint_data.get("social", {}).get("contributors", []),
                },
                "certificates": {
                    "subdomains": s.osint_data.get("certificates", {}).get("subdomains", [])[:20],
                    "org_names":  s.osint_data.get("certificates", {}).get("org_names", []),
                },
            },
            "wordlist": {
                "full_path":        s.final_wordlist_path,
                "total_words":      s.final_wordlist_size,
                "size_mb":          round(
                    Path(s.final_wordlist_path).stat().st_size / (1024*1024), 3
                ) if s.final_wordlist_path and Path(s.final_wordlist_path).exists() else 0,
                "top10_candidates": s.mutated_words[:10] if s.mutated_words else [],
                "sha256":           wordlist_sha,
            },
            "mutation_stats": {
                "strategies_used":  s.strategies_used,
                "total_mutations":  len(s.mutated_words),
            },
            "audit_log_path": str(Path.home() / ".wordsmith" / "audit" / f"{s.session_id}.log"),
            "session_id":     s.session_id,
            "generated_at":   datetime.now().isoformat(),
        }

        path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")

    # ── Markdown report ───────────────────────────────────────────────────────

    def _write_markdown(self, path: Path) -> None:
        s = self.session
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        lines: list[str] = [
            "# wordsmith Engagement Report",
            f"\n**Generated:** {now}  ",
            f"**Session ID:** `{s.session_id}`  ",
            f"**Target:** {s.target_domain}  ",
            "",
            "---",
            "",
            "## Target Intelligence",
            "",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| Domain | {s.target_domain} |",
            f"| Organization | {s.target_name} |",
            f"| Location | {s.target_location} |",
            f"| Founded Year | {s.target_founded_year} |",
            f"| Employees Found | {len(s.target_employees)} |",
            f"| Keywords Found | {len(s.target_keywords)} |",
            f"| Products Found | {len(s.target_products)} |",
            "",
            "## OSINT Findings",
            "",
        ]

        # WHOIS
        whois = s.osint_data.get("whois", {})
        if whois and "error" not in whois:
            lines += [
                "### WHOIS",
                f"- **Registrant Org:** {whois.get('registrant_org', '–')}",
                f"- **Registrar:** {whois.get('registrar', '–')}",
                f"- **Created:** {whois.get('creation_date', '–')}",
                "",
            ]

        # DNS
        dns = s.osint_data.get("dns", {})
        if dns and "error" not in dns:
            subs = dns.get("subdomains", [])
            lines += [
                "### DNS",
                f"- **Subdomains found:** {len(subs)}",
                f"- **Mail provider:** {dns.get('mail_provider', '–')}",
                f"- **SPF services:** {', '.join(dns.get('services_from_spf', [])[:5])}",
                "",
            ]

        # GitHub
        social = s.osint_data.get("social", {})
        if social and "error" not in social:
            lines += [
                "### GitHub / Social",
                f"- **Repos found:** {len(social.get('github_repos', []))}",
                f"- **Contributors:** {', '.join(social.get('contributors', [])[:10])}",
                f"- **LinkedIn dork:** `{social.get('linkedin_dork', '–')}`",
                "",
            ]

        # Wordlist section
        lines += [
            "## Wordlist Statistics",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Total words | {s.final_wordlist_size:,} |",
            f"| Output path | `{s.final_wordlist_path}` |",
            f"| Strategies used | {len(s.strategies_used)} |",
            "",
            "## Top Password Candidates (top 20)",
            "",
            "```",
        ]
        top20 = (s.mutated_words or [])[:20]
        lines.extend(top20)
        lines += [
            "```",
            "",
            "## Mutation Statistics",
            "",
        ]
        for strat in set(s.strategies_used):
            lines.append(f"- {strat.replace('_', ' ').title()}")
        lines += [
            "",
            "## Recommendations",
            "",
            "1. Test the top-1000 candidates first against the target.",
            "2. If policy enforcement is strict, use the policy-filtered list.",
            "3. Name-based variants file is useful for username enumeration.",
            "4. Review the OSINT findings for manual follow-up.",
            "5. Verify audit log integrity after the engagement: `wordsmith --verify-log " + s.session_id + "`",
            "",
            "## Evidence Chain (SHA-256)",
            "",
        ]

        if s.final_wordlist_path and Path(s.final_wordlist_path).exists():
            h = hashlib.sha256()
            with open(s.final_wordlist_path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            sha = h.hexdigest()
            lines += [
                f"| File | SHA-256 |",
                f"|------|---------|",
                f"| `{Path(s.final_wordlist_path).name}` | `{sha}` |",
                "",
            ]

        lines += [
            "---",
            "",
            "*Generated by wordsmith — authorized security engagements only.*",
        ]

        path.write_text("\n".join(lines), encoding="utf-8")

    # ── Terminal summary ──────────────────────────────────────────────────────

    def _display_terminal_summary(self) -> None:
        s = self.session
        console.print()
        console.print(Panel.fit(
            f"[bold color(214)]wordsmith Engagement Summary[/]\n"
            f"[dim]Session: {s.session_id}[/]",
            border_style="color(214)",
            padding=(0, 4),
        ))

        t = Table(box=box.ROUNDED, show_header=False, border_style="dim color(178)")
        t.add_column("Field", style="bold color(214)", width=22)
        t.add_column("Value", width=45)

        t.add_row("Target domain",    s.target_domain or "–")
        t.add_row("Organization",     s.target_name or "–")
        t.add_row("Location",         s.target_location or "–")
        t.add_row("Employees found",  str(len(s.target_employees)))
        t.add_row("Keywords found",   str(len(s.target_keywords)))
        t.add_row("Scraped words",    str(len(s.scraped_words)))
        t.add_row("Mutations",        f"{len(s.mutated_words):,}")
        t.add_row("Final wordlist",   f"{s.final_wordlist_size:,} words")
        t.add_row("Strategies used",  str(len(set(s.strategies_used))))
        t.add_row("Output file",      str(Path(s.final_wordlist_path).name) if s.final_wordlist_path else "–")

        console.print(t)
        console.print()

        if s.mutated_words:
            console.print("  [bold color(214)]Top 10 candidates:[/]")
            for i, w in enumerate(s.mutated_words[:10], 1):
                console.print(f"  {i:2d}. [color(220)]{w}[/]")
        console.print()
