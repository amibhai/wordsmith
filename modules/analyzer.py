"""Password policy analyzer — detect or manually input target password requirements."""
from __future__ import annotations

import logging
import re
from typing import Optional

from rich.console import Console
from .banner import console as _banner_console
from rich.table import Table
from rich import box

from .state import WordsmithSession

logger = logging.getLogger(__name__)
console = _banner_console

# Regex patterns for detecting policy hints in page text
_POLICY_PATTERNS: list[tuple[str, str, str]] = [
    (r"(?:at least|minimum|min)\s+(\d+)\s+char",         "min_length",  "int"),
    (r"(?:at most|maximum|max|no more than)\s+(\d+)\s+char", "max_length", "int"),
    (r"(?:must|should|require[sd]?)\s+(?:contain|include|have)\s+(?:a\s+)?(?:uppercase|capital)", "require_upper",   "bool"),
    (r"(?:must|should|require[sd]?)\s+(?:contain|include|have)\s+(?:a\s+)?(?:number|digit|numeric)", "require_number", "bool"),
    (r"(?:must|should|require[sd]?)\s+(?:contain|include|have)\s+(?:a\s+)?(?:special|symbol|punctuation)", "require_special", "bool"),
    (r"password\s+(?:must\s+be\s+)?(?:at\s+least\s+)?(\d+)\s+(?:characters?|chars?)\s+long", "min_length", "int"),
    (r"(?:length|characters?)\s*(?:between|from)\s+(\d+)\s*(?:to|-)\s+\d+", "min_length", "int"),
    (r"(?:length|characters?)\s*between\s+\d+\s*(?:to|-)\s+(\d+)", "max_length", "int"),
]

DEFAULT_POLICY: dict = {
    "min_length": 8,
    "max_length": 64,
    "require_upper": False,
    "require_number": False,
    "require_special": False,
    "forbidden_chars": [],
    "common_words_blocked": True,
}


class PolicyAnalyzer:
    """
    Detect or manually collect target password policy constraints.
    The output policy dict drives the MutationEngine's filter step.
    """

    def __init__(self, session: WordsmithSession) -> None:
        self.session = session
        self._policy: dict = dict(DEFAULT_POLICY)

    # ── Auto-detection ────────────────────────────────────────────────────────

    def detect_from_website(self, domain: str) -> dict:
        """
        Scrape login/register/reset pages for policy hints in HTML.
        Returns partial policy dict with whatever was found.
        """
        try:
            import httpx
            from bs4 import BeautifulSoup
        except ImportError:
            logger.warning("httpx/beautifulsoup4 not installed — skipping auto-detect")
            return {}

        partial: dict = {}
        policy_pages = [
            f"https://{domain}/register",
            f"https://{domain}/signup",
            f"https://{domain}/login",
            f"https://{domain}/reset-password",
            f"https://{domain}/forgot-password",
            f"https://{domain}/account/register",
            f"https://{domain}/user/register",
        ]

        with httpx.Client(
            headers={"User-Agent": "Mozilla/5.0"},
            timeout=8.0,
            follow_redirects=True,
            verify=False,
        ) as client:
            for url in policy_pages:
                try:
                    resp = client.get(url)
                    if resp.status_code not in (200, 201):
                        continue
                    soup = BeautifulSoup(resp.text, "html.parser")
                    text = soup.get_text(separator=" ").lower()
                    found = self._parse_policy_text(text)
                    partial.update(found)
                    if len(partial) >= 4:
                        break
                except Exception as exc:
                    logger.debug("Policy detect failed on %s: %s", url, exc)

        if partial:
            logger.info("Auto-detected policy: %s", partial)
        return partial

    def detect_from_error_messages(self) -> dict:
        """Look for policy hints in previously scraped text."""
        if not self.session.scraped_words:
            return {}

        full_text = " ".join(self.session.scraped_words).lower()
        return self._parse_policy_text(full_text)

    # ── Manual input ──────────────────────────────────────────────────────────

    def manual_input(self) -> dict:
        """Interactive wizard to manually enter password policy."""
        console.print()
        console.print("  [bold color(214)]Password Policy Configuration[/]")
        console.print("  [dim]Press Enter to accept defaults shown in brackets.[/]")
        console.print()

        policy: dict = {}

        def _ask_int(prompt: str, default: int) -> int:
            ans = input(f"  {prompt} [{default}]: ").strip()
            try:
                return int(ans) if ans else default
            except ValueError:
                return default

        def _ask_bool(prompt: str, default: bool) -> bool:
            default_str = "Y/n" if default else "y/N"
            ans = input(f"  {prompt} [{default_str}]: ").strip().lower()
            if ans in ("", "y", "yes"):
                return True
            if ans in ("n", "no"):
                return False
            return default

        policy["min_length"]      = _ask_int("Minimum password length?", 8)
        policy["max_length"]      = _ask_int("Maximum password length? (0 = no limit)", 0)
        policy["require_upper"]   = _ask_bool("Require uppercase letter?", False)
        policy["require_number"]  = _ask_bool("Require at least one digit?", False)
        policy["require_special"] = _ask_bool("Require special character?", False)

        forbidden_raw = input("  Forbidden characters (e.g. <>\"'): ").strip()
        policy["forbidden_chars"] = list(forbidden_raw) if forbidden_raw else []
        policy["common_words_blocked"] = _ask_bool("Common words blocked?", True)

        return policy

    # ── Combined run ──────────────────────────────────────────────────────────

    def analyze(self, domain: str) -> dict:
        """
        Try auto-detect, then fill gaps with session scraped text,
        then fallback to defaults. Updates session.policy.
        """
        console.print()
        console.print(f"  [color(214)][*][/] Auto-detecting password policy for [bold]{domain}[/]...")

        policy = dict(DEFAULT_POLICY)

        auto = self.detect_from_website(domain)
        policy.update(auto)

        scraped = self.detect_from_error_messages()
        for k, v in scraped.items():
            if k not in auto:
                policy[k] = v

        if not auto and not scraped:
            console.print("  [yellow][!][/] Could not auto-detect policy.")
            ans = input("  Manually enter policy? [Y/n]: ").strip().lower()
            if ans in ("", "y", "yes"):
                manual = self.manual_input()
                policy.update(manual)
        else:
            console.print(f"  [green][+][/] Policy detected: {auto}")

        self.session.policy = policy
        self._display_policy(policy)
        return policy

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _parse_policy_text(self, text: str) -> dict:
        partial: dict = {}
        for pattern, field, cast in _POLICY_PATTERNS:
            m = re.search(pattern, text, re.IGNORECASE)
            if m:
                if cast == "int":
                    try:
                        partial[field] = int(m.group(1))
                    except (IndexError, ValueError):
                        pass
                elif cast == "bool":
                    partial[field] = True
        return partial

    def _display_policy(self, policy: dict) -> None:
        t = Table(
            title="Detected Password Policy",
            box=box.ROUNDED,
            header_style="bold color(214)",
            border_style="dim color(178)",
        )
        t.add_column("Constraint",  style="bold", width=24)
        t.add_column("Value",       width=16)

        t.add_row("Min length",       str(policy.get("min_length", "–")))
        t.add_row("Max length",       str(policy.get("max_length", "none")) if policy.get("max_length") else "none")
        t.add_row("Require uppercase", "[green]yes[/]" if policy.get("require_upper") else "[dim]no[/]")
        t.add_row("Require number",   "[green]yes[/]" if policy.get("require_number") else "[dim]no[/]")
        t.add_row("Require special",  "[green]yes[/]" if policy.get("require_special") else "[dim]no[/]")
        t.add_row("Common blocked",   "[green]yes[/]" if policy.get("common_words_blocked") else "[dim]no[/]")

        forbidden = policy.get("forbidden_chars", [])
        t.add_row("Forbidden chars",  "".join(forbidden) if forbidden else "[dim]none[/]")

        console.print()
        console.print(t)
        console.print()
