"""Scope enforcement — authorize targets before any OSINT or scraping."""
from __future__ import annotations

import ipaddress
import logging
import re
from datetime import date, datetime
from pathlib import Path
from typing import Optional

import yaml
from rich import box
from rich.console import Console
from .banner import console as _banner_console
from rich.panel import Panel

logger = logging.getLogger(__name__)
console = _banner_console

DEFAULT_SCOPE_FILE = Path("scope.yaml")


class ScopeError(Exception):
    """Raised when a target is outside the authorized scope."""

    def __init__(self, message: str, target: str = "") -> None:
        super().__init__(message)
        self.target = target


class ScopeManager:
    """
    Load scope.yaml and enforce domain/IP/email authorization before
    any OSINT collection, scraping, or mutation targeting that target.

    Call check_scope(target) before EVERY outbound operation.
    """

    def __init__(self, scope_file: Path = DEFAULT_SCOPE_FILE) -> None:
        self._scope_file = scope_file
        self._engagement: dict = {}
        self._domains: list[str] = []
        self._ip_networks: list[ipaddress._BaseNetwork] = []
        self._email_patterns: list[str] = []
        self._restrictions: dict = {}
        self._loaded = False

        if scope_file.exists():
            self._load(scope_file)
        else:
            logger.debug("No scope file at %s", scope_file)

    def _load(self, path: Path) -> None:
        try:
            with open(path, encoding="utf-8") as fh:
                data = yaml.safe_load(fh) or {}

            self._engagement = data.get("engagement", {})
            targets = data.get("targets", {})
            self._domains = [d.lower() for d in targets.get("domains", [])]
            self._email_patterns = [e.lower() for e in targets.get("emails", [])]
            self._restrictions = data.get("restrictions", {})
            self._loaded = True

            for ip_str in targets.get("ip_ranges", []):
                try:
                    self._ip_networks.append(ipaddress.ip_network(ip_str, strict=False))
                except ValueError:
                    logger.warning("Invalid IP range in scope: %s", ip_str)

            logger.info(
                "Scope loaded: %d domains, %d IP ranges — from %s",
                len(self._domains), len(self._ip_networks), path,
            )
        except Exception as exc:
            logger.error("Failed to load scope file %s: %s", path, exc)

    # ── Core check ────────────────────────────────────────────────────────────

    def check_scope(self, target: str) -> bool:
        """Return True if target is authorized. Never raises — use require_scope() for hard blocking."""
        if not self._loaded:
            return True  # No scope file = warn mode, don't block

        # Email pattern check
        if "@" in target and not target.startswith("@"):
            domain_part = target.split("@")[-1].lower()
            if any(
                domain_part == pat.lstrip("@") or target.lower() == pat
                for pat in self._email_patterns
            ):
                return True
            # Fall through to domain check
            target = domain_part

        # IP address check
        try:
            addr = ipaddress.ip_address(target)
            return any(addr in net for net in self._ip_networks)
        except ValueError:
            pass

        # Domain / wildcard check
        target_lower = target.lower().lstrip("*.")
        for pattern in self._domains:
            clean_pattern = pattern.lstrip("*.")
            if target_lower == clean_pattern or target_lower.endswith("." + clean_pattern):
                return self._check_expiry()
        return False

    def require_scope(self, target: str, operation: str = "this operation") -> None:
        """
        Hard block if target is not in scope.
        Raises ScopeError with a clear message. Must be called before every outbound action.
        """
        if not self._loaded:
            console.print(
                "[yellow]  ⚠  No scope.yaml loaded — proceeding without scope enforcement.\n"
                "  Run [bold]wordsmith --scope-wizard[/bold] to create one.[/yellow]"
            )
            return

        if not self.check_scope(target):
            raise ScopeError(
                f"Target {target!r} is NOT in scope.yaml.\n"
                f"Obtain written authorization and add it before {operation!r}.",
                target=target,
            )
        logger.info("Scope PASSED: %s → %s", target, operation)

    def _check_expiry(self) -> bool:
        expiry_str = self._engagement.get("expiry_date", "")
        if not expiry_str:
            return True
        try:
            expiry = datetime.strptime(str(expiry_str), "%Y-%m-%d").date()
            if date.today() > expiry:
                logger.warning("Scope expired on %s", expiry_str)
                return False
        except ValueError:
            pass
        return True

    @property
    def loaded(self) -> bool:
        return self._loaded

    @property
    def restrictions(self) -> dict:
        return self._restrictions

    @property
    def engagement(self) -> dict:
        return self._engagement


# ── Module-level helpers ──────────────────────────────────────────────────────

def check_scope(target: str, scope_file: Path = DEFAULT_SCOPE_FILE) -> bool:
    """Convenience: check target against scope.yaml, warn if not loaded."""
    mgr = ScopeManager(scope_file)
    if not mgr.loaded:
        console.print(
            "[yellow]  ⚠  No scope.yaml found. "
            "Run [bold]wordsmith --scope-wizard[/bold] to create one.[/yellow]"
        )
        return True  # Warn but don't block when no file
    return mgr.check_scope(target)


# ── Scope wizard ──────────────────────────────────────────────────────────────

def scope_wizard(output_path: Path = DEFAULT_SCOPE_FILE) -> None:
    """Interactive CLI wizard to build scope.yaml."""
    console.print()
    console.print(Panel.fit(
        "[bold yellow]⚠  SCOPE WIZARD — AUTHORIZATION CHECKLIST  ⚠[/]\n\n"
        "You MUST hold written authorization before targeting any system.\n"
        "Confirm ALL of the following:",
        box=box.DOUBLE,
        border_style="red",
    ))
    console.print()

    checklist = [
        "I own this domain/system OR hold WRITTEN permission from the owner",
        "The permission specifies exact dates and scope of the engagement",
        "I understand unauthorized access violates CFAA / IT Act 2000 / similar laws",
        "I will use wordsmith ONLY for the systems listed in this scope file",
        "I will store generated wordlists securely and delete them when done",
        "I accept full legal responsibility for actions taken during this engagement",
    ]

    for i, item in enumerate(checklist, 1):
        console.print(f"  [bold color(214)]{i}.[/] {item}")

    console.print()
    answer = input("Type exactly  YES I CONFIRM  to proceed: ").strip()
    if answer != "YES I CONFIRM":
        console.print("[red]Aborted — scope.yaml was NOT created.[/]")
        return

    console.print()
    engagement_name  = input("Engagement name (e.g. 'Acme Corp Pentest Q3 2026'): ").strip()
    authorized_by    = input("Authorized by (full name, title): ").strip()
    auth_date        = input("Authorization date (YYYY-MM-DD): ").strip()
    expiry_date      = input("Expiry date (YYYY-MM-DD): ").strip()

    domains: list[str] = []
    console.print("\n[dim]Add target domains (blank to finish):[/]")
    while True:
        d = input("  Domain (e.g. example.com or *.example.com): ").strip()
        if not d:
            break
        domains.append(d)

    ip_ranges: list[str] = []
    console.print("\n[dim]Add IP ranges (CIDR, blank to skip):[/]")
    while True:
        ip = input("  IP range (e.g. 192.168.1.0/24): ").strip()
        if not ip:
            break
        try:
            ipaddress.ip_network(ip, strict=False)
            ip_ranges.append(ip)
        except ValueError:
            console.print(f"  [red]Invalid CIDR: {ip}[/]")

    emails: list[str] = []
    console.print("\n[dim]Add email patterns (e.g. @example.com, blank to skip):[/]")
    while True:
        e = input("  Email pattern: ").strip()
        if not e:
            break
        emails.append(e)

    max_size_str = input("\nMax wordlist size (MB, default 500): ").strip()
    try:
        max_size_mb = int(max_size_str)
    except ValueError:
        max_size_mb = 500

    scope_data = {
        "engagement": {
            "name": engagement_name,
            "authorized_by": authorized_by,
            "authorization_date": auth_date,
            "expiry_date": expiry_date,
        },
        "targets": {
            "domains": domains,
            "ip_ranges": ip_ranges,
            "emails": emails,
        },
        "restrictions": {
            "max_wordlist_size_mb": max_size_mb,
            "allowed_modules": ["osint", "scraper", "mutator", "generator"],
        },
    }

    with open(output_path, "w", encoding="utf-8") as fh:
        yaml.dump(scope_data, fh, default_flow_style=False, sort_keys=False, allow_unicode=True)

    console.print(f"\n[bold green]✓ scope.yaml created:[/] {output_path.resolve()}")
    console.print(f"  Engagement: [cyan]{engagement_name}[/]")
    console.print(f"  Domains:    [cyan]{len(domains)}[/]")
    console.print(f"  Expires:    [cyan]{expiry_date}[/]")
