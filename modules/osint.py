"""OSINT collector — passive public-data gathering for target intelligence."""
from __future__ import annotations

import json
import logging
import re
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError, as_completed
from pathlib import Path
from typing import Any, Optional

from rich import box
from rich.console import Console
from .banner import console as _banner_console
from rich.table import Table

from .audit import get_logger
from .netutil import ScopedHTTPClient, ScopeBlocked
from .scope import ScopeManager, DEFAULT_SCOPE_FILE
from .state import WordsmithSession

logger = logging.getLogger(__name__)
console = _banner_console

# Wall-clock budget for the parallel collection phase.
OSINT_DEADLINE = 120

_COMMON_SUBDOMAINS = [
    "www", "mail", "vpn", "remote", "admin", "portal", "dev", "staging",
    "api", "app", "login", "secure", "employees", "hr", "finance", "it",
    "web", "mx", "smtp", "ftp", "pop", "imap", "autodiscover", "owa",
    "webmail", "support", "helpdesk", "jira", "gitlab", "github",
    "jenkins", "confluence", "docs", "intranet", "extranet", "crm",
    "erp", "monitor", "nagios", "grafana", "kibana", "elastic",
]


class OSINTCollector:
    """
    Passively collects public intelligence about a target domain.
    All collection is read-only — no active scanning or authentication.
    """

    def __init__(self, session: WordsmithSession, scope_file: Path = DEFAULT_SCOPE_FILE) -> None:
        self.session    = session
        self._scope_mgr = ScopeManager(scope_file)
        self._audit     = get_logger(session.session_id)
        self._results: dict[str, Any] = {}

    def collect_all(self, domain: str) -> dict[str, Any]:
        """
        Run all collection methods in parallel.
        Returns enriched osint_data dict.
        """
        self._scope_mgr.require_scope(domain, "OSINT collection")
        self._audit.log("osint.start", domain=domain)

        # Email harvest is intentionally NOT in this pool: it reads whois /
        # social results and so must run AFTER they resolve (previously it
        # raced them, leaving the registrant-email path effectively dead).
        methods = {
            "whois":        lambda: self.collect_whois(domain),
            "dns":          lambda: self.collect_dns(domain),
            "certificates": lambda: self.collect_certificates(domain),
            "social":       lambda: self.collect_social(domain),
            "metadata":     lambda: self.collect_metadata(domain),
        }

        source_status: dict[str, tuple[str, str]] = {}

        with ThreadPoolExecutor(max_workers=4) as pool:
            futures = {pool.submit(fn): name for name, fn in methods.items()}
            pending = set(futures)

            def _collect(future) -> None:
                name = futures[future]
                try:
                    result = future.result()
                    self._results[name] = result
                    summary = self._summarize(name, result)
                    source_status[name] = ("✓", summary)
                    self._audit.log("osint.source_done", source=name, domain=domain)
                except Exception as exc:
                    logger.warning("OSINT %s failed: %s", name, exc)
                    self._results[name] = {}
                    source_status[name] = ("✗", str(exc)[:60])

            try:
                for future in as_completed(pending, timeout=OSINT_DEADLINE):
                    pending.discard(future)
                    _collect(future)
            except FuturesTimeoutError:
                # One or more sources are still running past the deadline.
                # Salvage anything that finished in the meantime and mark the
                # rest as timed out instead of losing the whole batch.
                for future in pending:
                    name = futures[future]
                    if future.done():
                        _collect(future)
                    else:
                        future.cancel()
                        logger.warning("OSINT %s timed out after %ss", name, OSINT_DEADLINE)
                        self._results[name] = {}
                        source_status[name] = ("✗", f"timed out after {OSINT_DEADLINE}s")

        # Website scrape is done separately (may be slow). Honor scope's
        # allowed_modules, and hand the scraper the SAME scope manager so its
        # fetches are scope-checked too.
        if self._scope_mgr.module_allowed("scraper"):
            try:
                from .scraper import WebScraper
                scraper = WebScraper(self.session, scope_mgr=self._scope_mgr)
                scraped = scraper.scrape(domain)
                self._results["website"] = {"words": scraped, "count": len(scraped)}
                source_status["website"] = ("✓", f"{len(scraped)} words scraped")
            except Exception as exc:
                logger.warning("Website scrape failed: %s", exc)
                self._results["website"] = {}
                source_status["website"] = ("✗", str(exc)[:60])
        else:
            source_status["website"] = ("–", "skipped (scope restriction)")

        self._merge_to_session()
        # Publish collected sources BEFORE the email pass, with update() rather
        # than a wholesale reassignment, so _parse_email_pattern's
        # osint_data["email_format"] is preserved instead of clobbered.
        self.session.osint_data.update(self._results)

        try:
            emails = self.collect_emails(domain)
            self._results["emails"] = emails
            source_status["emails"] = ("✓", self._summarize("emails", emails))
        except Exception as exc:
            logger.warning("OSINT emails failed: %s", exc)
            self._results["emails"] = []
            source_status["emails"] = ("✗", str(exc)[:60])
        self.session.osint_data.update(self._results)

        self._display_results(source_status)
        self._audit.log("osint.complete", domain=domain, sources=list(self._results.keys()))
        return self._results

    # ── Method 1: WHOIS ───────────────────────────────────────────────────────

    def collect_whois(self, domain: str) -> dict:
        """Extract org name, emails, registration dates from WHOIS."""
        try:
            import whois as whois_lib
        except ImportError:
            return {"error": "python-whois not installed"}

        try:
            w = whois_lib.whois(domain)
            result: dict[str, Any] = {}

            def _first(v):
                return (v[0] if isinstance(v, list) else v) or ""

            result["registrant_name"]  = str(_first(getattr(w, "name", "")))
            result["registrant_org"]   = str(_first(getattr(w, "org", "")))
            result["registrant_email"] = str(_first(getattr(w, "emails", "")))
            result["registrant_country"] = str(_first(getattr(w, "country", "")))
            result["registrant_city"]  = str(_first(getattr(w, "city", "")))
            result["registrar"]        = str(_first(getattr(w, "registrar", "")))
            result["name_servers"]     = [str(ns).lower() for ns in (getattr(w, "name_servers", None) or [])]

            creation = getattr(w, "creation_date", None)
            if creation:
                if isinstance(creation, list):
                    creation = creation[0]
                result["creation_date"] = str(creation)
                try:
                    result["founded_year"] = str(creation.year)
                except Exception:
                    pass

            # Seed session
            if result.get("registrant_org"):
                self._seed_org_name(result["registrant_org"])
            if result.get("registrant_name"):
                self.session.target_employees.append(result["registrant_name"])
            if result.get("registrant_city"):
                self.session.target_location = result["registrant_city"]
            if result.get("founded_year"):
                self.session.target_founded_year = result["founded_year"]

            return result
        except Exception as exc:
            return {"error": str(exc)}

    # ── Method 2: DNS ─────────────────────────────────────────────────────────

    def collect_dns(self, domain: str) -> dict:
        """Enumerate DNS records and discover subdomains."""
        try:
            import dns.resolver
            import dns.exception
        except ImportError:
            return {"error": "dnspython not installed"}

        result: dict[str, Any] = {
            "a_records": [],
            "mx_records": [],
            "txt_records": [],
            "ns_records": [],
            "subdomains": [],
            "mail_provider": "",
        }

        def _query(rtype: str) -> list[str]:
            try:
                return [str(r) for r in dns.resolver.resolve(domain, rtype)]
            except Exception:
                return []

        result["a_records"]   = _query("A")
        result["ns_records"]  = _query("NS")
        result["txt_records"] = _query("TXT")

        mx = _query("MX")
        result["mx_records"] = mx
        for m in mx:
            m_low = m.lower()
            if "google" in m_low or "gmail" in m_low:
                result["mail_provider"] = "Google Workspace"
            elif "outlook" in m_low or "microsoft" in m_low:
                result["mail_provider"] = "Microsoft 365"

        # SPF / DKIM patterns from TXT
        services: list[str] = []
        for txt in result["txt_records"]:
            for svc in re.findall(r"include:([a-z0-9.-]+)", txt, re.IGNORECASE):
                services.append(svc.split(".")[0])
        result["services_from_spf"] = list(set(services))

        # SOA admin email
        try:
            soa = dns.resolver.resolve(domain, "SOA")
            for r in soa:
                admin_raw = str(r.rname)
                if admin_raw:
                    admin_email = admin_raw.replace(".", "@", 1).rstrip(".")
                    result["soa_admin"] = admin_email
                    name_part = admin_email.split("@")[0]
                    self.session.target_keywords.append(name_part)
        except Exception:
            pass

        # Subdomain enumeration — scope + exclude enforced per name. An
        # explicitly EXCLUDED subdomain (e.g. mail.<domain> carved out by the
        # client) must never be resolved, even though it falls under an
        # authorized apex. "exclude always wins" has to hold here too.
        found_subs: list[str] = []
        for sub in _COMMON_SUBDOMAINS:
            fqdn = f"{sub}.{domain}"
            if not self._scope_mgr.check_scope(fqdn):
                logger.debug("Skipping out-of-scope/excluded subdomain %s", fqdn)
                continue
            try:
                dns.resolver.resolve(fqdn, "A", lifetime=2)
                found_subs.append(fqdn)
                self.session.target_keywords.append(sub)
            except Exception:
                pass
        result["subdomains"] = found_subs

        return result

    # ── Method 3: Website (delegated to scraper) ──────────────────────────────

    def collect_website(self, domain: str) -> dict:
        """Delegate to WebScraper and merge results."""
        from .scraper import WebScraper
        scraper = WebScraper(self.session)
        words = scraper.scrape(domain)
        return {"words": words, "count": len(words)}

    # ── Method 4: Certificates (crt.sh) ──────────────────────────────────────

    @staticmethod
    def _is_subdomain(name: str, domain: str) -> bool:
        """True iff `name` is `domain` itself or a dot-anchored subdomain of it.

        Replaces the old `if domain in name` substring test, under which
        `example.company.com` and `notexample.com` both matched `example.com`.
        """
        name = name.lower().strip().lstrip("*.")
        domain = domain.lower().strip()
        return bool(name) and (name == domain or name.endswith("." + domain))

    def collect_certificates(self, domain: str) -> dict:
        """Query crt.sh for certificate transparency logs."""
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            with ScopedHTTPClient(
                mode="external", allow_hosts=["crt.sh"], timeout=15.0, audit=self._audit
            ) as client:
                resp = client.get(url)
            if resp.status_code != 200:
                return {"error": f"crt.sh returned {resp.status_code}"}

            certs = resp.json()
            subdomains: set[str] = set()
            org_names: list[str] = []
            ou_names:  list[str] = []

            for cert in certs:
                for field in ("common_name", "name_value"):
                    val = cert.get(field, "")
                    for name in val.split("\n"):
                        name = name.strip().lower().lstrip("*.")
                        if self._is_subdomain(name, domain) and name not in subdomains:
                            subdomains.add(name)

                issuer = cert.get("issuer_ca_id", "")
                org = cert.get("issuer_name", "")
                if "O=" in org:
                    for part in org.split(","):
                        if part.strip().startswith("O="):
                            org_names.append(part.strip()[2:])
                        elif part.strip().startswith("OU="):
                            ou_names.append(part.strip()[3:])

            for org in org_names:
                self._seed_org_name(org)
            for ou in ou_names:
                self.session.target_keywords.append(ou.lower())

            return {
                "subdomains": list(subdomains),
                "org_names": list(set(org_names)),
                "ou_names": list(set(ou_names)),
            }
        except Exception as exc:
            return {"error": str(exc)}

    # ── Method 5: Social (passive) ────────────────────────────────────────────

    def collect_social(self, domain: str) -> dict:
        """Passive social signal collection — GitHub, HN, Reddit (no auth required)."""
        result: dict[str, Any] = {
            "github_repos": [],
            "contributors": [],
            "commit_emails": [],
            "hn_mentions": 0,
            "reddit_mentions": 0,
            "linkedin_dork": "",
        }

        org_name = self.session.target_name or domain.split(".")[0]
        result["linkedin_dork"] = (
            f'site:linkedin.com/in "{org_name}" — run manually in browser'
        )

        with ScopedHTTPClient(
            mode="external",
            allow_hosts=[
                "api.github.com", "github.com",
                "hn.algolia.com", "algolia.com",
                "reddit.com", "www.reddit.com",
            ],
            headers={"User-Agent": "security-audit/1.0"},
            timeout=10.0,
            audit=self._audit,
        ) as client:
            # GitHub repos
            try:
                resp = client.get(
                    "https://api.github.com/search/repositories",
                    params={"q": domain, "per_page": 10},
                )
                if resp.status_code == 403:
                    logger.debug("GitHub search rate-limited (unauthenticated 403)")
                if resp.status_code == 200:
                    for repo in resp.json().get("items", []):
                        result["github_repos"].append(repo.get("full_name", ""))
                        owner = repo.get("owner", {}).get("login", "")
                        if owner:
                            self.session.target_keywords.append(owner)
                            result["contributors"].append(owner)
            except Exception as exc:
                logger.debug("GitHub search failed: %s", exc)

            # Commit author emails from top repos
            for repo_name in result["github_repos"][:3]:
                try:
                    resp = client.get(
                        f"https://api.github.com/repos/{repo_name}/commits",
                        params={"per_page": 30},
                    )
                    if resp.status_code == 200:
                        for commit in resp.json():
                            commit_data = commit.get("commit", {})
                            for role in ("author", "committer"):
                                author = commit_data.get(role, {})
                                email = author.get("email", "")
                                name  = author.get("name", "")
                                if email and domain in email:
                                    result["commit_emails"].append(email)
                                    self.session.target_emails.append(email)
                                if name and name not in result["contributors"]:
                                    result["contributors"].append(name)
                                    self.session.target_employees.append(name)
                    time.sleep(0.5)
                except Exception as exc:
                    logger.debug("Commit fetch failed: %s", exc)

            # HackerNews
            try:
                resp = client.get(
                    "https://hn.algolia.com/api/v1/search",
                    params={"query": domain, "hitsPerPage": 5},
                )
                if resp.status_code == 200:
                    result["hn_mentions"] = resp.json().get("nbHits", 0)
            except Exception:
                pass

            # Reddit
            try:
                resp = client.get(
                    "https://www.reddit.com/search.json",
                    params={"q": domain, "limit": 5},
                    headers={"User-Agent": "security-audit/1.0"},
                )
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    result["reddit_mentions"] = data.get("dist", 0)
            except Exception:
                pass

        return result

    # ── Method 6: Email harvest ───────────────────────────────────────────────

    def collect_emails(self, domain: str) -> list[str]:
        """Collect emails from WHOIS, certs, GitHub commits, and optionally Hunter.io."""
        emails: set[str] = set()

        # From previously collected sources
        for src in (self._results.get("whois", {}), ):
            email = src.get("registrant_email", "")
            if email and "@" in email:
                emails.add(email.lower())

        for email in self.session.target_emails:
            if "@" in email:
                emails.add(email.lower())

        # Deduplicate and parse patterns
        clean = [e for e in emails if domain in e]
        if clean:
            self._parse_email_pattern(clean)

        # Extract first/last names
        for email in clean:
            local = email.split("@")[0]
            for sep in (".", "_", "-"):
                if sep in local:
                    parts = local.split(sep)
                    for p in parts:
                        if p.isalpha() and len(p) >= 2:
                            self.session.target_keywords.append(p)
                            self.session.target_employees.append(p.title())

        return list(emails)

    # ── Method 7: Document metadata ───────────────────────────────────────────

    def collect_metadata(self, domain: str) -> dict:
        """Download up to 5 public documents and extract author metadata.

        Every fetch goes through the scope-aware client (TLS on, redirects
        re-checked per hop) and is size-capped by streaming — so an absolute
        off-scope document URL is refused and a huge response can't exhaust
        memory (the old code buffered the full body *before* its 5 MB check).
        """
        from urllib.parse import urljoin

        result: dict[str, Any] = {"documents": [], "authors": [], "software": []}
        DOC_CAP = 5 * 1024 * 1024

        try:
            with ScopedHTTPClient(
                scope_mgr=self._scope_mgr, mode="target",
                headers={"User-Agent": "Mozilla/5.0"}, timeout=10.0, audit=self._audit,
            ) as client:
                try:
                    home = client.get_capped(f"https://{domain}", max_bytes=2 * 1024 * 1024)
                except ScopeBlocked as exc:
                    logger.debug("metadata homepage blocked: %s", exc)
                    return result
                if home.status_code != 200:
                    return result

                html = home.content.decode("utf-8", "ignore")
                doc_urls = re.findall(
                    r'href=["\']([^"\']*\.(?:pdf|docx|xlsx|pptx))["\']',
                    html,
                    re.IGNORECASE,
                )

                for doc_url in doc_urls[:5]:
                    full_url = urljoin(f"https://{domain}", doc_url)
                    try:
                        doc = client.get_capped(full_url, max_bytes=DOC_CAP)
                    except ScopeBlocked as exc:
                        logger.debug("off-scope document URL refused %s: %s", full_url, exc)
                        continue
                    except Exception as exc:
                        logger.debug("Doc fetch failed %s: %s", full_url, exc)
                        continue
                    if doc.status_code != 200 or doc.truncated:
                        continue  # non-200, or larger than the cap
                    meta = self._extract_doc_metadata(doc.content, full_url)
                    if meta:
                        result["documents"].append({"url": full_url, "metadata": meta})
                        for field in ("author", "creator", "last_modified_by", "company"):
                            val = meta.get(field, "")
                            if val:
                                result["authors"].append(val)
                                self.session.target_employees.append(val)
                        for field in ("software", "producer"):
                            val = meta.get(field, "")
                            if val:
                                result["software"].append(val)

        except Exception as exc:
            result["error"] = str(exc)

        return result

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _seed_org_name(self, org: str) -> None:
        """Parse org name and seed keywords."""
        if not org:
            return
        clean = re.sub(r"\b(ltd|llc|inc|corp|limited|pvt|private|co|company)\b", "", org, flags=re.IGNORECASE)
        clean = re.sub(r"[^\w\s]", " ", clean).strip()
        for part in clean.split():
            if len(part) >= 3:
                self.session.target_keywords.append(part.lower())
        if not self.session.target_name:
            self.session.target_name = clean.strip()

    def _parse_email_pattern(self, emails: list[str]) -> None:
        """Detect email format and add to session."""
        patterns: list[str] = []
        for email in emails:
            local = email.split("@")[0]
            if "." in local:
                parts = local.split(".")
                if len(parts) == 2:
                    if len(parts[0]) == 1:
                        patterns.append("f.lastname")
                    else:
                        patterns.append("firstname.lastname")
            elif "_" in local:
                patterns.append("firstname_lastname")
            elif re.match(r"^[a-z]+[0-9]*$", local):
                patterns.append("firstname")

        if patterns:
            self.session.osint_data["email_format"] = max(set(patterns), key=patterns.count)

    def _extract_doc_metadata(self, content: bytes, url: str) -> dict:
        """Extract metadata from PDF content using pypdf."""
        meta: dict = {}
        if url.lower().endswith(".pdf"):
            try:
                import io
                from pypdf import PdfReader
                reader = PdfReader(io.BytesIO(content))
                info = reader.metadata
                if info:
                    meta["author"]   = str(info.get("/Author", ""))
                    meta["creator"]  = str(info.get("/Creator", ""))
                    meta["producer"] = str(info.get("/Producer", ""))
                    meta["title"]    = str(info.get("/Title", ""))
            except Exception:
                pass
        return meta

    def _summarize(self, source: str, result: dict) -> str:
        """Build a short summary string for the results table."""
        if "error" in result:
            return f"error: {result['error'][:40]}"
        summaries = {
            "whois":        lambda r: f"org={r.get('registrant_org', '?')[:20]}, year={r.get('founded_year', '?')}",
            "dns":          lambda r: f"{len(r.get('subdomains', []))} subdomains, MX={r.get('mail_provider', '?')[:15]}",
            "certificates": lambda r: f"{len(r.get('subdomains', []))} subdomains, {len(r.get('org_names', []))} org variants",
            "social":       lambda r: f"{len(r.get('github_repos', []))} repos, {len(r.get('contributors', []))} contributors",
            "emails":       lambda r: f"{len(r) if isinstance(r, list) else 0} addresses",
            "metadata":     lambda r: f"{len(r.get('documents', []))} documents, {len(r.get('authors', []))} authors",
            "website":      lambda r: f"{r.get('count', 0)} words",
        }
        try:
            return summaries.get(source, lambda r: str(len(r)))(result)
        except Exception:
            return "ok"

    def _merge_to_session(self) -> None:
        """Merge collected data back into session fields."""
        # Deduplicate keywords and employees
        seen_kw: set[str] = set()
        clean_kw: list[str] = []
        for w in self.session.target_keywords:
            if w.lower() not in seen_kw:
                seen_kw.add(w.lower())
                clean_kw.append(w)
        self.session.target_keywords = clean_kw

        seen_emp: set[str] = set()
        clean_emp: list[str] = []
        for e in self.session.target_employees:
            if e.lower() not in seen_emp:
                seen_emp.add(e.lower())
                clean_emp.append(e)
        self.session.target_employees = clean_emp

    def _display_results(self, status: dict[str, tuple[str, str]]) -> None:
        """Display a Rich summary table of collection results."""
        t = Table(
            title="OSINT Collection Summary",
            box=box.ROUNDED,
            header_style="bold color(214)",
            border_style="dim color(178)",
        )
        t.add_column("Source",       style="bold", width=16)
        t.add_column("Status",       justify="center", width=8)
        t.add_column("Items Found",  width=50)

        order = ["whois", "dns", "website", "certificates", "social", "emails", "metadata"]
        for src in order:
            icon, summary = status.get(src, ("–", "not run"))
            icon_fmt = f"[green]{icon}[/]" if icon == "✓" else f"[red]{icon}[/]"
            t.add_row(src.title(), icon_fmt, summary)

        console.print()
        console.print(t)

        # Seed summary
        console.print()
        console.print(f"  [bold color(214)]Seed Summary:[/]")
        console.print(f"  Names found:    [color(220)]{len(self.session.target_employees)}[/]")
        console.print(f"  Keywords found: [color(220)]{len(self.session.target_keywords)}[/]")
        years = [self.session.target_founded_year] if self.session.target_founded_year else []
        console.print(f"  Years found:    [color(220)]{', '.join(years) or 'none'}[/]")
        console.print(f"  Products found: [color(220)]{len(self.session.target_products)}[/]")
        console.print(f"  Location:       [color(220)]{self.session.target_location or 'unknown'}[/]")
        console.print()
