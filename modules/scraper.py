"""Website scraper — crawl target domain and extract meaningful words."""
from __future__ import annotations

import logging
import re
import time
import urllib.robotparser
from collections import deque
from typing import Optional
from urllib.parse import urljoin, urlparse

from rich.console import Console
from .banner import console as _banner_console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TaskProgressColumn

from .netutil import ScopedHTTPClient, ScopeBlocked, HTML_PARSER as _HTML_PARSER
from .state import WordsmithSession

logger = logging.getLogger(__name__)
console = _banner_console

_UA = "Mozilla/5.0 (compatible; wordsmith-security-audit/1.0)"
_ROBOTS_UA = "wordsmith-security-audit"

STOP_WORDS = frozenset([
    "the", "and", "for", "with", "this", "that", "have", "from",
    "they", "will", "would", "could", "should", "about", "which",
    "their", "there", "what", "when", "where", "who", "how", "why",
    "all", "one", "two", "more", "also", "into", "than", "then",
    "your", "our", "its", "his", "her", "can", "are", "was", "were",
    "has", "had", "been", "being", "have", "not", "but", "out",
    "any", "may", "other", "some", "just", "like", "get", "use",
    "new", "time", "long", "very", "even", "back", "only", "come",
    "over", "after", "these", "those", "both", "much", "many",
    "www", "http", "https", "html", "php", "css", "img", "src",
    "href", "class", "style", "type", "data", "value", "name",
    "email", "mailto", "javascript", "function", "var", "const",
    "null", "true", "false", "undefined", "return", "window",
    "document", "object", "array", "string", "number", "boolean",
])

_TITLE_CASE_PATTERN = re.compile(r"^[A-Z][a-z]{2,}$")
_NAME_TRIGGER_WORDS = {
    "ceo", "cto", "coo", "cfo", "ciso", "vp", "director", "founder",
    "co-founder", "head", "chief", "president", "manager", "lead",
    "engineer", "architect", "by", "author", "written", "contact",
}


class WebScraper:
    """
    Crawls a target domain and extracts all meaningful words for wordlist seeding.
    Respects robots.txt, rate-limits to 2 req/s, stays on-domain.
    """

    def __init__(self, session: WordsmithSession, scope_mgr=None) -> None:
        self.session    = session
        self._scope_mgr = scope_mgr
        self.visited:   set[str] = set()
        self._enqueued: set[str] = set()
        self._requeued: set[str] = set()
        self.max_pages  = 50
        self.max_depth  = 3
        self.words:     set[str] = set()
        self.names:     list[str] = []
        self.products:  list[str] = []
        self._robots:   Optional[urllib.robotparser.RobotFileParser] = None
        self._last_req  = 0.0

    def scrape(self, domain: str) -> list[str]:
        """
        Crawl target.domain and return list of unique meaningful words.
        Shows live Rich progress during crawl.
        """
        try:
            from bs4 import BeautifulSoup
        except ImportError as exc:
            console.print(f"  [red][-][/red] Scraper requires beautifulsoup4: {exc}")
            return []

        base_url = f"https://{domain}"
        queue: deque[tuple[str, int]] = deque([(base_url, 0)])
        self._enqueued = {base_url}

        try:
            # Scope-aware client: TLS on, redirects re-checked per hop, and —
            # in target mode — refuses any host outside the engagement scope
            # (so a homepage 302 to an internal/metadata host is blocked).
            client = ScopedHTTPClient(
                scope_mgr=self._scope_mgr, mode="target",
                headers={"User-Agent": _UA}, timeout=10.0,
            )
        except ImportError as exc:
            console.print(f"  [red][-][/red] Scraper requires httpx: {exc}")
            return []

        with client, Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
            transient=True,
        ) as prog:
            task = prog.add_task(
                f"Crawling [color(214)]{domain}[/]...",
                total=self.max_pages,
            )
            self._load_robots(base_url, client)

            while queue and len(self.visited) < self.max_pages:
                url, depth = queue.popleft()
                if url in self.visited or depth > self.max_depth:
                    continue
                if not self._allowed_by_robots(url):
                    continue

                # Count the attempt now (not just successful HTML pages) so the
                # page cap bounds total requests and a dead URL isn't re-fetched.
                self.visited.add(url)
                self._rate_limit()
                try:
                    resp = client.get(url)
                    if resp.status_code == 429:
                        # Back off and re-enqueue ONCE instead of dropping.
                        time.sleep(5)
                        if url not in self._requeued:
                            self._requeued.add(url)
                            self.visited.discard(url)
                            queue.append((url, depth))
                        continue
                    if resp.status_code != 200:
                        continue
                    if "text/html" not in resp.headers.get("content-type", ""):
                        continue

                    soup = BeautifulSoup(resp.text, _HTML_PARSER)

                    page_words   = self._extract_words(soup)
                    page_links   = self._extract_links(soup, url, domain)
                    name_hints   = self._extract_names(soup)
                    product_hits = self._extract_products(soup)

                    self.words.update(page_words)
                    self.names.extend(name_hints)
                    self.products.extend(product_hits)

                    for link in page_links:
                        if link not in self.visited and link not in self._enqueued:
                            self._enqueued.add(link)
                            queue.append((link, depth + 1))

                    prog.advance(task)
                    prog.update(
                        task,
                        description=(
                            f"Crawling [color(214)]{domain}[/] — "
                            f"pages=[color(220)]{len(self.visited)}[/] "
                            f"words=[color(220)]{len(self.words)}[/] "
                            f"depth=[color(220)]{depth}[/]"
                        ),
                    )

                except ScopeBlocked as exc:
                    logger.debug("Blocked off-scope URL %s: %s", url, exc)
                except Exception as exc:
                    logger.debug("Scrape error on %s: %s", url, exc)

        self.session.scraped_words = list(self.words)
        self.session.target_employees.extend(
            n for n in self.names if n not in self.session.target_employees
        )
        self.session.target_products.extend(
            p for p in self.products if p not in self.session.target_products
        )
        logger.info("Scrape done: %d pages, %d words", len(self.visited), len(self.words))
        return list(self.words)

    # ── Content extraction ────────────────────────────────────────────────────

    def _extract_words(self, soup) -> set[str]:
        from bs4 import Comment

        words: set[str] = set()
        selectors = ["h1", "h2", "h3", "h4", "p", "li", "title", "span", "dt", "dd"]

        for tag in soup.find_all(selectors):
            text = tag.get_text(separator=" ")
            words.update(self._tokenize(text))

        # Meta tags
        for meta in soup.find_all("meta", attrs={"name": True}):
            if meta.get("name", "").lower() in ("description", "keywords"):
                words.update(self._tokenize(meta.get("content", "")))

        # Alt attributes
        for img in soup.find_all("img", alt=True):
            words.update(self._tokenize(img["alt"]))

        # Script strings
        for script in soup.find_all("script"):
            if script.string:
                for m in re.finditer(r'(?:APP_NAME|companyName|product|siteName|brand)\s*[=:]\s*["\']([^"\']+)["\']', script.string, re.IGNORECASE):
                    words.update(self._tokenize(m.group(1)))

        return words

    def _tokenize(self, text: str) -> set[str]:
        tokens: set[str] = set()
        for word in re.split(r"[\s\-_/\\|.,;:!?()\"'<>[\]{}]+", text):
            word = word.strip("'\".,;:!?")
            if not word:
                continue
            low = word.lower()
            if (
                4 <= len(word) <= 20
                and not word.isdigit()
                and low not in STOP_WORDS
                and not re.fullmatch(r"[^a-zA-Z0-9]+", word)
            ):
                tokens.add(low)
                if word != low:
                    tokens.add(word)  # preserve original case
        return tokens

    def _extract_links(self, soup, base_url: str, domain: str) -> list[str]:
        links: list[str] = []
        parsed_base = urlparse(base_url)
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            absolute = urljoin(base_url, href)
            parsed = urlparse(absolute)
            # Stay on same domain — dot-anchored so "evilexample.com" and
            # "notexample.com" do NOT count as in-scope for example.com.
            host = parsed.netloc.lower().split(":")[0]
            dom = domain.lower()
            if parsed.scheme in ("http", "https") and (host == dom or host.endswith("." + dom)):
                clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                if clean not in self.visited:
                    links.append(clean)
        return links[:30]  # cap per-page link expansion

    def _extract_names(self, soup) -> list[str]:
        """Detect person names near title words."""
        names: list[str] = []
        full_text = soup.get_text(separator=" ")

        for trigger in _NAME_TRIGGER_WORDS:
            pattern = re.compile(
                rf"\b{re.escape(trigger)}\b[^a-zA-Z]*([A-Z][a-z]+ [A-Z][a-z]+)",
                re.IGNORECASE,
            )
            for m in pattern.finditer(full_text):
                name = m.group(1).strip()
                if name not in names:
                    names.append(name)

        # Two consecutive title-case words not in stop words
        for m in re.finditer(r"\b([A-Z][a-z]{2,}) ([A-Z][a-z]{2,})\b", full_text):
            w1, w2 = m.group(1).lower(), m.group(2).lower()
            if w1 not in STOP_WORDS and w2 not in STOP_WORDS:
                full_name = f"{m.group(1)} {m.group(2)}"
                if full_name not in names:
                    names.append(full_name)

        return names[:20]

    def _extract_products(self, soup) -> list[str]:
        """Detect brand/product names — appear in title, h1, AND meta."""
        products: list[str] = []
        title_words: set[str] = set()

        title_tag = soup.find("title")
        if title_tag:
            for w in title_tag.get_text().split():
                if w[0:1].isupper() and len(w) >= 4 and w.lower() not in STOP_WORDS:
                    title_words.add(w)

        for h1 in soup.find_all("h1"):
            for w in h1.get_text().split():
                if w in title_words:
                    products.append(w.lower())

        return list(dict.fromkeys(products))[:10]

    # ── robots.txt ────────────────────────────────────────────────────────────

    def _load_robots(self, base_url: str, client: ScopedHTTPClient) -> None:
        """Fetch robots.txt through the scope-aware client (which has a
        timeout) rather than urllib's RobotFileParser.read(), which does its
        own un-timed urlopen and can hang indefinitely."""
        try:
            resp = client.get(f"{base_url}/robots.txt")
            if resp.status_code == 200 and resp.text:
                rp = urllib.robotparser.RobotFileParser()
                rp.parse(resp.text.splitlines())
                self._robots = rp
            else:
                self._robots = None
        except Exception as exc:
            logger.debug("robots.txt fetch failed: %s", exc)
            self._robots = None

    def _allowed_by_robots(self, url: str) -> bool:
        if self._robots is None:
            return True
        try:
            return self._robots.can_fetch(_ROBOTS_UA, url)
        except Exception:
            return True

    # ── Rate limiter ──────────────────────────────────────────────────────────

    def _rate_limit(self) -> None:
        """Enforce max 2 requests/second."""
        now = time.monotonic()
        elapsed = now - self._last_req
        if elapsed < 0.5:
            time.sleep(0.5 - elapsed)
        self._last_req = time.monotonic()
