"""Scope-aware HTTP — the single choke point for every outbound request to a
target (or a known third-party API), so scope/exclude enforcement cannot be
bypassed by a redirect, an absolute document URL, or a derived request.

Why this exists: the pipeline historically scope-checked only the apex domain
once, then fanned out — the scraper followed redirects anywhere with TLS
verification OFF, `collect_metadata` fetched absolute document URLs from any
host, and the policy analyzer hit login pages with no re-check. A homepage
that 302s to `169.254.169.254` (cloud metadata) or an internal host would be
fetched and parsed. `ScopedHTTPClient` closes that hole:

- TLS verification is ON by default.
- Redirects are followed manually; **every hop's host is re-checked**.
- `mode="target"` requires each host to pass the engagement scope (and never
  be excluded); private/loopback/link-local/reserved IPs are refused outright
  as an SSRF guard, regardless of scope-load state.
- `mode="external"` restricts requests to an explicit host allowlist (crt.sh,
  api.github.com, …) so a third-party API cannot redirect us off-list.
"""
from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from typing import Any, Optional

logger = logging.getLogger(__name__)

_REDIRECT_CODES = {301, 302, 303, 307, 308}
_DEFAULT_UA = "Mozilla/5.0 (compatible; wordsmith-security-audit/1.0)"


class ScopeBlocked(Exception):
    """Raised when a request (or a redirect hop) targets a disallowed host."""


@dataclass
class CappedResponse:
    """Minimal response surface for size-capped downloads."""
    status_code: int
    content: bytes
    url: str
    truncated: bool


def html_parser() -> str:
    """Prefer lxml when installed (faster, more lenient), else stdlib."""
    try:
        import lxml  # noqa: F401
        return "lxml"
    except ImportError:
        return "html.parser"


HTML_PARSER = html_parser()


def _host_of(url: Any) -> str:
    import httpx

    try:
        return (httpx.URL(str(url)).host or "").lower()
    except Exception:
        return ""


def _is_blocked_ip_literal(host: str) -> bool:
    """True if host is an IP literal in a range we must never fetch (SSRF)."""
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


class ScopedHTTPClient:
    def __init__(
        self,
        *,
        scope_mgr: Any = None,
        mode: str = "target",
        allow_hosts: Optional[list[str]] = None,
        headers: Optional[dict[str, str]] = None,
        timeout: float = 10.0,
        max_redirects: int = 5,
        verify: bool = True,
        audit: Any = None,
        _transport: Any = None,  # test seam (httpx.MockTransport)
    ) -> None:
        import httpx

        if mode not in ("target", "external"):
            raise ValueError(f"invalid mode: {mode!r}")
        self._scope = scope_mgr
        self._mode = mode
        self._allow = {h.lower() for h in (allow_hosts or [])}
        self._max_redirects = max_redirects
        self._audit = audit
        hdrs = {"User-Agent": _DEFAULT_UA}
        if headers:
            hdrs.update(headers)
        client_kwargs: dict[str, Any] = dict(
            headers=hdrs, timeout=timeout, follow_redirects=False, verify=verify
        )
        if _transport is not None:
            client_kwargs["transport"] = _transport
        self._client = httpx.Client(**client_kwargs)

    # ── host policy ────────────────────────────────────────────────────────────

    def _host_ok(self, host: str) -> bool:
        host = (host or "").lower().split(":")[0]
        if not host:
            return False
        if self._mode == "external":
            return any(host == a or host.endswith("." + a) for a in self._allow)
        # target mode
        if _is_blocked_ip_literal(host):
            return False  # SSRF guard, independent of scope-load state
        if self._scope is None or not getattr(self._scope, "loaded", False):
            return True  # warn-mode; --auto refuses to reach here unloaded
        return bool(self._scope.check_scope(host))

    def _guard(self, url: Any) -> str:
        host = _host_of(url)
        if not self._host_ok(host):
            if self._audit is not None:
                try:
                    self._audit.log("net.blocked", url=str(url), host=host, mode=self._mode)
                except Exception:
                    pass
            raise ScopeBlocked(
                f"Refused {self._mode}-scope request to {host or url!r} "
                f"(not authorized / excluded / unsafe)"
            )
        return host

    # ── requests ─────────────────────────────────────────────────────────────

    def get(self, url: str, *, params: Any = None, headers: Any = None):
        """Follow redirects manually, scope-checking every hop. Returns the
        final httpx.Response (fully read)."""
        import httpx

        current = httpx.URL(url)
        if params:
            current = current.copy_merge_params(params)
        for _ in range(self._max_redirects + 1):
            self._guard(current)
            resp = self._client.get(current, headers=headers)
            if resp.status_code in _REDIRECT_CODES and "location" in resp.headers:
                current = current.join(resp.headers["location"])
                continue
            return resp
        raise ScopeBlocked(f"Too many redirects starting from {url!r}")

    def get_capped(self, url: str, *, max_bytes: int, headers: Any = None) -> CappedResponse:
        """Like get(), but streams the final body and stops after max_bytes —
        so a hostile server cannot exhaust memory with a huge response."""
        import httpx

        current = httpx.URL(url)
        for _ in range(self._max_redirects + 1):
            self._guard(current)
            with self._client.stream("GET", current, headers=headers) as resp:
                if resp.status_code in _REDIRECT_CODES and "location" in resp.headers:
                    current = current.join(resp.headers["location"])
                    continue
                buf = bytearray()
                truncated = False
                for chunk in resp.iter_bytes():
                    buf.extend(chunk)
                    if len(buf) > max_bytes:
                        truncated = True
                        break
                return CappedResponse(
                    status_code=resp.status_code,
                    content=bytes(buf[:max_bytes]),
                    url=str(resp.url),
                    truncated=truncated,
                )
        raise ScopeBlocked(f"Too many redirects starting from {url!r}")

    # ── lifecycle ──────────────────────────────────────────────────────────────

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "ScopedHTTPClient":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()
