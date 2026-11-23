"""Tests for modules/netutil.py — the scope-aware HTTP choke point that stops
redirect/absolute-URL/SSRF bypasses of scope enforcement."""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

httpx = pytest.importorskip("httpx")

from modules.netutil import ScopedHTTPClient, ScopeBlocked
from modules.scope import ScopeManager


def _scope(tmp_path: Path, yaml_text: str) -> ScopeManager:
    p = tmp_path / "scope.yaml"
    p.write_text(textwrap.dedent(yaml_text), encoding="utf-8")
    return ScopeManager(p)


def _ok_transport():
    return httpx.MockTransport(lambda request: httpx.Response(200, text="ok"))


def test_target_mode_blocks_out_of_scope_host(tmp_path):
    scope = _scope(tmp_path, """
        targets:
          domains: ["example.com"]
    """)
    with ScopedHTTPClient(scope_mgr=scope, mode="target", _transport=_ok_transport()) as c:
        assert c.get("https://example.com/").status_code == 200
        with pytest.raises(ScopeBlocked):
            c.get("https://evil.com/")


def test_target_mode_blocks_excluded_host(tmp_path):
    scope = _scope(tmp_path, """
        targets:
          domains: ["*.example.com"]
        exclude:
          domains: ["mail.example.com"]
    """)
    with ScopedHTTPClient(scope_mgr=scope, mode="target", _transport=_ok_transport()) as c:
        assert c.get("https://app.example.com/").status_code == 200
        with pytest.raises(ScopeBlocked):
            c.get("https://mail.example.com/")


def test_ssrf_link_local_ip_blocked_even_without_scope(tmp_path):
    # No scope manager at all (warn-mode) — the SSRF guard must still fire.
    with ScopedHTTPClient(scope_mgr=None, mode="target", _transport=_ok_transport()) as c:
        for bad in ("http://169.254.169.254/latest/meta-data/",
                    "http://127.0.0.1/", "http://10.0.0.5/", "http://[::1]/"):
            with pytest.raises(ScopeBlocked):
                c.get(bad)


def test_redirect_hop_to_off_scope_is_blocked(tmp_path):
    scope = _scope(tmp_path, """
        targets:
          domains: ["example.com"]
    """)

    def handler(request):
        if request.url.host == "example.com":
            return httpx.Response(302, headers={"location": "https://evil.com/pwn"})
        return httpx.Response(200, text="should-not-reach")

    with ScopedHTTPClient(scope_mgr=scope, mode="target",
                          _transport=httpx.MockTransport(handler)) as c:
        with pytest.raises(ScopeBlocked):
            c.get("https://example.com/")  # 302 -> evil.com must be refused


def test_external_mode_allowlist(tmp_path):
    with ScopedHTTPClient(mode="external", allow_hosts=["crt.sh"],
                          _transport=_ok_transport()) as c:
        assert c.get("https://crt.sh/?q=x").status_code == 200
        with pytest.raises(ScopeBlocked):
            c.get("https://api.github.com/")


def test_get_capped_truncates_large_body(tmp_path):
    big = "A" * 10000
    transport = httpx.MockTransport(lambda r: httpx.Response(200, text=big))
    with ScopedHTTPClient(mode="external", allow_hosts=["example.com"],
                          _transport=transport) as c:
        resp = c.get_capped("https://example.com/big", max_bytes=1000)
        assert resp.truncated is True
        assert len(resp.content) == 1000
