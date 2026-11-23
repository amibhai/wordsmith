"""Tests for modules/osint.py — focused on scope enforcement over DERIVED
requests (the fan-out that previously bypassed scope/exclude)."""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from modules.state import WordsmithSession

dns_resolver = pytest.importorskip("dns.resolver")


def _scope_file(tmp_path: Path, yaml_text: str) -> Path:
    p = tmp_path / "scope.yaml"
    p.write_text(textwrap.dedent(yaml_text), encoding="utf-8")
    return p


def test_excluded_subdomain_is_never_resolved(tmp_path, monkeypatch):
    """Regression: DNS subdomain enumeration resolved every common name,
    including ones the client explicitly EXCLUDED (e.g. mail.<domain>)."""
    from modules.osint import OSINTCollector

    scope_path = _scope_file(tmp_path, """
        targets:
          domains: ["*.example.com"]
        exclude:
          domains: ["mail.example.com"]
    """)

    resolved: list[str] = []

    def fake_resolve(name, rtype, *args, **kwargs):
        resolved.append(str(name))
        raise dns_resolver.NXDOMAIN()

    monkeypatch.setattr(dns_resolver, "resolve", fake_resolve)

    session = WordsmithSession()
    session.target_domain = "example.com"
    collector = OSINTCollector(session, scope_path)
    collector.collect_dns("example.com")

    assert "mail.example.com" not in resolved, "excluded subdomain was resolved"
    # A non-excluded in-scope subdomain is still enumerated.
    assert "www.example.com" in resolved


def test_is_subdomain_is_dot_anchored():
    from modules.osint import OSINTCollector

    assert OSINTCollector._is_subdomain("api.example.com", "example.com") is True
    assert OSINTCollector._is_subdomain("example.com", "example.com") is True
    # The old `domain in name` substring test wrongly matched these:
    assert OSINTCollector._is_subdomain("example.company.com", "example.com") is False
    assert OSINTCollector._is_subdomain("notexample.com", "example.com") is False
