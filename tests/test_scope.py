"""Tests for modules/scope.py — authorization/exclusion enforcement.
Covers the exclude-overrides-include bug fixed in this pass."""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from modules.scope import ScopeError, ScopeManager


def _write_scope(tmp_path: Path, yaml_text: str) -> Path:
    p = tmp_path / "scope.yaml"
    p.write_text(textwrap.dedent(yaml_text), encoding="utf-8")
    return p


def test_missing_scope_file_warns_but_does_not_block(tmp_path):
    mgr = ScopeManager(tmp_path / "does-not-exist.yaml")
    assert mgr.loaded is False
    assert mgr.check_scope("anything.example.com") is True


def test_wildcard_domain_match(tmp_path):
    scope_path = _write_scope(tmp_path, """
        targets:
          domains:
            - "*.example.com"
    """)
    mgr = ScopeManager(scope_path)
    assert mgr.check_scope("app.example.com") is True
    assert mgr.check_scope("example.com") is True
    assert mgr.check_scope("evil.com") is False


def test_ip_cidr_match(tmp_path):
    scope_path = _write_scope(tmp_path, """
        targets:
          ip_ranges:
            - "192.168.1.0/24"
    """)
    mgr = ScopeManager(scope_path)
    assert mgr.check_scope("192.168.1.42") is True
    assert mgr.check_scope("10.0.0.1") is False


def test_email_pattern_match(tmp_path):
    scope_path = _write_scope(tmp_path, """
        targets:
          emails:
            - "@example.com"
    """)
    mgr = ScopeManager(scope_path)
    assert mgr.check_scope("someone@example.com") is True
    assert mgr.check_scope("someone@other.com") is False


def test_exclude_domain_overrides_broader_include(tmp_path):
    scope_path = _write_scope(tmp_path, """
        targets:
          domains:
            - "*.example.com"
        exclude:
          domains:
            - "mail.example.com"
    """)
    mgr = ScopeManager(scope_path)
    assert mgr.check_scope("app.example.com") is True
    assert mgr.check_scope("mail.example.com") is False

    with pytest.raises(ScopeError, match="EXCLUDED"):
        mgr.require_scope("mail.example.com")


def test_exclude_ip_range_overrides_broader_include(tmp_path):
    scope_path = _write_scope(tmp_path, """
        targets:
          ip_ranges:
            - "10.0.0.0/8"
        exclude:
          ip_ranges:
            - "10.0.0.200/32"
    """)
    mgr = ScopeManager(scope_path)
    assert mgr.check_scope("10.0.0.1") is True
    assert mgr.check_scope("10.0.0.200") is False


def test_exclude_email_overrides_broader_include(tmp_path):
    scope_path = _write_scope(tmp_path, """
        targets:
          emails:
            - "@example.com"
        exclude:
          emails:
            - "billing@example.com"
    """)
    mgr = ScopeManager(scope_path)
    assert mgr.check_scope("dev@example.com") is True
    assert mgr.check_scope("billing@example.com") is False


def test_expired_engagement_blocks(tmp_path):
    scope_path = _write_scope(tmp_path, """
        engagement:
          expiry_date: "2000-01-01"
        targets:
          domains:
            - "example.com"
    """)
    mgr = ScopeManager(scope_path)
    assert mgr.check_scope("example.com") is False


def test_require_scope_raises_for_out_of_scope_target(tmp_path):
    scope_path = _write_scope(tmp_path, """
        targets:
          domains:
            - "example.com"
    """)
    mgr = ScopeManager(scope_path)
    with pytest.raises(ScopeError):
        mgr.require_scope("evil.com")

    # Should not raise for an in-scope target.
    mgr.require_scope("example.com")


def test_expiry_enforced_for_ip_and_email_not_just_domain(tmp_path):
    """Regression: expiry only gated the domain branch, so an expired
    engagement still authorized every in-scope IP and email target."""
    scope_path = _write_scope(tmp_path, """
        engagement:
          expiry_date: "2000-01-01"
        targets:
          domains:
            - "example.com"
          ip_ranges:
            - "10.0.0.0/8"
          emails:
            - "@example.com"
    """)
    mgr = ScopeManager(scope_path)
    assert mgr.check_scope("example.com") is False
    assert mgr.check_scope("10.0.0.5") is False
    assert mgr.check_scope("dev@example.com") is False


def test_allowed_modules_restriction(tmp_path):
    scope_path = _write_scope(tmp_path, """
        targets:
          domains:
            - "example.com"
        restrictions:
          allowed_modules:
            - osint
            - mutator
    """)
    mgr = ScopeManager(scope_path)
    assert mgr.module_allowed("osint") is True
    assert mgr.module_allowed("scraper") is False
    # No restriction list => everything allowed.
    assert ScopeManager(_write_scope(tmp_path, """
        targets: {domains: ["example.com"]}
    """)).module_allowed("scraper") is True


def test_max_wordlist_mb_clamps_to_restriction(tmp_path):
    scope_path = _write_scope(tmp_path, """
        targets:
          domains:
            - "example.com"
        restrictions:
          max_wordlist_size_mb: 50
    """)
    mgr = ScopeManager(scope_path)
    assert mgr.max_wordlist_mb(100.0) == 50.0   # clamped down
    assert mgr.max_wordlist_mb(10.0) == 10.0    # already under the cap


def test_malformed_scope_is_fail_closed_signal(tmp_path):
    """A file that exists but won't parse must stay UNLOADED with an error
    recorded — that is the signal --auto uses to refuse to run (fail-closed),
    instead of the old silent fail-open."""
    p = tmp_path / "scope.yaml"
    p.write_text("targets: [this: is: not: valid: yaml", encoding="utf-8")
    mgr = ScopeManager(p)
    assert mgr.loaded is False
    assert mgr.load_error and "parse" in mgr.load_error.lower()
