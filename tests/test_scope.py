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
