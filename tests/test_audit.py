"""Tests for modules/audit.py — HMAC-chained audit log. Covers the
hardcoded-secret fix (key now generated per-install, not baked into
source) and the tamper-detection guarantee the log is supposed to provide.
"""
from __future__ import annotations

import json

from modules.audit import AuditLogger


def test_sign_and_verify_round_trip():
    logger = AuditLogger("test-session-1")
    logger.log("event.one", foo="bar")
    logger.log("event.two", count=42)
    logger.close(success=True)

    ok, count, msg = AuditLogger.verify("test-session-1")
    assert ok is True
    assert count == 4  # audit.init + event.one + event.two + session.end


def test_tampering_breaks_verification():
    logger = AuditLogger("test-session-2")
    logger.log("event.one", foo="bar")

    # Tamper with the on-disk log after the fact.
    path = logger.path
    lines = path.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[-1])
    entry["data"]["foo"] = "TAMPERED"
    lines[-1] = json.dumps(entry)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok, count, msg = AuditLogger.verify("test-session-2")
    assert ok is False
    assert "tampered" in msg.lower() or "mismatch" in msg.lower()


def test_broken_chain_detected():
    logger = AuditLogger("test-session-3")
    logger.log("event.one")
    logger.log("event.two")

    path = logger.path
    lines = path.read_text(encoding="utf-8").splitlines()
    # Drop the middle entry entirely — breaks the prev_hash chain.
    del lines[1]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok, count, msg = AuditLogger.verify("test-session-3")
    assert ok is False
    assert "chain broken" in msg.lower()


def test_key_file_created_once_and_reused(tmp_path, monkeypatch):
    from modules import audit as audit_mod
    monkeypatch.setattr(audit_mod, "AUDIT_DIR", tmp_path / "audit_reuse")

    AuditLogger("session-a").log("x")
    key_path = tmp_path / "audit_reuse" / ".hmac_key"
    assert key_path.exists()
    first_key = key_path.read_bytes()
    assert len(first_key) == 32

    AuditLogger("session-b").log("y")
    assert key_path.read_bytes() == first_key


def test_verify_missing_log_fails():
    ok, count, msg = AuditLogger.verify("no-such-session-id")
    assert ok is False
    assert count == 0


def test_resume_continues_chain_and_still_verifies():
    """Reopening a session's log (resume / report) must CONTINUE the chain,
    not reset it to genesis. Regression for the bug that made --verify-log
    report tampering on any resumed-or-reported session."""
    first = AuditLogger("resume-session")
    first.log("event.one")
    first.close(success=True)

    # Simulate a second process reopening the same session (fresh instance,
    # bypassing the per-process get_logger memo) — e.g. --resume or --report.
    second = AuditLogger("resume-session")
    second.log("report.generated")
    second.close(success=True)

    ok, count, msg = AuditLogger.verify("resume-session")
    assert ok is True, msg
    # init + event.one + end  +  resume + report.generated + end
    assert count == 6


def test_trailing_truncation_detected():
    """Deleting entries off the END of the log must be caught by the .head
    anchor (a bare forward-chain cannot detect tail truncation)."""
    logger = AuditLogger("truncate-session")
    logger.log("event.one")
    logger.log("event.two")
    logger.close(success=True)

    path = logger.path
    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) >= 2
    # Drop the last two entries; leave the .head anchor intact.
    path.write_text("\n".join(lines[:-2]) + "\n", encoding="utf-8")

    ok, count, msg = AuditLogger.verify("truncate-session")
    assert ok is False
    assert "truncation" in msg.lower()


def test_missing_key_reports_cannot_verify_not_tampering(tmp_path, monkeypatch):
    """A missing signing key must be reported distinctly from tampering, and
    must never cause a fresh key to be minted."""
    from modules import audit as audit_mod

    monkeypatch.setattr(audit_mod, "AUDIT_DIR", tmp_path / "nokey")
    AuditLogger("k-session").close(success=True)

    # Simulate verifying where the key is unavailable (another machine):
    # remove the key file and the in-memory cache.
    (tmp_path / "nokey" / ".hmac_key").unlink()
    audit_mod._key_cache.clear()

    ok, count, msg = AuditLogger.verify("k-session")
    assert ok is False
    assert "cannot verify" in msg.lower()
    assert "tamper" not in msg.lower() or "not" in msg.lower()
    # verify() must not have re-created the key.
    assert not (tmp_path / "nokey" / ".hmac_key").exists()
