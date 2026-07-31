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
