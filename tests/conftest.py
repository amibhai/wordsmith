"""Shared pytest fixtures — keeps every test isolated from the real
~/.wordsmith directory and outputs/ folder, regardless of how pytest is
invoked (bare `pytest`, `python -m pytest`, from any cwd)."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from modules import audit as audit_mod
from modules import generator as generator_mod
from modules import preflight as preflight_mod
from modules import state as state_mod
from modules.state import WordsmithSession


@pytest.fixture(autouse=True)
def isolated_wordsmith_home(tmp_path, monkeypatch):
    """Redirect every module-level 'well-known directory' constant to a
    per-test tmp_path so tests can never read/write the real ~/.wordsmith
    or outputs/ directories, and never leak state between tests (the HMAC
    key cache in modules/audit.py is keyed by directory path, so a fresh
    tmp_path per test naturally gets a fresh key too)."""
    monkeypatch.setattr(audit_mod, "AUDIT_DIR", tmp_path / "audit")
    monkeypatch.setattr(state_mod, "SESSIONS_DIR", tmp_path / "sessions")
    monkeypatch.setattr(generator_mod, "OUTPUTS_DIR", tmp_path / "outputs")
    monkeypatch.setattr(preflight_mod, "SENTINEL_FILE", tmp_path / "preflight_done")
    yield


@pytest.fixture
def sample_session() -> WordsmithSession:
    s = WordsmithSession()
    s.target_domain = "acme-example.com"
    s.target_name = "Acme"
    s.target_employees = ["Rahul Sharma", "Priya Verma"]
    s.target_products = ["AcmeCloud"]
    s.target_location = "Mumbai"
    s.target_founded_year = "2011"
    s.target_keywords = ["acme", "cloud"]
    return s
