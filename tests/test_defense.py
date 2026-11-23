"""Tests for modules/defense.py — the defensive (blue-team) flagship:
org banned-list + exposure report, derived from the same OSINT context."""
from __future__ import annotations

from modules.defense import DefenseAnalyzer
from modules.state import WordsmithSession


def _session() -> WordsmithSession:
    s = WordsmithSession()
    s.target_domain = "acme-example.com"
    s.target_name = "Acme"
    s.target_employees = ["Rahul Sharma", "Priya Verma"]
    s.target_products = ["AcmeCloud"]
    s.target_location = "Mumbai"
    s.target_founded_year = "2011"
    s.target_keywords = ["acme", "cloud"]
    return s


def test_build_stems_has_provenance_and_dedups():
    stems = DefenseAnalyzer(_session()).build_stems()
    by_term = {term: src for term, src in stems}
    assert by_term.get("acme") == "org name"          # org name wins over keyword
    assert "acmecloud" in by_term                     # product
    assert by_term.get("mumbai") == "location (WHOIS)"
    assert by_term.get("rahul") == "employee name"
    assert by_term.get("sharma") == "employee name"
    # deduplicated
    assert len(by_term) == len(stems)


def test_entra_terms_respect_length_limits():
    analyzer = DefenseAnalyzer(_session())
    terms = analyzer._entra_terms(analyzer.build_stems())
    assert all(4 <= len(t) <= 16 for t in terms)
    assert "acme" in terms
    # "cloud" (5) kept; a 3-char stem would be excluded by Entra's 4-char floor.
    assert len(terms) == len(set(terms))


def test_candidate_passwords_are_org_specific():
    cands = DefenseAnalyzer(_session()).candidate_passwords(limit=2000)
    assert cands, "expected some candidate passwords"
    low = [c.lower() for c in cands]
    assert any("acme" in c for c in low)


def test_exposure_metrics_are_grounded():
    analyzer = DefenseAnalyzer(_session())
    cands = analyzer.candidate_passwords(limit=2000)
    m = analyzer.exposure(cands)
    assert m["total_candidates"] == len(cands)
    assert 0 <= m["trivially_weak"] <= m["total_candidates"]
    labels = {b["pattern"] for b in m["pattern_breakdown"]}
    assert any("year" in lbl for lbl in labels)
    # percentages are sane
    for b in m["pattern_breakdown"]:
        assert 0.0 <= b["pct"] <= 100.0


def test_export_writes_banned_lists_and_report(tmp_path):
    paths = DefenseAnalyzer(_session()).export(
        tmp_path, "acme-example.com", "20260101_000000", formats=["all"]
    )
    for key in ("entra", "keycloak", "pwquality", "report_json", "report_md"):
        assert key in paths, f"missing output: {key}"
        assert (tmp_path / __import__("pathlib").Path(paths[key]).name).exists()

    md = (tmp_path / __import__("pathlib").Path(paths["report_md"]).name).read_text(encoding="utf-8")
    assert "Exposure" in md
    assert "estimates over" in md  # the honesty disclaimer about the figures
    entra = (tmp_path / __import__("pathlib").Path(paths["entra"]).name).read_text(encoding="utf-8")
    assert "acme" in entra.split()


def test_ad_format_aliases_to_entra(tmp_path):
    paths = DefenseAnalyzer(_session()).export(
        tmp_path, "t", "20260101_000000", formats=["ad"]
    )
    assert "entra" in paths
    assert "keycloak" not in paths  # only the requested (aliased) format written
