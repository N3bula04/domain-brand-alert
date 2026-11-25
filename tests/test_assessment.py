"""Offline checks for analyst assessments and their persisted rollups."""

import pytest

import storage
from scanners.assessment import ASSESSMENT_FIELDS, assess_finding, enrich_findings_with_related
from scanners.demo_data import synthetic_findings
from scanners.related_demo import build_demo_fixtures
from scanners.related_infra import FixtureSources, map_related

BRAND = "Northwind Bakery"
DOMAIN = "northwind-bakery.test"
LURE = "secure-northwind-bakery.test"
TYPO = "nrthwind-bakery.test"


@pytest.mark.parametrize(
    "title_prefix,priority,confidence",
    [
        (f"Lookalike resolves: {LURE}", "high", "medium"),
        (f"Lookalike resolves: {TYPO}", "medium", "low"),
        ("CT: brand-like names outside", "high", "low"),
        ("CT: notable hostnames", "medium", "high"),
        ("CT: 12 cert(s)", "low", "high"),
        ("apex resolves", "low", "high"),
        ("www resolves", "low", "high"),
        ("RDAP registration", "low", "high"),
    ],
)
def test_base_assessment(title_prefix, priority, confidence):
    finding = next(f for f in synthetic_findings(BRAND, DOMAIN) if f["title"].startswith(title_prefix))
    fingerprint = storage._fingerprint(finding)
    assess_finding(finding)
    assert (finding["priority"], finding["confidence"]) == (priority, confidence)
    assert all(finding[field] for field in ASSESSMENT_FIELDS)
    assert storage._fingerprint(finding) == fingerprint
    finding["next_action"] = "Compare the observed names with the inventory."
    original = finding.copy()
    assess_finding(finding)
    assert finding == original


def test_demo_typo_title_uses_variant_hostname():
    findings = synthetic_findings(BRAND, DOMAIN)
    typo = next(f for f in findings if f["target"] == TYPO)
    assert typo["title"] == f"Lookalike resolves: {TYPO}"
    assert all(f["title"] != f"Lookalike resolves: {DOMAIN}" for f in findings)


def test_related_fixture_assessments():
    fixtures = FixtureSources(build_demo_fixtures(DOMAIN, [LURE, TYPO]))
    mapped = map_related(DOMAIN, [LURE, TYPO], fixtures)
    findings = synthetic_findings(BRAND, DOMAIN)
    enrich_findings_with_related(findings, mapped)
    by_target = {f["target"]: f for f in findings}
    lure, typo = by_target[LURE], by_target[TYPO]
    assert (lure["priority"], lure["confidence"]) == ("high", "medium")
    assert "ns1.brand-dns.test" in lure["trigger"]
    assert f"login.{LURE}" in lure["trigger"]
    assert f"account-verify.{LURE}" in lure["trigger"]
    assert (typo["priority"], typo["confidence"], typo["severity"]) == ("medium", "low", "warn")
    assert "parking nameservers" in typo["trigger"]
    assert "no evidence of affiliation" in typo["what_would_change"]
    assert "Log and monitor" in typo["next_action"]
    original = [f.copy() for f in findings]
    enrich_findings_with_related(findings, mapped)
    assert findings == original


def test_recent_registration_raises_priority_without_raising_confidence():
    typo = next(f for f in synthetic_findings(BRAND, DOMAIN) if f["target"] == TYPO)
    mapped = {
        "finished_at": "2026-11-24T00:00:00Z",
        "domains": [{"domain": TYPO, "registered_at": "2026-09-01T00:00:00Z", "has_current_certificate": True}],
    }
    enrich_findings_with_related([typo], mapped)
    assert (typo["priority"], typo["confidence"], typo["severity"]) == ("high", "low", "high")


def test_live_related_job_updates_storage_and_matching_export(monkeypatch):
    import app

    storage.init_db()
    watch = storage.add_watch(BRAND, DOMAIN, mode="live")
    finding = next(f for f in synthetic_findings(BRAND, DOMAIN) if f["target"] == TYPO)
    finding["raw"].pop("demo")
    assess_finding(finding)
    result = {"mode": "live", "findings": [finding]}
    scan_id = storage.save_scan_result(watch["id"], result)["scan_id"]
    monkeypatch.setattr(app, "_LAST_SCAN", {**result, "scan_id": scan_id})
    fixtures = FixtureSources(build_demo_fixtures(DOMAIN, [TYPO]))
    monkeypatch.setattr(app, "LiveSources", lambda: fixtures)
    job = storage.create_related_job(watch["id"], scan_id, "live", "manual")
    app._run_related_job(job["id"], watch["id"])

    assert storage.get_related_job(job["id"])["status"] == "done"
    scan = storage.get_latest_scan(watch["id"])
    assert scan["counts"]["high"] == 1
    assert scan["result"]["findings"][0]["priority"] == "high"
    stored, = storage.get_scan_findings(scan_id)
    assert stored["severity"] == "high" and stored["confidence"] == "medium"
    assert stored["is_new"]
    assert app._LAST_SCAN["findings"][0]["priority"] == "high"
    digest = storage.digest_new_findings(watch["id"])
    assert digest["watches"][0]["findings"][0]["confidence"] == "medium"
    rescan = storage.save_scan_result(watch["id"], result)
    assert rescan["new_count"] == 0
