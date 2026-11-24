"""FastAPI routes: demo watches, background related-infrastructure job, storage, panel markup."""

import time

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    import app as app_module
    with TestClient(app_module.app) as c:
        yield c


def _wait_done(client, wid, timeout=10.0):
    end = time.time() + timeout
    while time.time() < end:
        data = client.get(f"/api/watches/{wid}/related").json()
        job = data["job"]
        if job and job["status"] not in ("queued", "running"):
            return data
        time.sleep(0.1)
    raise AssertionError("related job did not finish")


def test_health_and_pages(client):
    assert client.get("/api/health").json()["version"] == "0.5.0"
    html = client.get("/app").text
    assert 'id="detail-related"' in html
    assert "renderRelated" in client.get("/static/app.js").text


def test_demo_watch_scan_and_auto_related_job(client):
    r = client.post("/api/watches", json={"brand": "Acme", "domain": "acme-demo.test", "mode": "demo"})
    assert r.status_code == 200
    body = r.json()
    wid = body["watch"]["id"]
    assert body["result"]["counts"]["total"] == 8
    from scanners.assessment import ASSESSMENT_FIELDS

    findings = body["result"]["findings"]
    assert all(all(finding[field] for field in ASSESSMENT_FIELDS) for finding in findings)
    lookalikes = [f for f in findings if f["source"] == "DNS lookalike"]
    assert [(f["priority"], f["confidence"]) for f in lookalikes] == [
        ("high", "medium"), ("medium", "low"),
    ]
    data = _wait_done(client, wid)
    job = data["job"]
    assert job["status"] == "done" and job["mode"] == "demo" and job["trigger"] == "auto"
    res = job["result"]
    assert res["mode"] == "demo" and "synthetic" in res["demo_note"]
    assert len(res["domains"]) == 2 and res["brand"]["domain"] == "acme-demo.test"
    assert data["last_done"]["id"] == job["id"]


def test_manual_related_and_dedup(client):
    wid = client.post("/api/watches", json={"brand": "Acme", "domain": "acme-demo.test", "mode": "demo",
                                            "scan_now": False}).json()["watch"]["id"]
    assert client.post(f"/api/watches/{wid}/related").status_code == 409  # no scan yet
    client.post(f"/api/watches/{wid}/scan")
    _wait_done(client, wid)
    r = client.post(f"/api/watches/{wid}/related")
    assert r.status_code == 202 and r.json()["job"]["trigger"] == "manual"
    done = _wait_done(client, wid)
    assert done["job"]["status"] == "done"
    assert client.get("/api/watches/999/related").status_code == 404


def test_rescan_within_window_does_not_requeue(client):
    wid = client.post("/api/watches", json={"brand": "Acme", "domain": "acme-demo.test", "mode": "demo"}).json()["watch"]["id"]
    first = _wait_done(client, wid)["job"]["id"]
    client.post(f"/api/watches/{wid}/scan")
    time.sleep(0.3)
    assert client.get(f"/api/watches/{wid}/related").json()["job"]["id"] == first


def test_evidence_pack_carries_related_result(client):
    import io
    import json
    import zipfile
    wid = client.post("/api/watches", json={"brand": "Acme", "domain": "acme-demo.test", "mode": "demo"}).json()["watch"]["id"]
    _wait_done(client, wid)
    z = zipfile.ZipFile(io.BytesIO(client.get(f"/api/watches/{wid}/evidence-pack").content))
    meta = json.loads(next(z.read(n) for n in z.namelist() if n.endswith("metadata.json")))
    assert meta["version"] == "0.5.0"
    assert meta["related_infrastructure"]["status"] == "done"
    from scanners.assessment import ASSESSMENT_FIELDS

    for name in ("high_findings.csv", "all_findings.csv"):
        csv_data = next(z.read(n).decode() for n in z.namelist() if n.endswith(name))
        assert set(ASSESSMENT_FIELDS) <= set(csv_data.splitlines()[0].split(","))


def test_lookalike_targets_never_maps_synthetic_findings_live():
    import app as app_module
    demo = {"mode": "auto+demo", "findings": [
        {"source": "DNS lookalike", "target": "fake.test", "severity": "high", "raw": {"demo": True}}]}
    assert app_module._lookalike_targets(demo) == (["fake.test"], "demo")
    mixed = {"mode": "auto+demo", "findings": [
        {"source": "DNS lookalike", "target": "fake.test", "severity": "high", "raw": {"demo": True}},
        {"source": "DNS lookalike", "target": "real.test", "severity": "warn", "raw": {}},
        {"source": "DNS lookalike", "target": "allowed.test", "severity": "high", "raw": {}, "suppressed": True}]}
    assert app_module._lookalike_targets(mixed) == (["real.test"], "live")


def test_interrupted_jobs_marked_on_startup(tmp_path):
    import storage
    storage.init_db()
    w = storage.add_watch("Acme", "acme-demo.test", mode="demo")
    job = storage.create_related_job(w["id"], None, "demo", "manual")
    storage.init_db()
    assert storage.get_related_job(job["id"])["status"] == "interrupted"
