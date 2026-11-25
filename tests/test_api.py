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
    assert client.get("/api/health").json()["version"] == "0.5.1"
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
    assert meta["version"] == "0.5.1"
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


def _mock_webhook_dns(monkeypatch, answers):
    import socket

    def resolve(host, port, *, type):
        assert type == socket.SOCK_STREAM
        return [
            (socket.AF_INET6 if ":" in ip else socket.AF_INET, type, 0, "", (ip, port))
            for ip in answers[host]
        ]

    monkeypatch.setattr(socket, "getaddrinfo", resolve)


@pytest.mark.parametrize(("url", "answers"), [
    ("http://hook.test", {}),
    ("file:///tmp/webhook", {}),
    ("https://hook.test:65536", {}),
    ("https://127.0.0.1", {"127.0.0.1": ["127.0.0.1"]}),
    ("https://10.0.0.1", {"10.0.0.1": ["10.0.0.1"]}),
    ("https://169.254.169.254", {"169.254.169.254": ["169.254.169.254"]}),
    ("https://[::ffff:169.254.169.254]", {"::ffff:169.254.169.254": ["::ffff:a9fe:a9fe"]}),
    ("https://[fd00:ec2::254]", {"fd00:ec2::254": ["fd00:ec2::254"]}),
    ("https://hook.test", {"hook.test": ["8.8.8.8", "192.168.1.10"]}),
    ("https://hook.test", {"hook.test": ["fe80::1"]}),
    ("https://hook.test", {"hook.test": ["ff02::1"]}),
    ("https://hook.test", {"hook.test": ["::"]}),
    ("https://hook.test", {"hook.test": ["240.0.0.1"]}),
])
def test_reject_invalid_webhook_on_create_and_update(client, monkeypatch, url, answers):
    _mock_webhook_dns(monkeypatch, answers)
    body = {"brand": "Acme", "domain": "acme.test", "scan_now": False}
    assert client.post("/api/watches", json={**body, "webhook_url": url}).status_code == 422
    assert client.get("/api/watches").json()["watches"] == []

    watch = client.post("/api/watches", json=body).json()["watch"]
    path = f"/api/watches/{watch['id']}"
    response = client.patch(path, json={"webhook_url": url, "paused": True})
    assert response.status_code == 422
    stored = client.get(path).json()["watch"]
    assert stored["webhook_url"] is None and stored["paused"] is False


@pytest.mark.parametrize("disabled", ["", None])
def test_webhook_delivery_and_disable(client, monkeypatch, caplog, disabled):
    import httpx
    import app as app_module

    answers = {"hook.test": ["8.8.8.8", "2606:4700:4700::1111"]}
    _mock_webhook_dns(monkeypatch, answers)
    secret = "private-webhook-token"
    url = f"https://hook.test:8443/notify?token={secret}"
    body = {"brand": "Acme", "domain": "acme.test", "scan_now": False, "webhook_url": url}
    response = client.post("/api/watches", json=body)
    assert response.status_code == 200
    watch = response.json()["watch"]
    assert watch["webhook_url"] == url

    requests = []

    def receive(request):
        requests.append(request)
        return httpx.Response(302, headers={"Location": "https://other.test"})

    real_client = httpx.Client

    def webhook_client(**kwargs):
        assert kwargs["follow_redirects"] is False
        assert kwargs["trust_env"] is False
        return real_client(transport=httpx.MockTransport(receive), **kwargs)

    monkeypatch.setattr(httpx, "Client", webhook_client)
    caplog.set_level("DEBUG")
    meta = {"new_findings": [{"title": "New finding"}]}
    assert app_module._post_webhook(watch, meta) == {"ok": False, "status_code": 302}
    assert len(requests) == 1
    assert str(requests[0].url) == f"https://8.8.8.8:8443/notify?token={secret}"
    assert requests[0].headers["Host"] == "hook.test:8443"
    assert requests[0].extensions["sni_hostname"] == "hook.test"

    answers["hook.test"] = ["10.0.0.1"]
    assert app_module._post_webhook(watch, meta) == {"ok": False, "error": "ValueError"}
    assert len(requests) == 1
    assert secret not in caplog.text and url not in caplog.text
    assert f"watch {watch['id']} returned HTTP 302" in caplog.text

    path = f"/api/watches/{watch['id']}"
    assert client.patch(path, json={"webhook_url": disabled}).json()["watch"]["webhook_url"] is None


def test_get_scan_cannot_run_a_scan(client, monkeypatch):
    import app as app_module

    def unexpected_scan(*args, **kwargs):
        pytest.fail("GET /api/scan ran a scan")

    monkeypatch.setattr(app_module, "_one_off_scan", unexpected_scan)
    assert client.get("/api/scan?brand=Acme&domain=acme.test&mode=demo").status_code in (404, 405)


def test_viewed_state_requires_post(client, monkeypatch):
    from datetime import datetime, timezone
    import storage

    body = {"brand": "Acme", "domain": "acme.test", "scan_now": False}
    first, second = [
        client.post("/api/watches", json={**body, "domain": domain}).json()["watch"]["id"]
        for domain in ("first.test", "second.test")
    ]
    first_path = f"/api/watches/{first}"
    assert client.get(f"{first_path}?mark_viewed=true").status_code == 200
    assert client.get("/api/digest?mark_viewed=true").status_code == 200
    assert all(storage.get_watch(wid)["last_viewed_at"] is None for wid in (first, second))

    first_view = datetime(2026, 11, 26, 1, tzinfo=timezone.utc).isoformat()
    monkeypatch.setattr(storage, "_now", lambda: first_view)
    assert client.post(f"{first_path}/viewed").json()["watch"]["last_viewed_at"] == first_view
    assert storage.get_watch(second)["last_viewed_at"] is None

    all_view = datetime(2026, 11, 26, 2, tzinfo=timezone.utc).isoformat()
    monkeypatch.setattr(storage, "_now", lambda: all_view)
    digest = client.post("/api/digest/viewed")
    assert digest.status_code == 200
    assert {w["watch_id"]: w["last_viewed_at"] for w in digest.json()["watches"]} == {
        first: all_view, second: all_view,
    }


@pytest.mark.parametrize(("value", "expected"), [
    ("=1", "'=1"),
    ("  +1", "'  +1"),
    ("\u2003-1", "'\u2003-1"),
    ("\x00\n@name", "'\x00\n@name"),
    (" \ttext", "' \ttext"),
    ("\rtext", "'\rtext"),
    ("text\t=1", "text\t=1"),
    ("  ", "  "),
    ("'=1", "'=1"),
    (17, 17),
    (None, None),
])
def test_sanitize_csv_cell(value, expected):
    from app import sanitize_csv_cell

    assert sanitize_csv_cell(value) == expected


def test_export_filenames_and_csv_cells(client, monkeypatch):
    import csv
    import io
    import re
    import zipfile
    import app as app_module

    unsafe = 'A9/é\\_"\r\n' + "a" * 130
    assert app_module._filename_slug(unsafe, max_length=9) == "A9_______"
    assert len(app_module._filename_slug(unsafe)) == 120
    finding = {"title": " \t=1", "severity": "high"}
    monkeypatch.setattr(app_module, "_LAST_SCAN", {"domain": unsafe, "findings": [finding]})
    json_export = client.get("/api/export/json")
    csv_export = client.get("/api/export/csv")
    for extension, response in (("json", json_export), ("csv", csv_export)):
        assert re.fullmatch(rf"attachment; filename=brand_alert_[A-Za-z0-9_]{{1,120}}\.{extension}",
                            response.headers["Content-Disposition"])
    assert json_export.json()["findings"][0]["title"] == finding["title"]
    assert next(csv.DictReader(io.StringIO(csv_export.text)))["title"] == "'" + finding["title"]

    pack = {
        "watch": {"brand": unsafe, "domain": unsafe},
        "high_findings": [finding],
        "all_findings": [finding],
        "scan_history": [{"mode": "\r=1"}],
        "exported_at": "2026-11-26",
        "version": "0.5.1",
        "disclaimer": "",
    }
    monkeypatch.setattr(app_module.storage, "evidence_pack_data", lambda _: pack)
    response = client.get("/api/watches/1/evidence-pack")
    match = re.fullmatch(r"attachment; filename=(evidence_[A-Za-z0-9_]{1,40}_[A-Za-z0-9_]{1,120})\.zip",
                         response.headers["Content-Disposition"])
    assert match
    base = match[1]
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        assert len(archive.namelist()) == 5
        assert all(re.fullmatch(rf"{base}/[A-Za-z0-9_]+\.(csv|json|txt)", name)
                   for name in archive.namelist())
        for name, field, value in (
            ("high_findings", "title", "' \t=1"),
            ("all_findings", "title", "' \t=1"),
            ("scan_history", "mode", "'\r=1"),
        ):
            data = archive.read(f"{base}/{name}.csv").decode()
            assert next(csv.DictReader(io.StringIO(data)))[field] == value


def test_sample_csv_quotes_carriage_returns(tmp_path, monkeypatch):
    import csv
    import json
    import sys
    import sample_run

    title = "\r=1"
    monkeypatch.setattr(sample_run, "OUT", tmp_path)
    monkeypatch.setattr(sample_run, "run_scan", lambda *args, **kwargs: {"findings": [{"title": title}]})
    monkeypatch.setattr(sys, "argv", ["sample_run.py"])
    sample_run.main()
    with (tmp_path / "last_scan.csv").open(newline="", encoding="utf-8") as handle:
        assert [row["title"] for row in csv.DictReader(handle)] == ["'" + title]
    assert json.loads((tmp_path / "last_scan.json").read_text())["findings"][0]["title"] == title
