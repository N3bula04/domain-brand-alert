"""The three scanners on top of osint-collectors keep their v0.3 return shapes."""

import pytest
from osint_collectors.dns import set_resolver_factory
from osint_collectors.offline import FixtureResolver

from scanners import ct_check, dns_check, rdap_check

FINDING_KEYS = {"severity", "source", "title", "detail", "target", "timestamp", "why_it_matters", "raw"}


@pytest.fixture
def fixture_dns():
    records = {
        "brand-example.test:A": {"status": "ok", "answers": ["192.0.2.10"]},
        "www.brand-example.test:CNAME": {"status": "ok", "answers": ["brand-example.test."]},
        "brand-examp1e.test:A": {"status": "ok", "answers": ["198.51.100.7"]},
        "secure-brand-example.test:A": {"status": "ok", "answers": ["198.51.100.8"]},
    }
    r = FixtureResolver(records)
    set_resolver_factory(lambda ns, t: r)
    yield r
    set_resolver_factory(None)


def test_resolve_host_shape_and_nxdomain_shortcut(fixture_dns):
    out = dns_check.resolve_host("brand-example.test")
    assert out == {"hostname": "brand-example.test", "resolves": True,
                   "records": {"A": ["192.0.2.10"], "AAAA": [], "CNAME": []}, "errors": []}
    fixture_dns.queries.clear()
    gone = dns_check.resolve_host("nothing-here.test")
    assert gone["resolves"] is False and gone["errors"] == []
    assert fixture_dns.queries == ["nothing-here.test:a"]  # NXDOMAIN on A: AAAA/CNAME not asked


def test_primary_dns_titles_unchanged(fixture_dns):
    f = dns_check.check_primary_dns("brand-example.test")
    assert [x["title"] for x in f] == ["apex resolves (brand-example.test)", "www resolves (www.brand-example.test)"]
    assert all(set(x) == FINDING_KEYS for x in f)
    assert "brand-example.test." in f[1]["detail"]


def test_lookalike_dns_finds_resolving_candidates(fixture_dns):
    f = dns_check.check_lookalike_dns("brand-example.test", brand="brand-example", limit=200)
    targets = {x["target"] for x in f}
    assert {"brand-examp1e.test", "secure-brand-example.test"} <= targets
    for x in f:
        assert x["source"] == "DNS lookalike" and x["title"] == f"Lookalike resolves: {x['target']}"
        assert x["severity"] in ("high", "warn") and "generation_reason" in x["raw"]


def test_dns_answers_are_cached(fixture_dns):
    dns_check.resolve_host("brand-example.test")
    fixture_dns.queries.clear()
    dns_check.resolve_host("brand-example.test")
    assert fixture_dns.queries == []


CERTS = [
    {"id": 1, "issuer_name": "CN=Fixture CA", "common_name": "brand-example.test",
     "name_value": "brand-example.test\n*.brand-example.test\nadmin.brand-example.test",
     "not_before": "2026-01-01", "not_after": "2026-12-01"},
    {"id": 2, "issuer_name": "CN=Fixture CA", "common_name": "brandexample-login.test",
     "name_value": "brandexample-login.test", "not_before": "2026-01-01", "not_after": "2026-12-01"},
]


@pytest.mark.localhttp
def test_ct_findings_from_fake_crtsh(fake_server, monkeypatch):
    srv = fake_server(lambda path, n: (200, {}, CERTS))
    monkeypatch.setattr(ct_check, "CRT_SH", srv.url)
    f = ct_check.check_certificate_transparency("brand-example.test", brand="BrandExample")
    titles = [x["title"] for x in f]
    assert "CT: 2 cert(s) for brand-example.test" not in titles  # cert 2 is not under the domain
    assert "CT: 1 cert(s) for brand-example.test" in titles
    assert "CT: notable hostnames in certificates" in titles
    assert "CT: brand-like names outside brand-example.test" in titles
    assert all(set(x) == FINDING_KEYS for x in f)
    assert len(srv.requests) == 3  # %.domain, domain, %brand%
    # Second scan inside the cache TTL: no new requests.
    ct_check.check_certificate_transparency("brand-example.test", brand="BrandExample")
    assert len(srv.requests) == 3


@pytest.mark.localhttp
def test_ct_429_backs_off_and_next_scan_skips(fake_server, monkeypatch):
    srv = fake_server(lambda path, n: (429, {"Retry-After": "300"}, ""))
    monkeypatch.setattr(ct_check, "CRT_SH", srv.url)
    f = ct_check.check_certificate_transparency("brand-example.test", brand="")
    assert [x["title"] for x in f] == ["CT lookup unavailable"]
    assert "HTTP 429" in f[0]["detail"] and "backing off until" in f[0]["detail"]
    assert len(srv.requests) == 1  # never retried; the second query is skipped by the back-off
    f2 = ct_check.check_certificate_transparency("brand-example.test", brand="")
    assert len(srv.requests) == 1 and "skipped" in f2[0]["detail"]


@pytest.mark.localhttp
def test_ct_timeout_not_cached(fake_server, monkeypatch):
    import time

    def slow(path, n):
        if n <= 2:
            time.sleep(0.6)
        return 200, {}, CERTS
    srv = fake_server(slow)
    monkeypatch.setattr(ct_check, "CRT_SH", srv.url)
    entries, err = ct_check._fetch_certs("brand-example.test", timeout=0.2)
    assert entries == [] and err == "crt.sh timed out (common under load)"
    entries, err = ct_check._fetch_certs("brand-example.test", timeout=5)
    assert err is None and len(entries) == 2


RDAP_DOMAIN = {
    "ldhName": "brand-example.test", "status": ["active"],
    "events": [{"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"}],
    "nameservers": [{"ldhName": "ns1.brand-dns.test"}],
    "entities": [{"roles": ["registrar"], "handle": "1", "vcardArray": ["vcard", [["fn", {}, "text", "Fixture Registrar"]]]}],
}


@pytest.mark.localhttp
def test_rdap_registration_finding(fake_server, monkeypatch):
    srv = fake_server(lambda path, n: (200, {}, RDAP_DOMAIN))
    monkeypatch.setattr(rdap_check, "REDIRECTOR", srv.url)
    f = rdap_check.check_registration("brand-example.test")
    assert f[0]["title"] == "RDAP registration for brand-example.test" and f[0]["source"] == "RDAP"
    assert "Registered: 2020-01-01T00:00:00Z" in f[0]["detail"] and "NS: ns1.brand-dns.test" in f[0]["detail"]
    assert f[0]["raw"]["entities"][0]["name"] == "Fixture Registrar"
    assert srv.requests == ["/domain/brand-example.test"]


@pytest.mark.localhttp
def test_rdap_429_records_backoff_then_skips(fake_server, monkeypatch):
    srv = fake_server(lambda path, n: (429, {"Retry-After": "120"}, ""))
    monkeypatch.setattr(rdap_check, "REDIRECTOR", srv.url)
    monkeypatch.setattr(rdap_check, "python_whois", None)
    data, err = rdap_check.rdap_lookup("brand-example.test")
    assert data is None and err.startswith("RDAP rate-limited") and "backing off until" in err
    data, err = rdap_check.rdap_lookup("brand-example.test")
    assert err.startswith("RDAP skipped") and len(srv.requests) == 1
    f = rdap_check.check_registration("brand-example.test")
    assert f[0]["title"] == "Registration lookup skipped/unavailable for brand-example.test"


@pytest.mark.localhttp
def test_rdap_falls_back_to_bootstrap(fake_server, monkeypatch):
    auth = fake_server(lambda path, n: (200, {}, RDAP_DOMAIN))
    boot = {"services": [[["test"], [auth.url]]]}
    red = fake_server(lambda path, n: (200, {}, boot) if path == "/dns.json" else (503, {}, ""))
    monkeypatch.setattr(rdap_check, "REDIRECTOR", red.url)
    monkeypatch.setattr(rdap_check, "BOOTSTRAP_URLS", {"domain": red.url + "dns.json"})
    data, err = rdap_check.rdap_lookup("brand-example.test")
    assert err is None and data["ldhName"] == "brand-example.test"
