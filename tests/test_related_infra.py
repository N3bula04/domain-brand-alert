"""Related-infrastructure mapping, replayed from fictional fixtures with the network blocked."""

from osint_collectors.offline import network_blocked

from scanners import collect, related_demo, shared_infra
from scanners.related_infra import FixtureSources, map_related

from conftest import FIXTURES

BRAND = "brand-example.test"
LOOKALIKES = ["brand-examp1e.test", "secure-brand-example.test", "brandexample.test", "brand-exampel.test"]


def _run(lookalikes=LOOKALIKES):
    src = FixtureSources.from_dir(FIXTURES / "related")
    with network_blocked():
        return map_related(BRAND, lookalikes, src), src


def _by_domain(result):
    return {d["domain"]: d for d in result["domains"]}


def test_brand_baseline():
    r, _ = _run()
    b = r["brand"]
    assert b["ips"] == ["192.0.2.10", "203.0.113.5"]
    assert b["ns"] == ["ns1.brand-dns.test", "ns2.brand-dns.test"]
    assert b["mx"] == ["mail.brand-example.test"] and b["registrar"] == "Fixture Registrar"
    assert r["sources_mode"] == "fixtures" and "not proof" in r["sources_note"]


def test_unshared_nameserver_overlap_is_notable():
    d = _by_domain(_run()[0])["brand-examp1e.test"]
    assert [(o["type"], o["value"], o["strength"]) for o in d["overlaps"]] == [
        ("nameserver", "ns1.brand-dns.test", "notable")]
    assert d["shared_flags"] == [] and d["notable_overlaps"] == 1
    a = d["addresses"][0]
    assert a["ptr"] == ["vps7.fictional-host.test"]
    assert a["network"]["holder"] == "Fictional Telecom Pte Ltd" and a["network"]["block"] == "198.51.100.0/24"
    assert d["registrar"] == "Other Registrar" and d["mx"] == ["mx.brand-examp1e.test"]
    assert d["cert_names"] == ["login.brand-examp1e.test"] and d["cert_count"] == 1


def test_shared_cdn_and_registrar_overlaps_are_played_down():
    d = _by_domain(_run()[0])["secure-brand-example.test"]
    kinds = {(o["type"], o["strength"]) for o in d["overlaps"]}
    assert kinds == {("ip", "weak"), ("registrar", "weak")}
    ip = next(o for o in d["overlaps"] if o["type"] == "ip")
    assert ip["value"] == "203.0.113.5" and "www.brand-example.test" in ip["label"]
    assert "FixtureCDN" in ip["shared_reason"]
    assert any("Fixture parking" in f for f in d["shared_flags"])
    assert len(d["addresses"]) == collect.CAP_JOB_IPS_PER_DOMAIN and "only the first 4" in d["notes"][0]
    assert d["notable_overlaps"] == 0


def test_bulk_hosting_ip_weak_but_nameserver_and_certificate_notable():
    d = _by_domain(_run()[0])["brandexample.test"]
    got = {(o["type"], o["value"]): o["strength"] for o in d["overlaps"]}
    assert got[("ip", "192.0.2.10")] == "weak"            # holder "Example Web Hosting Ltd"
    assert got[("nameserver", "ns1.brand-dns.test")] == "notable"
    assert got[("nameserver", "ns2.brand-dns.test")] == "notable"
    assert got[("certificate", "www.brand-example.test")] == "notable"
    assert "sni.cloudflaressl.com" not in d["cert_names"]   # CDN placeholder names dropped


def test_rdap_cap_is_enforced_and_logged():
    r, src = _run()
    assert r["usage"]["rdap_requests"] == collect.CAP_JOB_RDAP_REQUESTS == 10
    assert sum(1 for c in src.calls if c.startswith("rdap")) == 10
    assert any("per-job RDAP cap (10) reached" in e["detail"] for e in r["log"])
    d = _by_domain(r)["brand-exampel.test"]
    assert d["aaaa"] == ["2001:db8::10"] and d["registrar"] is None


def test_crtsh_and_lookalike_caps(monkeypatch):
    monkeypatch.setattr(collect, "CAP_JOB_CRTSH_QUERIES", 2)
    monkeypatch.setattr(collect, "CAP_JOB_LOOKALIKES", 3)
    r, src = _run(LOOKALIKES + ["extra-1.test", "extra-2.test"])
    assert len(r["domains"]) == 3 and r["not_mapped"] == ["brand-exampel.test", "extra-1.test", "extra-2.test"]
    assert sum(1 for c in src.calls if c.startswith("crtsh")) == 2
    assert any(e["source"] == "crt.sh" and "cap (2) reached" in e["detail"] for e in r["log"])


def test_duplicates_and_brand_itself_are_ignored():
    r, _ = _run(["Brand-Example.test", "brand-examp1e.test.", "brand-examp1e.test"])
    assert [d["domain"] for d in r["domains"]] == ["brand-examp1e.test"]


def test_demo_fixtures_tell_the_intended_story():
    looks = ["ame.test", "secure-acme.test", "acme-demo.test"]
    src = FixtureSources(related_demo.build_demo_fixtures("acme.test", looks))
    with network_blocked():
        r = map_related("acme.test", looks, src)
    d = _by_domain(r)
    assert [o["strength"] for o in d["ame.test"]["overlaps"]] == ["notable"]
    assert {o["strength"] for o in d["secure-acme.test"]["overlaps"]} == {"weak"}
    assert d["acme-demo.test"]["overlaps"] == [] and d["acme-demo.test"]["shared_flags"]
    for dom in d.values():
        for a in dom["addresses"]:
            assert a["ip"].startswith(("192.0.2.", "198.51.100.", "203.0.113."))


def test_shared_infra_reference_checks():
    assert shared_infra.cdn_provider("104.16.1.1") == "Cloudflare"
    assert shared_infra.cdn_provider("151.101.1.1") == "Fastly"
    assert shared_infra.cdn_provider("192.0.2.1") is None
    assert shared_infra.cdn_provider("203.0.113.1", {"X": ["203.0.113.0/24"]}) == "X"
    assert shared_infra.cdn_provider("2606:4700::1") == "Cloudflare"
    assert shared_infra.bulk_hosting("Amazon Technologies Inc.") == "amazon"
    assert shared_infra.bulk_hosting("Colombia Movil") is None
    assert shared_infra.dns_provider("ns1.sedoparking.com") == ("parking", "Sedo parking")
    assert shared_infra.dns_provider("ns-1.awsdns-07.co.uk") == ("managed", "Amazon Route 53")
    assert shared_infra.dns_provider("ns1.brand-dns.test") is None
