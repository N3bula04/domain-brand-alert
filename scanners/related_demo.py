"""Synthetic fixtures for the related-infrastructure view in demo mode.

Demo watches never touch the network. The real mapper (related_infra.py)
replays these generated fixtures through FixtureSources. All addresses are
in documentation ranges (RFC 5737). The registrar, network, CDN and parking
names are fictional and marked as such.

The data tells a small story so every part of the panel shows something:
  * lookalike 1 shares a nameserver with the brand (not a shared provider),
    so the overlap is notable;
  * lookalike 2 shares the brand's www IP on a fictional CDN range and uses
    the brand's registrar, so both overlaps are played down as shared;
  * the rest sit on a fictional parking service, with no overlaps.
"""

from __future__ import annotations

from typing import Any

DEMO_CDN = {"DemoCDN (fictional)": ["203.0.113.0/25"]}
DEMO_DNS_PROVIDERS = {"parking": {"parking-demo.test": "Demo parking service (fictional)"}}
REGISTRAR = "Example Registrar Ltd (fictional)"
OTHER_REGISTRAR = "Placeholder Names Inc (fictional)"


def _rdap_domain(name: str, registrar: str, *, registered: str = "2026-09-01T00:00:00Z") -> dict[str, Any]:
    return {
        "objectClassName": "domain",
        "ldhName": name,
        "events": [{"eventAction": "registration", "eventDate": registered}],
        "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", registrar]]]}],
    }


def _rdap_ip(ip: str, cidr: str, holder: str, name: str) -> dict[str, Any]:
    pfx, length = cidr.split("/")
    return {
        "objectClassName": "ip network",
        "name": name,
        "startAddress": pfx,
        "cidr0_cidrs": [{"v4prefix": pfx, "length": int(length)}],
        "entities": [{"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", holder]]]}],
    }


def _cert(cid: int, names: list[str]) -> dict[str, Any]:
    return {
        "id": cid,
        "issuer_name": "C=XX, O=Demo CA (fictional), CN=Demo Issuing CA 1",
        "common_name": names[0],
        "name_value": "\n".join(names),
        "not_before": "2026-09-02T00:00:00",
        "not_after": "2026-12-01T00:00:00",
    }


def build_demo_fixtures(brand_domain: str, lookalikes: list[str]) -> dict[str, Any]:
    b = brand_domain.lower().strip(".")
    dns: dict[str, dict] = {}
    rdap: dict[str, dict] = {}
    crtsh: dict[str, list] = {}

    def rec(name: str, rtype: str, answers: list[str]) -> None:
        dns[f"{name}:{rtype}"] = {"status": "ok", "answers": answers}

    # Brand baseline
    rec(b, "A", ["192.0.2.10"])
    rec(f"www.{b}", "A", ["203.0.113.20"])
    rec(b, "NS", ["ns1.brand-dns.test.", "ns2.brand-dns.test."])
    rec(b, "MX", [f"10 mail.{b}."])
    rdap[f"domain:{b}"] = _rdap_domain(b, REGISTRAR)

    rdap["ip:203.0.113.20"] = _rdap_ip("203.0.113.20", "203.0.113.0/25", "DemoCDN Edge (fictional)", "DEMOCDN-EDGE")
    rec("203.0.113.20", "PTR", ["edge-20.democdn.test."])

    for i, dom in enumerate(lookalikes):
        dom = dom.lower().strip(".")
        if i == 0:
            ip = "198.51.100.44"
            rec(dom, "A", [ip])
            rec(dom, "NS", ["ns1.brand-dns.test.", "ns9.other-dns.test."])
            rec(dom, "MX", [f"10 mx.{dom}."])
            rec(ip, "PTR", ["host44.fictional-networks.test."])
            rdap[f"ip:{ip}"] = _rdap_ip(ip, "198.51.100.0/24", "Fictional Networks Pte Ltd", "FICTIONAL-NET")
            rdap[f"domain:{dom}"] = _rdap_domain(dom, OTHER_REGISTRAR)
            crtsh[dom] = [_cert(9001, [dom, f"www.{dom}", f"login.{dom}", f"account-verify.{dom}"])]
        elif i == 1:
            ip = "203.0.113.20"
            rec(dom, "A", [ip])
            rec(dom, "NS", ["ns1.parking-demo.test.", "ns2.parking-demo.test."])
            rdap[f"domain:{dom}"] = _rdap_domain(dom, REGISTRAR, registered="2024-09-01T00:00:00Z")
            crtsh[dom] = [_cert(9002, [dom, f"www.{dom}"])]
        else:
            ip = f"198.51.100.{100 + i}"
            rec(dom, "A", [ip])
            rec(dom, "NS", ["ns1.parking-demo.test.", "ns2.parking-demo.test."])
            rdap[f"ip:{ip}"] = _rdap_ip(ip, "198.51.100.0/24", "Fictional Networks Pte Ltd", "FICTIONAL-NET")
            rdap[f"domain:{dom}"] = _rdap_domain(dom, OTHER_REGISTRAR)

    return {"dns": dns, "rdap": rdap, "crtsh": crtsh, "cdn_ranges": DEMO_CDN,
            "dns_providers": DEMO_DNS_PROVIDERS}
