"""Related infrastructure for lookalike domains (public data only).

For each lookalike (capped), this collects:
  * A / AAAA, NS and MX records, plus reverse DNS for its addresses,
    all through the recursive resolver;
  * the RDAP network holder for its addresses and the RDAP registrar for
    the domain;
  * other names on the same certificates, from crt.sh.

It then compares each lookalike with the brand's own domain and reports
overlaps: same IP address, same nameserver, same registrar, or a
certificate that also names a brand host. When the shared thing is a CDN,
bulk-hosting netblock, managed DNS service or parking service, the overlap
is flagged as "shared" and played down, because thousands of unrelated
sites share those.

Nothing here connects to the lookalike's web or mail servers. Every
lookup goes to a DNS resolver, crt.sh or an RDAP registry. An overlap is a
lead to check, not proof that the same people run both domains.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

import dns.reversename
from osint_collectors.cache import Cache
from osint_collectors.ct import crtsh_fetch, is_cdn_placeholder, parse_ct_entries
from osint_collectors.dns import dns_query
from osint_collectors.offline import FixtureResolver
from osint_collectors.psl import host_in_domain, registrable_domain
from osint_collectors.rdap import entities_by_role, ip_block, vcard

from scanners import collect, shared_infra

SOURCES_NOTE = (
    "Public data only: DNS via your recursive resolver, certificate transparency via crt.sh, "
    "registration and network data via RDAP. No connections are made to the lookalike's own "
    "web or mail servers. An overlap is a lead to verify, not proof of common ownership."
)
MAX_CERT_NAMES = 25


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Data sources: live (osint-collectors + caches) or fixtures (demo / tests)
# ---------------------------------------------------------------------------

class LiveSources:
    """Real lookups through osint-collectors, using data/cache/ and the shared throttle."""

    mode = "live"

    def __init__(self) -> None:
        self._resolver = collect.resolver(1.0)

    def dns(self, name: str, rtype: str) -> tuple[str, list[str], str]:
        return dns_query(self._resolver, collect.cache("dns"), name, rtype)

    def needs_network(self, service: str, key: str) -> bool:
        """False if the answer is already cached (cached answers don't count against caps)."""
        ns = {"crtsh": "crtsh", "rdap": "rdap"}[service]
        return collect.cache(ns).get(ns, key) is None

    def crtsh(self, query: str) -> tuple[str, list, str]:
        return crtsh_fetch(collect.cache("crtsh"), query, timeout=25.0, client=collect.client(), attempts=2)

    def rdap(self, kind: str, target: str) -> tuple[dict | None, str | None]:
        from scanners.rdap_check import rdap_get
        return rdap_get(kind, target)


class FixtureSources:
    """Answers from in-memory fixtures. Never touches the network.

    fixtures = {"dns": {"name:RTYPE": {...}}, "crtsh": {"query": [entries]},
                "rdap": {"domain:example.test": {...}, "ip:192.0.2.1": {...}},
                "cdn_ranges": {"Name": ["cidr", ...]},                 # optional, fictional
                "dns_providers": {"parking": {dom: label}, "managed": {...}}}  # optional
    Every lookup counts against the caps, so cap behaviour is testable.
    """

    mode = "fixtures"

    def __init__(self, fixtures: dict[str, Any]):
        self.fixtures = fixtures
        self._resolver = FixtureResolver(fixtures.get("dns", {}))
        self._nocache = Cache(Path("."), enabled=False)
        self.extra_cdn = fixtures.get("cdn_ranges") or {}
        self.extra_dns = fixtures.get("dns_providers") or {}
        self.calls: list[str] = []

    @classmethod
    def from_dir(cls, path: Path) -> "FixtureSources":
        path = Path(path)
        fx: dict[str, Any] = {}
        for key in ("dns", "crtsh", "rdap", "cdn_ranges", "dns_providers"):
            f = path / f"{key}.json"
            fx[key] = json.loads(f.read_text(encoding="utf-8")) if f.exists() else {}
        return cls(fx)

    def dns(self, name: str, rtype: str) -> tuple[str, list[str], str]:
        self.calls.append(f"dns {name} {rtype}")
        return dns_query(self._resolver, self._nocache, name, rtype)

    def needs_network(self, service: str, key: str) -> bool:
        return True

    def crtsh(self, query: str) -> tuple[str, list, str]:
        self.calls.append(f"crtsh {query}")
        entries = self.fixtures.get("crtsh", {}).get(query)
        if entries is None:
            return "empty", [], "no certificates found"
        return ("ok" if entries else "empty"), entries, f"{len(entries)} certificate entries (fixture)"

    def rdap(self, kind: str, target: str) -> tuple[dict | None, str | None]:
        self.calls.append(f"rdap {kind} {target}")
        data = self.fixtures.get("rdap", {}).get(f"{kind}:{target}")
        if data is None:
            return None, "RDAP: domain not found" if kind == "domain" else "RDAP: no record"
        return data, None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _clean(host: str) -> str:
    return host.strip().lower().rstrip(".")


def _mx_hosts(answers: Iterable[str]) -> list[str]:
    out = []
    for a in answers:
        parts = a.split()
        host = _clean(parts[-1]) if parts else ""
        if host:
            out.append(host)
    return sorted(set(out))


def registrar_name(rdap_domain: dict | None) -> str | None:
    if not rdap_domain:
        return None
    for ent in entities_by_role(rdap_domain).get("registrar", []):
        name = vcard(ent).get("fn") or vcard(ent).get("org")
        if name:
            return name.strip()
    return None


def network_summary(rdap_ip: dict | None) -> dict[str, str]:
    if not rdap_ip:
        return {}
    roles = entities_by_role(rdap_ip)
    holder = ""
    for role in ("registrant", "administrative", "technical"):
        for ent in roles.get(role, []):
            vc = vcard(ent)
            holder = vc.get("org") or vc.get("fn") or ""
            if holder:
                break
        if holder:
            break
    return {
        "holder": holder or str(rdap_ip.get("name") or ""),
        "name": str(rdap_ip.get("name") or ""),
        "block": ip_block(rdap_ip),
        "country": str(rdap_ip.get("country") or ""),
    }


class _Budget:
    def __init__(self, name: str, limit: int):
        self.name, self.limit, self.used = name, limit, 0

    def take(self) -> bool:
        if self.used >= self.limit:
            return False
        self.used += 1
        return True


# ---------------------------------------------------------------------------
# The mapper
# ---------------------------------------------------------------------------

class _Mapper:
    def __init__(self, sources, log: Callable[[str, str, str, str], None]):
        self.src = sources
        self.log = log
        self.crtsh_budget = _Budget("crt.sh", collect.CAP_JOB_CRTSH_QUERIES)
        self.rdap_budget = _Budget("RDAP", collect.CAP_JOB_RDAP_REQUESTS)
        self._rdap_memo: dict[str, tuple[dict | None, str | None]] = {}

    def dns(self, name: str, rtype: str) -> list[str]:
        status, answers, detail = self.src.dns(name, rtype)
        if status not in ("ok", "empty", "nxdomain"):
            self.log("DNS", f"{name} {rtype}", status, detail)
        return answers if status == "ok" else []

    def rdap(self, kind: str, target: str) -> tuple[dict | None, str | None]:
        key = f"{kind}:{target}"
        if key in self._rdap_memo:
            return self._rdap_memo[key]
        if self.src.needs_network("rdap", key) and not self.rdap_budget.take():
            out = (None, f"skipped: per-job RDAP cap ({self.rdap_budget.limit}) reached")
        else:
            out = self.src.rdap(kind, target)
        if out[1]:
            self.log("RDAP", key, "skipped" if out[1].startswith(("skipped", "RDAP skipped")) else "error", out[1])
        self._rdap_memo[key] = out
        return out

    def crtsh(self, query: str) -> tuple[list, str | None]:
        if self.src.needs_network("crtsh", query) and not self.crtsh_budget.take():
            msg = f"skipped: per-job crt.sh cap ({self.crtsh_budget.limit}) reached"
            self.log("crt.sh", query, "skipped", msg)
            return [], msg
        status, entries, detail = self.src.crtsh(query)
        if status not in ("ok", "empty"):
            self.log("crt.sh", query, status, detail)
            return [], detail
        return entries, None

    def host_profile(self, domain: str) -> dict[str, Any]:
        """DNS profile for one domain: apex A/AAAA (+ www for the brand), NS, MX, PTR."""
        a = self.dns(domain, "A")
        aaaa = self.dns(domain, "AAAA")
        ns = sorted({_clean(x) for x in self.dns(domain, "NS")})
        mx = _mx_hosts(self.dns(domain, "MX"))
        return {"domain": domain, "a": a, "aaaa": aaaa, "ns": ns, "mx": mx}

    def ptr(self, ip: str) -> list[str]:
        try:
            rev = str(dns.reversename.from_address(ip))
        except Exception:  # noqa: BLE001
            return []
        return sorted({_clean(x) for x in self.dns(rev, "PTR")})


def _ip_shared_reason(ip: str, network: dict[str, str], extra_cdn: dict | None = None) -> str | None:
    cdn = shared_infra.cdn_provider(ip, extra_cdn)
    if cdn:
        return f"{cdn} CDN range (shared by many unrelated sites)"
    kw = shared_infra.bulk_hosting(network.get("holder"))
    if kw:
        return f"bulk hosting netblock ({network.get('holder')})"
    return None


def _ns_shared_reason(ns_host: str, extra_dns: dict | None = None) -> str | None:
    prov = shared_infra.dns_provider(ns_host, extra_dns)
    if not prov:
        return None
    kind, label = prov
    return f"{label} ({'parking / for-sale service' if kind == 'parking' else 'managed DNS used by many domains'})"


def map_related(brand_domain: str, lookalikes: list[str], sources=None) -> dict[str, Any]:
    """Map related infrastructure for up to CAP_JOB_LOOKALIKES lookalikes. Never raises for lookup errors."""
    sources = sources or LiveSources()
    started = _now()
    log_entries: list[dict[str, str]] = []

    def log(source: str, query: str, status: str, detail: str) -> None:
        log_entries.append({"source": source, "query": query, "status": status, "detail": detail})

    m = _Mapper(sources, log)
    extra_cdn = getattr(sources, "extra_cdn", None)   # fictional ranges from demo/test fixtures only
    extra_dns = getattr(sources, "extra_dns", None)
    brand_domain = _clean(brand_domain)
    seen: set[str] = set()
    targets: list[str] = []
    for d in lookalikes:
        d = _clean(d)
        if d and d not in seen and d != brand_domain:
            seen.add(d)
            targets.append(d)
    mapped, not_mapped = targets[: collect.CAP_JOB_LOOKALIKES], targets[collect.CAP_JOB_LOOKALIKES:]

    # ---- brand baseline ----
    brand = m.host_profile(brand_domain)
    www = f"www.{brand_domain}"
    brand["www_a"] = m.dns(www, "A")
    brand["www_aaaa"] = m.dns(www, "AAAA")
    brand_ip_host: dict[str, str] = {}
    for ip in brand["a"] + brand["aaaa"]:
        brand_ip_host.setdefault(ip, brand_domain)
    for ip in brand["www_a"] + brand["www_aaaa"]:
        brand_ip_host.setdefault(ip, www)
    brand_ips = sorted(brand_ip_host)
    brand_data, _err = m.rdap("domain", registrable_domain(brand_domain))
    brand["registrar"] = registrar_name(brand_data)
    brand["ips"] = brand_ips

    # ---- lookalikes ----
    results = []
    for dom in mapped:
        prof = m.host_profile(dom)
        notes: list[str] = []
        ips = (prof["a"] + prof["aaaa"])[: collect.CAP_JOB_IPS_PER_DOMAIN]
        if len(prof["a"] + prof["aaaa"]) > len(ips):
            notes.append(f"only the first {collect.CAP_JOB_IPS_PER_DOMAIN} addresses were followed")
        addresses = []
        for ip in ips:
            net_data, _e = m.rdap("ip", ip)
            net = network_summary(net_data)
            addresses.append({
                "ip": ip,
                "ptr": m.ptr(ip),
                "network": net,
                "shared": _ip_shared_reason(ip, net, extra_cdn),
            })
        dom_data, _e = m.rdap("domain", registrable_domain(dom))
        registrar = registrar_name(dom_data)

        entries, ct_err = m.crtsh(dom)
        certs = parse_ct_entries(entries, dom) if entries else {}
        cert_names: set[str] = set()
        for c in certs.values():
            cert_names |= c["names"]
        cert_names = {n for n in cert_names if n != dom and n != f"www.{dom}" and not is_cdn_placeholder(n)}
        if ct_err:
            notes.append(f"crt.sh: {ct_err}")

        ns_shared = {ns: _ns_shared_reason(ns, extra_dns) for ns in prof["ns"]}

        # ---- overlaps with the brand ----
        overlaps: list[dict[str, Any]] = []
        for addr in addresses:
            if addr["ip"] in brand_ips:
                overlaps.append(_overlap("ip", addr["ip"], f"same IP address as {brand_ip_host[addr['ip']]}",
                                         addr["shared"]))
        for ns in prof["ns"]:
            if ns in brand["ns"]:
                overlaps.append(_overlap("nameserver", ns, f"same nameserver as {brand_domain}", ns_shared.get(ns)))
        if registrar and brand["registrar"] and registrar.lower() == brand["registrar"].lower():
            overlaps.append(_overlap("registrar", registrar, f"same registrar as {brand_domain}",
                                     "registrars serve very many unrelated customers"))
        brand_cert_hits = sorted(n for n in cert_names if host_in_domain(n, brand_domain))
        for n in brand_cert_hits[:5]:
            overlaps.append(_overlap("certificate", n, f"a certificate for {dom} also names {n}", None))

        shared_flags = sorted({a["shared"] for a in addresses if a["shared"]} |
                              {r for r in ns_shared.values() if r})
        results.append({
            **prof,
            "addresses": addresses,
            "nameserver_shared": ns_shared,
            "registrar": registrar,
            "cert_count": len(certs),
            "cert_names": sorted(cert_names)[:MAX_CERT_NAMES],
            "cert_names_total": len(cert_names),
            "overlaps": overlaps,
            "shared_flags": shared_flags,
            "notable_overlaps": sum(1 for o in overlaps if o["strength"] == "notable"),
            "notes": notes,
        })

    return {
        "brand": brand,
        "domains": results,
        "not_mapped": not_mapped,
        "limits": {
            "lookalikes": collect.CAP_JOB_LOOKALIKES,
            "ips_per_domain": collect.CAP_JOB_IPS_PER_DOMAIN,
            "crtsh_queries": collect.CAP_JOB_CRTSH_QUERIES,
            "rdap_requests": collect.CAP_JOB_RDAP_REQUESTS,
        },
        "usage": {"crtsh_queries": m.crtsh_budget.used, "rdap_requests": m.rdap_budget.used},
        "log": log_entries,
        "sources_mode": getattr(sources, "mode", "live"),
        "sources_note": SOURCES_NOTE,
        "started_at": started,
        "finished_at": _now(),
    }


def _overlap(kind: str, value: str, label: str, shared_reason: str | None) -> dict[str, Any]:
    if kind == "registrar":
        return {"type": kind, "value": value, "label": label, "shared": True,
                "shared_reason": shared_reason, "strength": "weak"}
    return {
        "type": kind,
        "value": value,
        "label": label,
        "shared": bool(shared_reason),
        "shared_reason": shared_reason,
        "strength": "weak" if shared_reason else "notable",
    }
