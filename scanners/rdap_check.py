"""RDAP / WHOIS lookups using public endpoints (no paid APIs).

RDAP goes through osint-collectors: rdap.org first, then the server listed in
IANA's RDAP bootstrap files (covers every TLD that publishes RDAP, not just a
hard-coded list). Answers are cached in data/cache/ for 24 hours. On HTTP 429
the Retry-After window is saved and RDAP is skipped until it ends. WHOIS
(python-whois, port 43 to the registry's WHOIS server) is the fallback.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from osint_collectors.rdap import (IANA_BOOTSTRAP, RDAP_REDIRECTOR, RateLimited, rdap_backoff_until, rdap_fetch,
                                   rdap_record_backoff)

from scanners import collect

try:
    import whois as python_whois
except Exception:  # noqa: BLE001
    python_whois = None

# Endpoints (module-level so tests can point them at a local fake server).
REDIRECTOR = RDAP_REDIRECTOR
BOOTSTRAP_URLS = dict(IANA_BOOTSTRAP)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def rdap_get(kind: str, target: str, timeout: float = 12.0) -> tuple[dict[str, Any] | None, str | None]:
    """One RDAP object ('domain' or 'ip'). Returns (data, error); never raises."""
    rdap_cache = collect.cache("rdap")
    until = rdap_backoff_until(rdap_cache)
    if until is not None:
        return None, f"RDAP skipped: rate-limited earlier, backing off until {until.isoformat()}"
    try:
        status, data, detail = rdap_fetch(rdap_cache, kind, target, timeout=timeout, client=collect.client(),
                                          redirector=REDIRECTOR, bootstrap_urls=BOOTSTRAP_URLS)
    except RateLimited as exc:
        until = rdap_record_backoff(rdap_cache, exc.retry_after)
        return None, f"RDAP rate-limited ({exc.detail}); backing off until {until.isoformat()}"
    if status == "ok" and isinstance(data, dict):
        return data, None
    if status == "empty":
        return None, "RDAP: domain not found" if kind == "domain" else "RDAP: no record"
    if status == "timeout":
        return None, "RDAP timed out"
    return None, f"RDAP error: {detail}"


def rdap_lookup(domain: str, timeout: float = 12.0) -> tuple[dict[str, Any] | None, str | None]:
    return rdap_get("domain", domain.lower().strip("."), timeout=timeout)


def whois_lookup(domain: str) -> tuple[dict[str, Any] | None, str | None]:
    if python_whois is None:
        return None, "python-whois not available"
    try:
        w = python_whois.whois(domain)
        if w is None:
            return None, "WHOIS returned empty"
        # python-whois returns a WhoisEntry mapping-like object
        data = {}
        for key in ("domain_name", "registrar", "creation_date", "expiration_date", "updated_date", "name_servers", "status", "emails"):
            try:
                val = w.get(key) if hasattr(w, "get") else getattr(w, key, None)
            except Exception:  # noqa: BLE001
                val = None
            if val is not None:
                data[key] = str(val) if not isinstance(val, (list, str, int, float, bool)) else val
        return data or {"raw": str(w)[:500]}, None
    except Exception as exc:  # noqa: BLE001
        return None, f"WHOIS error: {type(exc).__name__}: {exc}"


def _summarize_rdap(data: dict[str, Any]) -> dict[str, Any]:
    events = {}
    for ev in data.get("events") or []:
        action = ev.get("eventAction")
        date = ev.get("eventDate")
        if action and date:
            events[action] = date
    status = data.get("status") or []
    entities = []
    for ent in data.get("entities") or []:
        roles = ent.get("roles") or []
        handle = ent.get("handle")
        vcard_name = None
        vcard = ent.get("vcardArray")
        if isinstance(vcard, list) and len(vcard) > 1:
            for item in vcard[1]:
                if isinstance(item, list) and item and item[0] == "fn":
                    vcard_name = item[3] if len(item) > 3 else None
        entities.append({"roles": roles, "handle": handle, "name": vcard_name})
    ns = []
    for n in data.get("nameservers") or []:
        if isinstance(n, dict) and n.get("ldhName"):
            ns.append(n["ldhName"])
    return {
        "ldhName": data.get("ldhName"),
        "status": status,
        "events": events,
        "entities": entities[:8],
        "nameservers": ns[:8],
    }


def check_registration(domain: str) -> list[dict[str, Any]]:
    domain = domain.strip().lower().removeprefix("http://").removeprefix("https://").split("/")[0]
    if domain.startswith("www."):
        domain = domain[4:]
    findings: list[dict[str, Any]] = []
    ts = _now()

    rdap_data, rdap_err = rdap_lookup(domain)
    if rdap_data:
        summary = _summarize_rdap(rdap_data)
        events = summary.get("events") or {}
        detail_parts = []
        if events.get("registration"):
            detail_parts.append(f"Registered: {events['registration']}")
        if events.get("expiration"):
            detail_parts.append(f"Expires: {events['expiration']}")
        if summary.get("status"):
            detail_parts.append(f"Status: {', '.join(map(str, summary['status'][:4]))}")
        if summary.get("nameservers"):
            detail_parts.append(f"NS: {', '.join(summary['nameservers'][:4])}")
        findings.append(
            {
                "severity": "info",
                "source": "RDAP",
                "title": f"RDAP registration for {domain}",
                "detail": "; ".join(detail_parts) or "RDAP record retrieved",
                "target": domain,
                "timestamp": ts,
                "why_it_matters": (
                    "Public registration metadata helps confirm registrar, expiry, and nameservers. "
                    "Privacy-redacted records are common."
                ),
                "raw": summary,
            }
        )
    else:
        # Fall back to WHOIS
        whois_data, whois_err = whois_lookup(domain)
        if whois_data:
            findings.append(
                {
                    "severity": "info",
                    "source": "WHOIS",
                    "title": f"WHOIS record for {domain}",
                    "detail": (
                        f"Registrar: {whois_data.get('registrar', 'n/a')}; "
                        f"Created: {whois_data.get('creation_date', 'n/a')}; "
                        f"Expires: {whois_data.get('expiration_date', 'n/a')}"
                    ),
                    "target": domain,
                    "timestamp": ts,
                    "why_it_matters": (
                        "WHOIS is a legacy public registration lookup. Many registries redact contacts; "
                        "treat as a weak signal only."
                    ),
                    "raw": whois_data,
                }
            )
        else:
            findings.append(
                {
                    "severity": "info",
                    "source": "RDAP/WHOIS",
                    "title": f"Registration lookup skipped/unavailable for {domain}",
                    "detail": f"RDAP: {rdap_err or 'n/a'}; WHOIS: {whois_err or 'n/a'}",
                    "target": domain,
                    "timestamp": ts,
                    "why_it_matters": (
                        "Some registries block automated RDAP/WHOIS or require interactive access. "
                        "This demo skips paid WHOIS APIs by design."
                    ),
                    "raw": {"rdap_error": rdap_err, "whois_error": whois_err},
                }
            )
    return findings
