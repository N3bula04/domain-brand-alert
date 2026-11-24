"""DNS resolution checks for apex, www, and lookalike candidates.

Queries go through your recursive resolver via osint-collectors (cached in
data/cache/ for an hour). Nothing here connects to the hosts themselves.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from osint_collectors.dns import dns_query

from scanners import collect
from scanners.lookalikes import generate_lookalikes, split_domain


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def resolve_host(hostname: str, timeout: float = 1.0) -> dict[str, Any]:
    """A / AAAA / CNAME for one name. Same return shape as v0.3."""
    res = collect.resolver(timeout)
    dns_cache = collect.cache("dns")
    records: dict[str, list[str]] = {"A": [], "AAAA": [], "CNAME": []}
    errors: list[str] = []
    for rtype in ("A", "AAAA", "CNAME"):
        status, answers, detail = dns_query(res, dns_cache, hostname, rtype)
        if status == "ok":
            records[rtype] = answers
        elif status == "nxdomain":
            break  # the name does not exist: no point asking for other types
        elif status == "timeout":
            errors.append(f"{rtype} timeout")
        elif status == "error":
            errors.append(f"{rtype}: {detail}")
    resolves = bool(records["A"] or records["AAAA"] or records["CNAME"])
    return {
        "hostname": hostname,
        "resolves": resolves,
        "records": records,
        "errors": errors,
    }


def check_primary_dns(domain: str) -> list[dict[str, Any]]:
    label, tld = split_domain(domain)
    apex = f"{label}{tld}"
    findings: list[dict[str, Any]] = []
    ts = _now()

    for host, role in ((apex, "apex"), (f"www.{apex}", "www")):
        result = resolve_host(host)
        if result["resolves"]:
            addrs = result["records"]["A"] or result["records"]["AAAA"] or result["records"]["CNAME"]
            findings.append(
                {
                    "severity": "info",
                    "source": "DNS",
                    "title": f"{role} resolves ({host})",
                    "detail": f"Addresses/CNAMEs: {', '.join(addrs[:5])}",
                    "target": host,
                    "timestamp": ts,
                    "why_it_matters": (
                        "Baseline confirmation that the monitored domain is live in public DNS."
                    ),
                    "raw": result,
                }
            )
        else:
            findings.append(
                {
                    "severity": "warn",
                    "source": "DNS",
                    "title": f"{role} does not resolve ({host})",
                    "detail": "No A/AAAA/CNAME answers (or lookup timed out).",
                    "target": host,
                    "timestamp": ts,
                    "why_it_matters": (
                        "If this is your production domain, a missing DNS answer may indicate "
                        "misconfiguration or takeover risk worth verifying."
                    ),
                    "raw": result,
                }
            )
    return findings


def check_lookalike_dns(domain: str, brand: str = "", limit: int = 60) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    ts = _now()
    candidates = generate_lookalikes(domain, brand=brand, limit=limit)

    for cand in candidates:
        host = cand["domain"]
        result = resolve_host(host)
        if not result["resolves"]:
            continue
        addrs = result["records"]["A"] or result["records"]["AAAA"] or result["records"]["CNAME"]
        # Resolving lookalikes are higher signal
        reason_l = cand["reason"].lower()
        high_kw = ("phishing", "typosquat", "homoglyph", "bit-flip", "prefix/suffix")
        severity = "high" if any(k in reason_l for k in high_kw) else "warn"
        findings.append(
            {
                "severity": severity,
                "source": "DNS lookalike",
                "title": f"Lookalike resolves: {host}",
                "detail": f"Reason: {cand['reason']}. Addresses: {', '.join(addrs[:5])}",
                "target": host,
                "timestamp": ts,
                "why_it_matters": (
                    "A publicly resolving lookalike can be used for phishing, brand impersonation, "
                    "or confusion. Investigate ownership and certificate use."
                ),
                "raw": {**result, "generation_reason": cand["reason"]},
            }
        )
    return findings
