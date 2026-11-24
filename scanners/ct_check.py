"""Certificate Transparency lookups via the public crt.sh JSON API (through osint-collectors).

Results are cached in data/cache/ for 6 hours, crt.sh requests are spaced at
least 2 s apart, and a scan makes at most CAP_SCAN_CRTSH_QUERIES queries. On
HTTP 429 the Retry-After window is saved and crt.sh is skipped until it ends.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from osint_collectors.ct import crtsh_fetch

from scanners import collect

CRT_SH = "https://crt.sh/"
CRTSH_ATTEMPTS = 2  # one retry on timeout / 5xx; never on 429


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _fetch_certs(query: str, timeout: float = 25.0) -> tuple[list[dict], str | None]:
    """Return (entries, error). Same contract as v0.3; never raises for network problems."""
    status, entries, detail = crtsh_fetch(
        collect.cache("crtsh"), query, timeout=timeout, client=collect.client(),
        base_url=CRT_SH, attempts=CRTSH_ATTEMPTS,
    )
    if status in ("ok", "empty"):
        return entries, None
    if status == "timeout":
        return [], "crt.sh timed out (common under load)"
    if status == "skipped":
        return [], detail.replace("skipped: ", "skipped (", 1) + ")"
    return [], detail if detail.startswith("crt.sh") else f"crt.sh error: {detail}"


def _names_from_entry(entry: dict) -> set[str]:
    names: set[str] = set()
    cn = (entry.get("common_name") or "").strip().lower()
    if cn:
        names.add(cn)
    nvs = entry.get("name_value") or ""
    for line in str(nvs).split("\n"):
        n = line.strip().lower()
        if n:
            names.add(n)
    return names


def check_certificate_transparency(domain: str, brand: str = "", limit: int = 40) -> list[dict[str, Any]]:
    """Query crt.sh for the domain and brand-ish patterns; emit findings."""
    domain = domain.strip().lower().removeprefix("http://").removeprefix("https://").split("/")[0]
    if domain.startswith("www."):
        domain = domain[4:]
    brand_clean = "".join(c for c in (brand or "").lower() if c.isalnum() or c in "-")
    findings: list[dict[str, Any]] = []
    ts = _now()

    queries = [f"%.{domain}", domain]
    if brand_clean and brand_clean not in domain:
        # Identity search — may return broad results; we filter loosely
        queries.append(f"%{brand_clean}%")
    queries = queries[: collect.CAP_SCAN_CRTSH_QUERIES]

    seen_ids: set[int] = set()
    all_entries: list[dict] = []
    errors: list[str] = []

    for q in queries:
        entries, err = _fetch_certs(q)
        if err:
            errors.append(f"{q}: {err}")
            continue
        for e in entries:
            eid = e.get("id")
            if eid in seen_ids:
                continue
            if eid is not None:
                seen_ids.add(eid)
            all_entries.append(e)

    if errors and not all_entries:
        findings.append(
            {
                "severity": "info",
                "source": "Certificate Transparency (crt.sh)",
                "title": "CT lookup unavailable",
                "detail": "; ".join(errors),
                "target": domain,
                "timestamp": ts,
                "why_it_matters": (
                    "crt.sh is a free public CT search and is often rate-limited. "
                    "Retry later or use demo mode for a synthetic walkthrough."
                ),
                "raw": {"errors": errors},
            }
        )
        return findings

    # Summarize known-good domain certs
    domain_related: list[dict] = []
    brand_suspicious: list[dict] = []

    for e in all_entries:
        names = _names_from_entry(e)
        related = any(n == domain or n.endswith("." + domain) or n == "*." + domain for n in names)
        brand_hit = False
        if brand_clean:
            brand_hit = any(brand_clean in n.replace(".", "").replace("-", "") or brand_clean in n for n in names)
        entry_summary = {
            "id": e.get("id"),
            "issuer": e.get("issuer_name"),
            "not_before": e.get("not_before"),
            "not_after": e.get("not_after"),
            "names": sorted(names)[:12],
        }
        if related:
            domain_related.append(entry_summary)
        elif brand_hit:
            # Exclude if name is clearly unrelated long junk? keep for MVP visibility
            brand_suspicious.append(entry_summary)

    if domain_related:
        # Deduplicate by name sets
        unique_names: set[str] = set()
        for e in domain_related:
            unique_names.update(e["names"])
        sample = sorted(unique_names)[:15]
        findings.append(
            {
                "severity": "info",
                "source": "Certificate Transparency (crt.sh)",
                "title": f"CT: {len(domain_related)} cert(s) for {domain}",
                "detail": f"Sample names: {', '.join(sample)}" + ("…" if len(unique_names) > 15 else ""),
                "target": domain,
                "timestamp": ts,
                "why_it_matters": (
                    "CT logs show which hostnames have had publicly logged TLS certificates — "
                    "useful for discovering forgotten subdomains."
                ),
                "raw": {"count": len(domain_related), "sample": domain_related[:10], "errors": errors},
            }
        )

        # Highlight wildcard / unusual subdomains lightly
        interesting = [
            n
            for n in unique_names
            if n.startswith("*.")
            or any(tok in n for tok in ("login", "secure", "vpn", "admin", "staging", "dev", "test"))
        ]
        if interesting:
            findings.append(
                {
                    "severity": "warn",
                    "source": "Certificate Transparency (crt.sh)",
                    "title": "CT: notable hostnames in certificates",
                    "detail": ", ".join(sorted(interesting)[:20]),
                    "target": domain,
                    "timestamp": ts,
                    "why_it_matters": (
                        "Wildcards and login/admin-style names in CT can expand your attack surface "
                        "inventory (still public data only)."
                    ),
                    "raw": {"names": sorted(interesting)[:40]},
                }
            )
    else:
        findings.append(
            {
                "severity": "info",
                "source": "Certificate Transparency (crt.sh)",
                "title": f"No CT certs found for {domain}",
                "detail": "Query returned no domain-related entries (or was empty).",
                "target": domain,
                "timestamp": ts,
                "why_it_matters": (
                    "Absence may mean a new domain, private PKI only, or a temporary CT search gap."
                ),
                "raw": {"errors": errors},
            }
        )

    # Brand matches that are NOT under the primary domain — potential impersonation signal
    filtered_brand = []
    for e in brand_suspicious[:limit]:
        names = e["names"]
        if any(domain in n for n in names):
            continue
        filtered_brand.append(e)

    if filtered_brand and brand_clean:
        sample_names: list[str] = []
        for e in filtered_brand[:15]:
            sample_names.extend(e["names"][:3])
        findings.append(
            {
                "severity": "high",
                "source": "Certificate Transparency (crt.sh)",
                "title": f"CT: brand-like names outside {domain}",
                "detail": f"{len(filtered_brand)} cert(s); sample: {', '.join(sample_names[:12])}",
                "target": brand_clean,
                "timestamp": ts,
                "why_it_matters": (
                    "Certificates for hostnames containing your brand but not under your domain "
                    "can indicate lookalike sites. Many hits are false positives (shared words) — review carefully."
                ),
                "raw": {"sample": filtered_brand[:10]},
            }
        )

    if errors:
        findings.append(
            {
                "severity": "info",
                "source": "Certificate Transparency (crt.sh)",
                "title": "Partial CT query errors",
                "detail": "; ".join(errors),
                "target": domain,
                "timestamp": ts,
                "why_it_matters": "Some crt.sh queries failed; results may be incomplete.",
                "raw": {"errors": errors},
            }
        )

    return findings
