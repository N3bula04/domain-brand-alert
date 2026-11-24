"""Synthetic findings for offline / demo mode when live APIs fail."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def synthetic_findings(brand: str, domain: str) -> list[dict[str, Any]]:
    ts = _now()
    brand = brand or "DemoBrand"
    domain = domain or "brand-example.test"
    label = domain.split(".")[0]
    suffix = domain.split(".", 1)[-1] if "." in domain else "test"
    slug = "".join(ch for ch in brand.lower() if ch.isalnum() or ch == "-") or label
    typo = f"{label[0]}{label[2:]}.{suffix}" if len(label) > 2 else f"{label}-x.test"
    # Preserve the legacy typo title used in scan fingerprints.
    typo_title_domain = domain if "." in domain else f"{label}.com"
    return [
        {
            "severity": "info",
            "source": "DNS",
            "title": f"apex resolves ({domain})",
            "detail": "Addresses/CNAMEs: 192.0.2.10 (synthetic)",
            "target": domain,
            "timestamp": ts,
            "why_it_matters": "Baseline confirmation that the monitored domain is live in public DNS.",
            "raw": {"demo": True},
        },
        {
            "severity": "info",
            "source": "DNS",
            "title": f"www resolves (www.{domain})",
            "detail": "Addresses/CNAMEs: 203.0.113.20 (synthetic)",
            "target": f"www.{domain}",
            "timestamp": ts,
            "why_it_matters": "Baseline confirmation that the monitored domain is live in public DNS.",
            "raw": {"demo": True},
        },
        {
            "severity": "warn",
            "source": "DNS lookalike",
            "title": f"Lookalike resolves: {typo_title_domain}",
            "detail": f"Variant: {typo}. Reason: Missing character typosquat. Addresses: 203.0.113.20 (synthetic)",
            "target": typo,
            "timestamp": ts,
            "why_it_matters": (
                "A publicly resolving lookalike can be used for phishing, brand impersonation, "
                "or confusion. Compare public infrastructure and certificate use."
            ),
            "raw": {"demo": True, "generation_reason": "Missing character typosquat"},
        },
        {
            "severity": "high",
            "source": "DNS lookalike",
            "title": f"Lookalike resolves: secure-{label}.{suffix}",
            "detail": "Reason: Brand-keyword phishing-style hostname. Addresses: 198.51.100.44 (synthetic)",
            "target": f"secure-{label}.{suffix}",
            "timestamp": ts,
            "why_it_matters": (
                "A publicly resolving lookalike can be used for phishing, brand impersonation, "
                "or confusion. Compare public infrastructure and certificate use."
            ),
            "raw": {"demo": True, "generation_reason": "Brand-keyword phishing-style hostname"},
        },
        {
            "severity": "info",
            "source": "Certificate Transparency (crt.sh)",
            "title": f"CT: 12 cert(s) for {domain}",
            "detail": f"Sample names: {domain}, www.{domain}, api.{domain}, staging.{domain}",
            "target": domain,
            "timestamp": ts,
            "why_it_matters": (
                "CT logs show which hostnames have had publicly logged TLS certificates — "
                "useful for discovering forgotten subdomains."
            ),
            "raw": {"demo": True, "count": 12},
        },
        {
            "severity": "warn",
            "source": "Certificate Transparency (crt.sh)",
            "title": "CT: notable hostnames in certificates",
            "detail": f"*.{domain}, login.{domain}, staging.{domain}",
            "target": domain,
            "timestamp": ts,
            "why_it_matters": (
                "Wildcards and login/admin-style names in CT can expand your attack surface inventory."
            ),
            "raw": {"demo": True},
        },
        {
            "severity": "high",
            "source": "Certificate Transparency (crt.sh)",
            "title": f"CT: brand-like names outside {domain}",
            "detail": f"3 cert(s); sample: {slug}-login.test, my{slug}.test, {slug}support.test",
            "target": brand.lower(),
            "timestamp": ts,
            "why_it_matters": (
                "Certificates for hostnames containing your brand but not under your domain "
                "can indicate lookalike sites. Many hits are false positives — review carefully."
            ),
            "raw": {"demo": True},
        },
        {
            "severity": "info",
            "source": "RDAP",
            "title": f"RDAP registration for {domain}",
            "detail": "Registered: 1995-08-14T04:00:00Z; Status: client delete prohibited; NS: ns1.dns-provider.test, ns2.dns-provider.test (synthetic)",
            "target": domain,
            "timestamp": ts,
            "why_it_matters": (
                "Public registration metadata helps confirm registrar, expiry, and nameservers."
            ),
            "raw": {"demo": True},
        },
    ]
