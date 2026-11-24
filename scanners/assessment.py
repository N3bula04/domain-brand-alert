"""Analyst assessments for scan findings and related public evidence."""

from datetime import datetime, timedelta, timezone
import re

ASSESSMENT_FIELDS = ("priority", "confidence", "trigger", "what_would_change", "next_action")
PRIORITY_BY_SEVERITY = {"high": "high", "warn": "medium", "info": "low"}
SEVERITY_BY_PRIORITY = {priority: severity for severity, priority in PRIORITY_BY_SEVERITY.items()}
RECENT_REGISTRATION = timedelta(days=90)


def _set_priority(finding, priority):
    finding.update(priority=priority, severity=SEVERITY_BY_PRIORITY[priority])


def assess_finding(finding):
    """Fill missing fields in place, preserving complete authored assessments."""
    if all(finding.get(key) for key in ASSESSMENT_FIELDS):
        _set_priority(finding, finding["priority"])
        return

    source = finding["source"]
    title = finding["title"]
    priority = PRIORITY_BY_SEVERITY[finding["severity"]]
    confidence = "high"

    if source == "DNS lookalike":
        reason = (finding.get("raw") or {}).get("generation_reason", "Lookalike hostname")
        label = finding["target"].split(".")[0].lower()
        lure = any(word in reason.lower() for word in ("phishing", "prefix/suffix", "brand prefix"))
        lure = lure or label.startswith(("secure-", "login-", "support-"))
        if lure:
            priority, confidence = "high", "medium"
            trigger = "Brand-keyword hostname with a login or support cue resolves in public DNS"
            change = (
                "A login-style certificate name, uncommon shared nameserver, recent registration with a "
                "currently valid certificate, or brand-mimicking login page would raise concern. "
                "Parking, no certificate, or a confirmed defensive registration would lower it."
            )
            action = "Review certificates and nameservers, then record which login-style names are in use."
        else:
            priority, confidence = "medium", "low"
            trigger = f"{reason} resolves in public DNS"
            change = (
                "An uncommon nameserver or certificate overlap, login-style certificate names, or "
                "brand-mimicking content would raise concern. Shared hosting, a CDN or registrar, "
                "parking, or no relevant certificate would lower it."
            )
            action = "Record the variant and compare infrastructure before escalating."
    elif title.startswith("CT: brand-like names outside "):
        confidence = "low"
        trigger = "CT logged brand-like certificate names outside the monitored domain"
        change = (
            "Recent registration with a currently valid certificate raises urgency, while a brand-mimicking "
            "login page would strengthen confidence. Unrelated use of a shared word would lower concern."
        )
        action = "Check which sample names resolve and compare their infrastructure."
    elif title.startswith("CT: notable hostnames"):
        trigger = "CT logged wildcard or login, admin, or staging-style hostnames on the monitored domain"
        change = "Unexpected names still in use would raise priority. Known or retired names would lower it."
        action = "Confirm which hostnames are expected and still in use."
    elif "unavailable" in title.lower() or title == "Partial CT query errors":
        trigger = "One or more public source queries failed or were skipped"
        change = (
            "Repeated failures would raise the priority of closing the coverage gap. "
            "A successful retry would close it."
        )
        action = "Retry later to fill the source coverage gap."
    elif title.startswith("No CT certs found"):
        trigger = "CT returned no matching certificate entries for the monitored domain"
        change = "A known public certificate missing from the results would raise priority. Private PKI or a confirmed lack of issuance would lower it."
        action = "Compare the result with the expected certificate inventory."
    elif source.startswith("Certificate"):
        trigger = "CT returned certificate entries for the monitored domain"
        change = "Unexpected names or issuers would raise priority. Issuance that matches inventory would keep priority low."
        action = "Compare the certificate sample with the expected inventory."
    elif source == "DNS" and "does not resolve" in title:
        confidence = "medium"
        trigger = "The DNS lookup returned no address or alias"
        change = (
            "Repeatable failure for a production host or a dangling alias would raise concern. "
            "Expected absence or a successful retry after a timeout would lower it."
        )
        action = "Verify the host and its DNS records for a production outage or dangling alias."
    elif source == "DNS":
        trigger = "The monitored hostname returned a public DNS address or alias"
        change = "An unexpected address or alias would raise priority. A match to the expected DNS records would keep priority low."
        action = "Compare the answer with the expected DNS records."
    else:
        trigger = "Public registration records were returned for the monitored domain"
        change = "Unexpected registrar or nameserver changes would raise priority. Records matching the expected registration would keep priority low."
        action = "Compare the registration details with the domain inventory."

    finding.update(confidence=confidence, trigger=trigger, what_would_change=change, next_action=action)
    _set_priority(finding, priority)


def utc_datetime(value):
    """Parse a public source timestamp, treating timestamps without offsets as UTC."""
    if not isinstance(value, str):
        return None
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def enrich_findings_with_related(findings, related_result, *, reassess=False):
    """Apply mapped evidence to matching lookalikes in place."""
    domains = {row["domain"]: row for row in related_result.get("domains", [])}
    observed = utc_datetime(related_result.get("finished_at")) or datetime.now(timezone.utc)
    for finding in findings:
        if finding["source"] != "DNS lookalike":
            continue
        target = finding["target"].lower().rstrip(".")
        domain = domains.get(target)
        is_demo = (finding.get("raw") or {}).get("demo")
        if not domain or finding.get("suppressed") or (related_result.get("mode") == "live" and is_demo):
            continue
        if reassess:
            for key in ASSESSMENT_FIELDS:
                finding.pop(key, None)
        assess_finding(finding)
        overlaps = domain.get("overlaps", [])
        notable = [o for o in overlaps if o["strength"] == "notable" and o["type"] != "registrar"]
        nameservers = [o["value"] for o in notable if o["type"] == "nameserver"]
        cert_names = [
            name for name in domain.get("cert_names", [])
            if re.search(r"(?:^|[.-])(?:login|account-verify|verify-account)(?:[.-]|$)",
                         name.removesuffix("." + target))
        ]
        signals = []
        if nameservers:
            signals.append(f"shared uncommon nameserver {', '.join(nameservers[:2])}")
        if cert_names:
            signals.append(f"certificate names {', '.join(cert_names[:3])}")

        registered = utc_datetime(domain.get("registered_at"))
        recent_with_cert = (
            registered and timedelta(0) <= observed - registered <= RECENT_REGISTRATION
            and domain.get("has_current_certificate")
        )
        parking = any("parking" in reason.lower() for reason in domain.get("shared_flags", []))
        weak_only = not notable and (bool(overlaps) or parking)

        trigger_context = []
        if signals:
            _set_priority(finding, "high")
            finding["confidence"] = "medium"
            trigger_context.extend(signals)
            finding["what_would_change"] = (
                "A live page mimicking the brand would strengthen confidence. "
                "A verified defensive registration, shared DNS service, or inactive login names would lower concern."
            )
            evidence = []
            if nameservers:
                evidence.append("shared nameservers")
            if cert_names:
                evidence.append("certificate hostnames")
            finding["next_action"] = f"Verify which listed {' and '.join(evidence)} are in use."
        elif weak_only:
            finding["confidence"] = "low"
            if parking:
                trigger_context.append("parking nameservers")
            for overlap in overlaps[:2]:
                kind = overlap["type"]
                if kind == "ip":
                    reason = overlap.get("shared_reason") or ""
                    kind = "CDN IP" if "CDN range" in reason else "IP"
                trigger_context.append(f"shared {kind} {overlap['value']}")
            finding["what_would_change"] = (
                "An uncommon infrastructure overlap or brand-mimicking content would raise concern. "
                "Shared hosting, CDN, or registrar links offer no evidence of affiliation. Confirmed parking would lower concern."
            )
            finding["next_action"] = "Log and monitor the variant, escalating only if independent evidence emerges."
        if recent_with_cert:
            _set_priority(finding, "high")
            trigger_context.append("recent RDAP registration and a currently valid certificate")
            if not signals:
                finding["next_action"] = "Review certificate names and compare the hostname with expected brand infrastructure."

        if trigger_context:
            suffix = " · " + " · ".join(trigger_context)
            if not finding["trigger"].endswith(suffix):
                finding["trigger"] += suffix
