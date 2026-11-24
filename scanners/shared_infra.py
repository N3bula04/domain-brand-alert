"""Reference data for 'shared CDN / hosting' flags.

Many unrelated sites share the same CDN edge IPs, bulk-hosting netblocks,
managed DNS providers and domain-parking nameservers. A lookalike that
"shares" one of these with your brand is not evidence that the same people
run both, so these matches are played down in the related-infrastructure view.

The lists are short and hand-maintained, so they are not exhaustive.
"""

from __future__ import annotations

import ipaddress
import re

from osint_collectors.psl import host_in_domain, registrable_domain

# Published CDN ranges. Cloudflare: https://www.cloudflare.com/ips/
# Fastly: https://api.fastly.com/public-ip-list
CDN_RANGES: dict[str, list[str]] = {
    "Cloudflare": [
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
        "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
        "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
        "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
    ],
    "Fastly": [
        "23.235.32.0/20", "43.249.72.0/22", "103.244.50.0/24", "103.245.222.0/23",
        "103.245.224.0/24", "104.156.80.0/20", "140.248.64.0/18", "140.248.128.0/17",
        "146.75.0.0/17", "151.101.0.0/16", "157.52.64.0/18", "167.82.0.0/17",
        "167.82.128.0/20", "167.82.160.0/20", "167.82.224.0/20", "172.111.64.0/18",
        "185.31.16.0/22", "199.27.72.0/21", "199.232.0.0/16",
        "2a04:4e40::/32", "2a04:4e42::/32",
    ],
}

# Netblock holders that rent address space to the public (whole-word match).
BULK_HOSTING_KEYWORDS = [
    "amazon", "aws", "google", "microsoft", "azure", "cloudflare", "fastly", "akamai",
    "digitalocean", "linode", "vultr", "choopa", "ovh", "hetzner", "leaseweb", "godaddy",
    "namecheap", "hostinger", "ionos", "alibaba", "aliyun", "tencent", "oracle", "contabo",
    "scaleway", "hostgator", "bluehost", "unified layer", "newfold", "squarespace", "wix",
    "shopify", "vercel", "netlify", "github", "heroku", "hosting", "datacenter", "data center",
    "colocation", "vps",
]

# Managed DNS providers: a nameserver here means "uses a popular DNS host".
MANAGED_DNS = {
    "cloudflare.com": "Cloudflare DNS",
    "domaincontrol.com": "GoDaddy DNS",
    "registrar-servers.com": "Namecheap DNS",
    "googledomains.com": "Google DNS",
    "nsone.net": "NS1",
    "akam.net": "Akamai DNS",
    "ultradns.com": "UltraDNS",
    "ultradns.net": "UltraDNS",
    "dnsimple.com": "DNSimple",
    "digitalocean.com": "DigitalOcean DNS",
    "linode.com": "Linode DNS",
    "hostgator.com": "HostGator DNS",
    "bluehost.com": "Bluehost DNS",
    "wixdns.net": "Wix DNS",
    "squarespacedns.com": "Squarespace DNS",
    "vercel-dns.com": "Vercel DNS",
    "netlify.com": "Netlify DNS",
    "ovh.net": "OVH DNS",
    "gandi.net": "Gandi DNS",
    "name.com": "Name.com DNS",
    "dnsowl.com": "NameSilo DNS",
    "hichina.com": "Alibaba Cloud DNS",
}
MANAGED_DNS_LABELS = {r"^awsdns-\d{2}$": "Amazon Route 53", r"^azure-dns$": "Azure DNS"}

# Domain-parking / for-sale nameservers. Very common on lookalike domains.
PARKING_DNS = {
    "sedoparking.com": "Sedo parking",
    "parkingcrew.net": "ParkingCrew",
    "bodis.com": "Bodis parking",
    "above.com": "Above.com parking",
    "dan.com": "Dan.com (for sale)",
    "afternic.com": "Afternic (for sale)",
    "parklogic.com": "ParkLogic",
    "uniregistrymarket.link": "Uniregistry market",
    "huge-domains.com": "HugeDomains (for sale)",
}

def cdn_provider(ip: str, extra: dict[str, list[str]] | None = None) -> str | None:
    """CDN name if ip is in a published range. `extra` adds ranges (fictional demo/test CDNs)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for name, ranges in list(CDN_RANGES.items()) + list((extra or {}).items()):
        for cidr in ranges:
            net = ipaddress.ip_network(cidr, strict=False)
            if addr.version == net.version and addr in net:
                return name
    return None


def bulk_hosting(holder: str | None) -> str | None:
    """Return the matching keyword if a netblock holder looks like a public hosting provider."""
    text = (holder or "").lower()
    for kw in BULK_HOSTING_KEYWORDS:
        if re.search(r"(?<![a-z0-9])" + re.escape(kw) + r"(?![a-z0-9])", text):
            return kw
    return None


def dns_provider(ns_host: str, extra: dict[str, dict[str, str]] | None = None) -> tuple[str, str] | None:
    """('parking'|'managed', label) for a nameserver host on a known shared provider.

    `extra` = {"parking": {domain: label}, "managed": {domain: label}} (fictional demo/test providers).
    """
    h = ns_host.lower().rstrip(".")
    extra = extra or {}
    for dom, label in extra.get("parking", {}).items():
        if host_in_domain(h, dom):
            return "parking", label
    for dom, label in extra.get("managed", {}).items():
        if host_in_domain(h, dom):
            return "managed", label
    for dom, label in PARKING_DNS.items():
        if host_in_domain(h, dom):
            return "parking", label
    for dom, label in MANAGED_DNS.items():
        if host_in_domain(h, dom):
            return "managed", label
    reg_label = registrable_domain(h).split(".")[0]
    for pattern, label in MANAGED_DNS_LABELS.items():
        if re.match(pattern, reg_label):
            return "managed", label
    return None
