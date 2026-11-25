"""Shared collector runtime: osint-collectors with Brand Alert's cache, caps and throttling.

Everything here is synchronous (requests + dnspython). FastAPI routes and the
background jobs call it from worker threads, never on the event loop.

Rate-limit safety, in layers:
  * a JSON cache under data/cache/ (DNS 1 h, crt.sh 6 h, RDAP 24 h), so
    repeated scans mostly hit disk;
  * a process-wide throttle: at least 2 s between crt.sh requests and 1 s
    between RDAP requests, across all threads;
  * fixed per-scan / per-job caps (see the CAP_* constants);
  * HTTP 429 is never retried: the Retry-After window is saved in the cache
    and later calls skip that service until it ends.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any

from osint_collectors.cache import Cache
from osint_collectors.dns import make_resolver
from osint_collectors.http import HttpClient, HttpOutcome, host_of

ROOT = Path(__file__).resolve().parent.parent
CACHE_DIR = ROOT / "data" / "cache"
APP_VERSION = "0.5.1"
USER_AGENT = (
    f"DomainBrandAlert/{APP_VERSION} (+https://github.com/N3bula04/domain-brand-alert; personal project)"
)

# --- per-scan caps (a "scan" = one run_scan call) ---
CAP_SCAN_CRTSH_QUERIES = 3   # %.domain, domain, %brand%
CAP_SCAN_RDAP_DOMAINS = 1    # the primary domain only
# --- per related-infrastructure job caps ---
CAP_JOB_LOOKALIKES = 8       # lookalike domains mapped per job
CAP_JOB_IPS_PER_DOMAIN = 4   # A/AAAA addresses followed per domain (PTR + RDAP)
CAP_JOB_CRTSH_QUERIES = 4    # crt.sh lookups per job (exact-name queries)
CAP_JOB_RDAP_REQUESTS = 10   # RDAP lookups (domains + IP networks) per job

# Minimum gap between real network requests to the same service (seconds).
MIN_INTERVAL = {"crt.sh": 2.0, "rdap": 1.0}

DNS_TTL_HOURS = 1     # lookalikes can appear at any time; keep DNS fresh
CRTSH_TTL_HOURS = 6
RDAP_TTL_HOURS = 24


def _service(url: str) -> str:
    host = host_of(url).lower()
    if host == "crt.sh" or host.endswith(".crt.sh"):
        return "crt.sh"
    return "rdap"


class ThrottledClient(HttpClient):
    """HttpClient that spaces real requests per service across all threads."""

    _lock = threading.Lock()
    _last: dict[str, float] = {}

    def get(self, url: str, **kwargs: Any) -> HttpOutcome:
        svc = _service(url)
        gap = MIN_INTERVAL.get(svc, 1.0)
        with ThrottledClient._lock:
            wait = ThrottledClient._last.get(svc, 0.0) + gap - time.monotonic()
            if wait > 0:
                time.sleep(wait)
            ThrottledClient._last[svc] = time.monotonic()
        return super().get(url, **kwargs)


_caches: dict[str, Cache] = {}
_client: ThrottledClient | None = None
_init_lock = threading.Lock()


def cache(kind: str) -> Cache:
    """Cache for 'dns', 'crtsh' or 'rdap' (same directory, different TTLs)."""
    ttl = {"dns": DNS_TTL_HOURS, "crtsh": CRTSH_TTL_HOURS, "rdap": RDAP_TTL_HOURS}[kind]
    with _init_lock:
        if kind not in _caches:
            _caches[kind] = Cache(CACHE_DIR, enabled=True, ttl_hours=ttl)
        return _caches[kind]


def client() -> ThrottledClient:
    global _client
    with _init_lock:
        if _client is None:
            _client = ThrottledClient(user_agent=USER_AGENT)
        return _client


def resolver(timeout: float = 1.0):
    """Recursive resolver (system config). lifetime = 2 x timeout; dns_query adds one TCP retry."""
    return make_resolver(None, timeout)


def configure(cache_dir: Path | None = None) -> None:
    """Point the caches somewhere else (tests). None restores data/cache/."""
    global CACHE_DIR
    with _init_lock:
        CACHE_DIR = Path(cache_dir) if cache_dir else ROOT / "data" / "cache"
        _caches.clear()
