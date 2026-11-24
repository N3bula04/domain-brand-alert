# Changelog

## 0.5.0 (2026-11-24)

- Split findings into priority and confidence, with a trigger, evidence that would change the assessment, and a next analyst action.
- Enrich lookalike assessments with related infrastructure in demo scans and after live mapping jobs. Treat shared providers and registrars as weak leads.
- Retain severity as a compatibility rollup of priority for existing counts, filters, fingerprints, and exports.

## 0.4.0 (2026-10-01)

First public release. Demo-mode findings and sample outputs use a fictional brand
on the reserved `.test` TLD and documentation IP ranges only. The dashboard is
served at `/` (also `/app` and `/dashboard`).

### Added
- **Related infrastructure** panel for each watch, built from public data only. For each resolving lookalike in the latest scan it shows:
  - A/AAAA, NS and MX records, plus reverse DNS for each address
  - the RDAP network holder for each address and the RDAP registrar for the domain
  - other names on the same certificates (crt.sh)
  - overlaps with the brand's own domain: same IP, same nameserver, same registrar, or a certificate naming a brand host

  A **shared CDN/hosting** flag plays an overlap down when the shared thing is a published CDN range, a bulk-hosting netblock, a managed DNS service or a parking service. Registrar matches are always weak.
- Mapping runs as a capped background job on a single worker thread. Results are stored in the new `related_jobs` table. A job runs automatically after a watch scan with lookalikes (at most every 6 h) or on demand (`POST /api/watches/{id}/related`). Jobs left queued or running by a restart are marked `interrupted`.
- Demo watches map synthetic fixtures (fictional names, documentation IP ranges) and make no network lookups. Synthetic findings are never looked up live.
- The evidence pack's `metadata.json` includes the latest related-infrastructure result.
- pytest suite with offline fixtures and a fake local HTTP server, plus GitHub Actions CI on Python 3.10 and 3.12.

### Changed
- `scanners/dns_check.py`, `ct_check.py` and `rdap_check.py` now use the shared [osint-collectors](https://github.com/N3bula04/osint-collectors) v0.1.0 package (`requests` + `dnspython`) instead of `httpx`. Their return shapes and finding titles are unchanged, so existing "new since last scan" fingerprints still match.
- RDAP uses rdap.org with the IANA bootstrap fallback, replacing the hard-coded list of eight TLD servers.
- Lookups are cached in `data/cache/` (DNS 1 h, crt.sh 6 h, RDAP 24 h). Requests are spaced across threads (crt.sh 2 s, RDAP 1 s) and capped per scan and per job. HTTP 429 starts a stored back-off instead of being retried.
- DNS: when a name returns NXDOMAIN for A, AAAA and CNAME are no longer queried.
- Scans triggered from the API run in a worker thread instead of blocking the event loop.
- `httpx` is still a dependency: the webhook POST and FastAPI's TestClient use it.

### Note
- Installing now needs `git`. The shared collectors are installed from the public `osint-collectors` repo at tag `v0.1.0`.

## 0.3.0 and earlier

Watchlist, scheduler, allowlist, diffs, digest, webhooks and evidence packs. See the feature list in the README.
