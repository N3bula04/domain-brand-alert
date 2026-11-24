"""
Domain & Brand Alert — local personal demo (v0.4.0).

Public-data only: Certificate Transparency (crt.sh), DNS, RDAP/WHOIS, collected
through the shared osint-collectors package. Not enterprise threat intel.

The collectors are synchronous (requests + dnspython), so routes run scans in
Starlette's worker threadpool and related-infrastructure mapping runs on a
single background worker thread; nothing blocking runs on the event loop.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import threading
import zipfile
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

import httpx
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

import scheduler as watch_scheduler
import storage
from scanners.ct_check import check_certificate_transparency
from scanners.demo_data import synthetic_findings
from scanners.dns_check import check_lookalike_dns, check_primary_dns
from scanners.rdap_check import check_registration
from scanners.related_demo import build_demo_fixtures
from scanners.related_infra import FixtureSources, LiveSources, map_related

ROOT = Path(__file__).resolve().parent
VERSION = "0.4.0"
log = logging.getLogger("domain-brand-alert")

# In-memory last scan for export convenience
_LAST_SCAN: dict[str, Any] = {}
_SCAN_LOCK = threading.Lock()

# Related-infrastructure mapping: one worker thread, so at most one job runs at a time
# (on top of the per-job caps in scanners/collect.py).
_RELATED_EXECUTOR = ThreadPoolExecutor(max_workers=1, thread_name_prefix="related-infra")
_RELATED_ENQUEUE_LOCK = threading.Lock()
RELATED_AUTO_MIN_HOURS = 6  # automatic re-mapping after a watch scan at most this often


class ScanRequest(BaseModel):
    brand: str = Field(..., min_length=1, max_length=80, examples=["Example"])
    domain: str = Field(..., min_length=3, max_length=120, examples=["example.com"])
    mode: Literal["live", "demo", "auto"] = "auto"
    lookalike_limit: int = Field(50, ge=5, le=200)


class WatchCreate(BaseModel):
    brand: str = Field(..., min_length=1, max_length=80)
    domain: str = Field(..., min_length=3, max_length=120)
    mode: Literal["live", "demo", "auto"] = "auto"
    lookalike_limit: int = Field(50, ge=5, le=200)
    interval_minutes: int = Field(60, ge=5, le=10080)
    scan_now: bool = True
    webhook_url: str | None = Field(None, max_length=500)


class WatchUpdate(BaseModel):
    mode: Literal["live", "demo", "auto"] | None = None
    lookalike_limit: int | None = Field(None, ge=5, le=200)
    interval_minutes: int | None = Field(None, ge=5, le=10080)
    paused: bool | None = None
    webhook_url: str | None = Field(None, max_length=500)


class AllowlistCreate(BaseModel):
    domain: str = Field(..., min_length=1, max_length=120)
    watch_id: int | None = None  # None = global
    note: str | None = Field(None, max_length=200)


def _normalize_domain(domain: str) -> str:
    d = domain.strip().lower()
    d = d.removeprefix("http://").removeprefix("https://")
    d = d.split("/")[0].split(":")[0]
    if d.startswith("www."):
        d = d[4:]
    return d


def run_scan(brand: str, domain: str, mode: str = "auto", lookalike_limit: int = 50) -> dict[str, Any]:
    brand = brand.strip()
    domain = _normalize_domain(domain)
    started = datetime.now(timezone.utc).isoformat()
    findings: list[dict[str, Any]] = []
    notes: list[str] = []
    used_mode = mode

    if mode == "demo":
        findings = synthetic_findings(brand, domain)
        notes.append("Demo mode: synthetic findings only (no live network queries).")
        used_mode = "demo"
    else:
        try:
            findings.extend(check_primary_dns(domain))
        except Exception as exc:  # noqa: BLE001
            notes.append(f"DNS primary check error: {exc}")

        try:
            findings.extend(check_lookalike_dns(domain, brand=brand, limit=lookalike_limit))
        except Exception as exc:  # noqa: BLE001
            notes.append(f"DNS lookalike check error: {exc}")

        try:
            findings.extend(check_certificate_transparency(domain, brand=brand))
        except Exception as exc:  # noqa: BLE001
            notes.append(f"CT check error: {exc}")

        try:
            findings.extend(check_registration(domain))
        except Exception as exc:  # noqa: BLE001
            notes.append(f"RDAP/WHOIS check error: {exc}")

        used_mode = "live"

        if mode == "auto":
            real = [f for f in findings if not (f.get("raw") or {}).get("demo")]
            usable = [
                f
                for f in real
                if f.get("severity") in ("warn", "high")
                or (f.get("source", "").startswith("Certificate") and "unavailable" not in f.get("title", "").lower())
                or f.get("source") in ("RDAP", "WHOIS", "DNS")
            ]
            ct_fail = any("unavailable" in f.get("title", "").lower() for f in findings)
            no_lookalikes = not any(f.get("source") == "DNS lookalike" for f in findings)
            if ct_fail and no_lookalikes and len(usable) <= 2:
                notes.append(
                    "Live sources returned sparse results; appending synthetic demo findings for UI walkthrough."
                )
                findings.extend(synthetic_findings(brand, domain))
                used_mode = "auto+demo"

    order = {"high": 0, "warn": 1, "info": 2}
    findings.sort(key=lambda f: (order.get(f.get("severity", "info"), 9), f.get("source", ""), f.get("title", "")))

    counts = {
        "high": sum(1 for f in findings if f.get("severity") == "high"),
        "warn": sum(1 for f in findings if f.get("severity") == "warn"),
        "info": sum(1 for f in findings if f.get("severity") == "info"),
        "total": len(findings),
    }

    return {
        "brand": brand,
        "domain": domain,
        "mode": used_mode,
        "started_at": started,
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "counts": counts,
        "notes": notes,
        "findings": findings,
        "disclaimer": (
            "Personal project demo using public DNS, Certificate Transparency (crt.sh), "
            "and RDAP/WHOIS only. Not enterprise threat intelligence. Expect false positives."
        ),
    }


# ---- Related infrastructure (background job) ----

def _lookalike_targets(scan_result: dict[str, Any]) -> tuple[list[str], str]:
    """Lookalike domains from a stored scan, highest severity first, plus the job mode.

    Synthetic (demo) findings are only ever mapped against synthetic fixtures,
    never looked up live.
    """
    order = {"high": 0, "warn": 1, "info": 2}
    found = [
        f for f in (scan_result.get("findings") or [])
        if f.get("source") == "DNS lookalike" and not f.get("suppressed") and f.get("target")
    ]
    found.sort(key=lambda f: order.get(f.get("severity", "info"), 9))
    real = [f for f in found if not (f.get("raw") or {}).get("demo")]
    if scan_result.get("mode") == "demo" or (found and not real):
        return [f["target"] for f in found], "demo"
    return [f["target"] for f in real], "live"


def _run_related_job(job_id: int, watch_id: int) -> None:
    storage.update_related_job(job_id, status="running", started_at=datetime.now(timezone.utc).isoformat())
    try:
        watch = storage.get_watch(watch_id)
        latest = storage.get_latest_scan(watch_id)
        if not watch or not latest:
            raise RuntimeError("watch has no stored scan yet")
        targets, mode = _lookalike_targets(latest["result"])
        if mode == "demo":
            sources = FixtureSources(build_demo_fixtures(watch["domain"], targets))
        else:
            sources = LiveSources()
        result = map_related(watch["domain"], targets, sources)
        result["mode"] = mode
        result["scan_id"] = latest["id"]
        if mode == "demo":
            result["demo_note"] = (
                "Demo watch: everything below is synthetic (fictional names, documentation IP ranges). "
                "No network lookups were made."
            )
        storage.update_related_job(job_id, status="done", mode=mode, result=result,
                                   finished_at=datetime.now(timezone.utc).isoformat())
    except Exception as exc:  # noqa: BLE001
        log.exception("Related-infrastructure job %s failed", job_id)
        storage.update_related_job(job_id, status="error", error=f"{type(exc).__name__}: {exc}",
                                   finished_at=datetime.now(timezone.utc).isoformat())


def enqueue_related(watch: dict[str, Any], trigger: str = "manual") -> dict[str, Any]:
    """Queue a mapping job for the watch's latest scan (or return the one already queued/running)."""
    with _RELATED_ENQUEUE_LOCK:
        active = storage.get_active_related_job(watch["id"])
        if active:
            return active
        latest = storage.get_latest_scan(watch["id"])
        mode = _lookalike_targets(latest["result"])[1] if latest else watch.get("mode", "live")
        job = storage.create_related_job(watch["id"], latest["id"] if latest else None, mode, trigger)
    _RELATED_EXECUTOR.submit(_run_related_job, job["id"], watch["id"])
    return job


def _maybe_auto_related(watch: dict[str, Any], result: dict[str, Any]) -> None:
    """After a watch scan: re-map at most every RELATED_AUTO_MIN_HOURS, and only if there are lookalikes."""
    if not _lookalike_targets(result)[0]:
        return
    last = storage.get_latest_related_job(watch["id"])
    if last and last.get("requested_at"):
        try:
            age_h = (datetime.now(timezone.utc) - datetime.fromisoformat(last["requested_at"])).total_seconds() / 3600
        except ValueError:
            age_h = RELATED_AUTO_MIN_HOURS
        if age_h < RELATED_AUTO_MIN_HOURS and last["status"] != "error":
            return
    enqueue_related(watch, trigger="auto")


def _post_webhook(watch: dict[str, Any], meta: dict[str, Any]) -> dict[str, Any] | None:
    """POST JSON of new findings to watch webhook_url if set. Skip if empty."""
    url = (watch.get("webhook_url") or "").strip()
    if not url:
        return None
    new_findings = meta.get("new_findings") or []
    if not new_findings:
        log.info("Webhook skipped for watch %s: no new findings", watch.get("id"))
        return {"skipped": True, "reason": "no_new_findings"}
    payload = {
        "event": "new_findings",
        "version": VERSION,
        "watch_id": watch["id"],
        "brand": watch["brand"],
        "domain": watch["domain"],
        "scan_id": meta.get("scan_id"),
        "new_count": meta.get("new_count", len(new_findings)),
        "high_new": meta.get("high_new", 0),
        "findings": new_findings,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.post(url, json=payload)
        log.info("Webhook POST %s → %s for watch %s", url, resp.status_code, watch["id"])
        return {"ok": resp.is_success, "status_code": resp.status_code}
    except Exception as exc:  # noqa: BLE001
        log.warning("Webhook POST failed for watch %s: %s", watch.get("id"), exc)
        return {"ok": False, "error": str(exc)}


def _scan_and_save(watch: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Run scan, persist, fire webhook. Returns (result, meta)."""
    result = run_scan(
        watch["brand"],
        watch["domain"],
        mode=watch["mode"],
        lookalike_limit=watch["lookalike_limit"],
    )
    # Apply allowlist filtering for in-memory view too
    kept, suppressed = storage.filter_allowlisted(result.get("findings") or [], watch_id=watch["id"])
    result = {
        **result,
        "findings": kept,
        "suppressed_findings": suppressed,
        "counts": {
            "high": sum(1 for f in kept if f.get("severity") == "high"),
            "warn": sum(1 for f in kept if f.get("severity") == "warn"),
            "info": sum(1 for f in kept if f.get("severity") == "info"),
            "total": len(kept),
            "suppressed": len(suppressed),
        },
    }
    meta = storage.save_scan_result(watch["id"], {**result, "findings": kept + suppressed})
    # Attach is_new onto kept findings from meta
    new_fps = {f.get("fingerprint") for f in (meta.get("new_findings") or [])}
    for f in result["findings"]:
        fp = storage._fingerprint(f)  # noqa: SLF001
        f["is_new"] = fp in new_fps
    webhook = _post_webhook(watch, meta)
    if webhook is not None:
        meta["webhook"] = webhook
    try:
        _maybe_auto_related(watch, result)
    except Exception:  # noqa: BLE001
        log.exception("Could not queue related-infrastructure job for watch %s", watch.get("id"))
    return result, meta


def _scan_due_watches() -> None:
    due = storage.active_watches_due()
    if not due:
        return
    log.info("Scheduler: %d watch(es) due", len(due))
    for w in due:
        try:
            with _SCAN_LOCK:
                result, _meta = _scan_and_save(w)
                global _LAST_SCAN
                _LAST_SCAN = {**result, "watch_id": w["id"]}
            log.info("Scheduled scan done for watch %s (%s)", w["id"], w["domain"])
        except Exception:  # noqa: BLE001
            log.exception("Scheduled scan failed for watch %s", w.get("id"))


@asynccontextmanager
async def lifespan(_app: FastAPI):
    global _RELATED_EXECUTOR
    storage.init_db()
    _RELATED_EXECUTOR = ThreadPoolExecutor(max_workers=1, thread_name_prefix="related-infra")
    backend = watch_scheduler.start(_scan_due_watches, poll_seconds=60)
    log.info("Watch scheduler backend: %s", backend)
    yield
    watch_scheduler.stop()
    _RELATED_EXECUTOR.shutdown(wait=False, cancel_futures=True)


app = FastAPI(
    title="Domain & Brand Alert",
    description="Personal local demo — public DNS / CT / RDAP signals only.",
    version=VERSION,
    lifespan=lifespan,
)
app.mount("/static", StaticFiles(directory=str(ROOT / "static")), name="static")
templates = Jinja2Templates(directory=str(ROOT / "templates"))


# ---- Pages ----

@app.get("/", response_class=HTMLResponse)
@app.get("/app", response_class=HTMLResponse)
@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("index.html", {"request": request, "version": VERSION})


@app.get("/digest", response_class=HTMLResponse)
async def digest_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("digest.html", {"request": request, "version": VERSION})


@app.get("/api/health")
async def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "service": "domain-brand-alert",
        "version": VERSION,
        "scheduler": watch_scheduler.status(),
    }


def _one_off_scan(brand: str, domain: str, mode: str, lookalike_limit: int) -> dict[str, Any]:
    """Blocking one-off scan + global allowlist (runs in a worker thread)."""
    global _LAST_SCAN
    with _SCAN_LOCK:
        result = run_scan(brand, domain, mode=mode, lookalike_limit=lookalike_limit)
        # Apply global allowlist for one-off scans
        kept, suppressed = storage.filter_allowlisted(result.get("findings") or [], watch_id=None)
        result = {
            **result,
            "findings": kept,
            "suppressed_findings": suppressed,
            "counts": {
                "high": sum(1 for f in kept if f.get("severity") == "high"),
                "warn": sum(1 for f in kept if f.get("severity") == "warn"),
                "info": sum(1 for f in kept if f.get("severity") == "info"),
                "total": len(kept),
                "suppressed": len(suppressed),
            },
        }
        _LAST_SCAN = result
    return result


def _watch_scan(watch: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Blocking watch scan (runs in a worker thread)."""
    global _LAST_SCAN
    with _SCAN_LOCK:
        result, meta = _scan_and_save(watch)
        _LAST_SCAN = {**result, "watch_id": watch["id"]}
    return result, meta


@app.post("/api/scan")
async def api_scan(body: ScanRequest) -> JSONResponse:
    result = await run_in_threadpool(_one_off_scan, body.brand, body.domain, body.mode, body.lookalike_limit)
    return JSONResponse(result)


@app.get("/api/scan")
async def api_scan_get(
    brand: str = Query(..., min_length=1),
    domain: str = Query(..., min_length=3),
    mode: Literal["live", "demo", "auto"] = "auto",
    lookalike_limit: int = Query(50, ge=5, le=200),
) -> JSONResponse:
    result = await run_in_threadpool(_one_off_scan, brand, domain, mode, lookalike_limit)
    return JSONResponse(result)


@app.get("/api/export/json")
async def export_json() -> StreamingResponse:
    if not _LAST_SCAN:
        return StreamingResponse(
            io.BytesIO(b'{"error":"No scan yet. Run a scan first."}'),
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=no_scan.json"},
        )
    payload = json.dumps(_LAST_SCAN, indent=2).encode("utf-8")
    domain = _LAST_SCAN.get("domain", "scan").replace(".", "_")
    return StreamingResponse(
        io.BytesIO(payload),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=brand_alert_{domain}.json"},
    )


@app.get("/api/export/csv")
async def export_csv() -> StreamingResponse:
    buf = io.StringIO()
    writer = csv.DictWriter(
        buf,
        fieldnames=["severity", "source", "title", "detail", "target", "timestamp", "why_it_matters", "is_new"],
    )
    writer.writeheader()
    for f in (_LAST_SCAN or {}).get("findings") or []:
        writer.writerow({k: f.get(k, "") for k in writer.fieldnames})
    data = buf.getvalue().encode("utf-8")
    domain = (_LAST_SCAN or {}).get("domain", "scan").replace(".", "_")
    return StreamingResponse(
        io.BytesIO(data),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=brand_alert_{domain}.csv"},
    )


# ---- Watchlist API ----

@app.get("/api/watches")
async def api_list_watches(
    severity: str | None = Query(None, pattern="^(high|warn|new)$"),
) -> JSONResponse:
    return JSONResponse({"watches": storage.dashboard_summary(severity_filter=severity)})


@app.post("/api/watches")
async def api_create_watch(body: WatchCreate) -> JSONResponse:
    domain = _normalize_domain(body.domain)
    watch = storage.add_watch(
        brand=body.brand.strip(),
        domain=domain,
        mode=body.mode,
        lookalike_limit=body.lookalike_limit,
        interval_minutes=body.interval_minutes,
        webhook_url=body.webhook_url,
    )
    scan_meta = None
    result = None
    if body.scan_now:
        watch = storage.get_watch(watch["id"]) or watch
        result, scan_meta = await run_in_threadpool(_watch_scan, watch)
        watch = storage.get_watch(watch["id"]) or watch
    return JSONResponse({"watch": watch, "scan": scan_meta, "result": result})


@app.get("/api/watches/{watch_id}")
async def api_get_watch(
    watch_id: int,
    new_only: bool = Query(False, description="If true, latest findings filtered to is_new only"),
    mark_viewed: bool = Query(False, description="Mark watch as viewed (clears digest)"),
) -> JSONResponse:
    watch = storage.get_watch(watch_id)
    if not watch:
        raise HTTPException(404, "Watch not found")
    latest = storage.get_latest_scan(watch_id)
    history = storage.list_scan_history(watch_id, limit=20)
    if latest and new_only:
        latest = {
            **latest,
            "result": {
                **latest["result"],
                "findings": [
                    f
                    for f in (latest["result"].get("findings") or [])
                    if f.get("is_new") and not f.get("suppressed")
                ],
            },
        }
        # Recount for diff view
        findings = latest["result"]["findings"]
        latest["result"]["counts"] = {
            "high": sum(1 for f in findings if f.get("severity") == "high"),
            "warn": sum(1 for f in findings if f.get("severity") == "warn"),
            "info": sum(1 for f in findings if f.get("severity") == "info"),
            "total": len(findings),
        }
        latest["diff"] = True
    if mark_viewed:
        watch = storage.mark_watch_viewed(watch_id) or watch
    return JSONResponse({
        "watch": {**watch, "paused": bool(watch["paused"])},
        "latest": latest,
        "history": history,
        "allowlist": storage.list_allowlist(watch_id, include_global=True),
    })


@app.patch("/api/watches/{watch_id}")
async def api_update_watch(watch_id: int, body: WatchUpdate) -> JSONResponse:
    if not storage.get_watch(watch_id):
        raise HTTPException(404, "Watch not found")
    fields = body.model_dump(exclude_none=True)
    # Allow clearing webhook with empty string
    raw = body.model_dump()
    if "webhook_url" in raw and raw["webhook_url"] is not None:
        fields["webhook_url"] = raw["webhook_url"]
    if "paused" in fields:
        fields["paused"] = 1 if fields["paused"] else 0
    updated = storage.update_watch(watch_id, **fields)
    return JSONResponse({"watch": {**(updated or {}), "paused": bool((updated or {}).get("paused"))}})


@app.post("/api/watches/{watch_id}/pause")
async def api_pause_watch(watch_id: int) -> JSONResponse:
    if not storage.get_watch(watch_id):
        raise HTTPException(404, "Watch not found")
    updated = storage.set_paused(watch_id, True)
    return JSONResponse({"watch": {**(updated or {}), "paused": True}})


@app.post("/api/watches/{watch_id}/resume")
async def api_resume_watch(watch_id: int) -> JSONResponse:
    if not storage.get_watch(watch_id):
        raise HTTPException(404, "Watch not found")
    updated = storage.set_paused(watch_id, False)
    return JSONResponse({"watch": {**(updated or {}), "paused": False}})


@app.delete("/api/watches/{watch_id}")
async def api_delete_watch(watch_id: int) -> JSONResponse:
    if not storage.delete_watch(watch_id):
        raise HTTPException(404, "Watch not found")
    return JSONResponse({"ok": True, "deleted": watch_id})


@app.post("/api/watches/{watch_id}/scan")
async def api_scan_watch(watch_id: int) -> JSONResponse:
    watch = storage.get_watch(watch_id)
    if not watch:
        raise HTTPException(404, "Watch not found")
    result, meta = await run_in_threadpool(_watch_scan, watch)
    return JSONResponse({"watch_id": watch_id, "scan": meta, "result": result})


@app.get("/api/watches/{watch_id}/related")
async def api_related_get(watch_id: int) -> JSONResponse:
    """Latest related-infrastructure job for the watch (status + stored result)."""
    if not storage.get_watch(watch_id):
        raise HTTPException(404, "Watch not found")
    latest = storage.get_latest_related_job(watch_id)
    done = latest if (latest and latest["status"] == "done") else storage.get_latest_related_job(watch_id, finished_only=True)
    return JSONResponse({"watch_id": watch_id, "job": latest, "last_done": done})


@app.post("/api/watches/{watch_id}/related")
async def api_related_run(watch_id: int) -> JSONResponse:
    """Queue a capped background mapping job (returns the active one if already queued/running)."""
    watch = storage.get_watch(watch_id)
    if not watch:
        raise HTTPException(404, "Watch not found")
    if not storage.get_latest_scan(watch_id):
        raise HTTPException(409, "Run a scan for this watch first")
    job = await run_in_threadpool(enqueue_related, watch, "manual")
    return JSONResponse({"watch_id": watch_id, "job": job}, status_code=202)


@app.get("/api/watches/{watch_id}/history")
async def api_watch_history(watch_id: int, limit: int = Query(20, ge=1, le=100)) -> JSONResponse:
    if not storage.get_watch(watch_id):
        raise HTTPException(404, "Watch not found")
    return JSONResponse({"watch_id": watch_id, "history": storage.list_scan_history(watch_id, limit=limit)})


@app.get("/api/watches/{watch_id}/diff")
async def api_watch_diff(watch_id: int) -> JSONResponse:
    """Surface only NEW (non-suppressed) findings from the latest scan."""
    watch = storage.get_watch(watch_id)
    if not watch:
        raise HTTPException(404, "Watch not found")
    latest = storage.get_latest_scan(watch_id)
    if not latest:
        return JSONResponse({
            "watch_id": watch_id,
            "brand": watch["brand"],
            "domain": watch["domain"],
            "scan_id": None,
            "new_count": 0,
            "findings": [],
        })
    findings = [
        f
        for f in (latest["result"].get("findings") or [])
        if f.get("is_new") and not f.get("suppressed")
    ]
    return JSONResponse({
        "watch_id": watch_id,
        "brand": watch["brand"],
        "domain": watch["domain"],
        "scan_id": latest["id"],
        "finished_at": latest["finished_at"],
        "new_count": len(findings),
        "findings": findings,
        "diff": True,
    })


# ---- Allowlist ----

@app.get("/api/allowlist")
async def api_list_allowlist(
    watch_id: int | None = Query(None),
    include_global: bool = Query(True),
) -> JSONResponse:
    return JSONResponse({"allowlist": storage.list_allowlist(watch_id, include_global=include_global)})


@app.post("/api/allowlist")
async def api_add_allowlist(body: AllowlistCreate) -> JSONResponse:
    if body.watch_id is not None and not storage.get_watch(body.watch_id):
        raise HTTPException(404, "Watch not found")
    try:
        entry = storage.add_allowlist_entry(body.domain, watch_id=body.watch_id, note=body.note)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    return JSONResponse({"entry": entry})


@app.delete("/api/allowlist/{entry_id}")
async def api_delete_allowlist(entry_id: int) -> JSONResponse:
    if not storage.delete_allowlist_entry(entry_id):
        raise HTTPException(404, "Allowlist entry not found")
    return JSONResponse({"ok": True, "deleted": entry_id})


# ---- Digest ----

@app.get("/api/digest")
async def api_digest(
    watch_id: int | None = Query(None),
    mark_viewed: bool = Query(False),
) -> JSONResponse:
    if watch_id is not None and not storage.get_watch(watch_id):
        raise HTTPException(404, "Watch not found")
    return JSONResponse(storage.digest_new_findings(watch_id, mark_viewed=mark_viewed))


@app.post("/api/watches/{watch_id}/viewed")
async def api_mark_viewed(watch_id: int) -> JSONResponse:
    if not storage.get_watch(watch_id):
        raise HTTPException(404, "Watch not found")
    watch = storage.mark_watch_viewed(watch_id)
    return JSONResponse({"watch": watch})


# ---- Evidence pack ----

@app.get("/api/watches/{watch_id}/evidence-pack")
async def api_evidence_pack(watch_id: int) -> StreamingResponse:
    """ZIP handoff pack: metadata JSON, high findings CSV, full findings CSV, README."""
    pack = storage.evidence_pack_data(watch_id)
    if not pack:
        raise HTTPException(404, "Watch not found")

    brand_slug = "".join(c if c.isalnum() else "_" for c in pack["watch"]["brand"])[:40]
    domain_slug = pack["watch"]["domain"].replace(".", "_")
    base = f"evidence_{brand_slug}_{domain_slug}"

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(f"{base}/metadata.json", json.dumps(pack, indent=2))

        # High findings CSV
        high_buf = io.StringIO()
        high_writer = csv.DictWriter(
            high_buf,
            fieldnames=["severity", "source", "title", "detail", "target", "timestamp", "why_it_matters", "is_new"],
        )
        high_writer.writeheader()
        for f in pack["high_findings"]:
            high_writer.writerow({k: f.get(k, "") for k in high_writer.fieldnames})
        zf.writestr(f"{base}/high_findings.csv", high_buf.getvalue())

        # All findings CSV
        all_buf = io.StringIO()
        all_writer = csv.DictWriter(
            all_buf,
            fieldnames=["severity", "source", "title", "detail", "target", "timestamp", "why_it_matters", "is_new"],
        )
        all_writer.writeheader()
        for f in pack["all_findings"]:
            all_writer.writerow({k: f.get(k, "") for k in all_writer.fieldnames})
        zf.writestr(f"{base}/all_findings.csv", all_buf.getvalue())

        # Scan history summary
        hist_buf = io.StringIO()
        hist_writer = csv.DictWriter(
            hist_buf,
            fieldnames=["scan_id", "started_at", "finished_at", "mode", "high", "warn", "info", "total"],
        )
        hist_writer.writeheader()
        for h in pack["scan_history"]:
            c = h.get("counts") or {}
            hist_writer.writerow({
                "scan_id": h.get("id"),
                "started_at": h.get("started_at"),
                "finished_at": h.get("finished_at"),
                "mode": h.get("mode"),
                "high": c.get("high", 0),
                "warn": c.get("warn", 0),
                "info": c.get("info", 0),
                "total": c.get("total", 0),
            })
        zf.writestr(f"{base}/scan_history.csv", hist_buf.getvalue())

        readme = f"""# Evidence Pack — {pack['watch']['brand']} / {pack['watch']['domain']}

Generated: {pack['exported_at']}
Product: Domain & Brand Alert v{pack['version']}

## Contents

- metadata.json — watch config, latest scan metadata, allowlist, high findings
- high_findings.csv — severity=high findings only (client handoff focus)
- all_findings.csv — all non-suppressed findings from latest scan
- scan_history.csv — recent scan timestamps and severity counts

## Sources

Public DNS, Certificate Transparency (crt.sh), RDAP/WHOIS only.
metadata.json also carries the latest related-infrastructure result (if one has been run).
Overlaps there are leads to verify, not proof of common ownership.

## Disclaimer

{pack['disclaimer']}
"""
        zf.writestr(f"{base}/README.txt", readme)

    buf.seek(0)
    filename = f"{base}.zip"
    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/scans/{scan_id}")
async def api_get_scan(
    scan_id: int,
    new_only: bool = Query(False),
) -> JSONResponse:
    scan = storage.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    if new_only:
        findings = [
            f
            for f in (scan["result"].get("findings") or [])
            if f.get("is_new") and not f.get("suppressed")
        ]
        scan = {
            **scan,
            "result": {**scan["result"], "findings": findings},
            "diff": True,
        }
    return JSONResponse(scan)


@app.get("/api/scheduler")
async def api_scheduler() -> JSONResponse:
    return JSONResponse(watch_scheduler.status())


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app:app", host="127.0.0.1", port=8765, reload=False)
