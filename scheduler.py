"""Background re-scan scheduler (APScheduler if available, else daemon thread)."""

from __future__ import annotations

import logging
import threading
from typing import Callable

log = logging.getLogger("domain-brand-alert.scheduler")

_scheduler = None
_thread: threading.Thread | None = None
_stop = threading.Event()
_scan_fn: Callable[[], None] | None = None
_poll_seconds = 60


def _tick() -> None:
    if _scan_fn is None:
        return
    try:
        _scan_fn()
    except Exception:  # noqa: BLE001
        log.exception("Scheduled scan tick failed")


def _thread_loop() -> None:
    while not _stop.wait(_poll_seconds):
        _tick()


def start(scan_due_watches: Callable[[], None], poll_seconds: int = 60) -> str:
    """Start scheduler. Returns backend name used."""
    global _scheduler, _thread, _scan_fn, _poll_seconds
    _scan_fn = scan_due_watches
    _poll_seconds = max(15, int(poll_seconds))

    try:
        from apscheduler.schedulers.background import BackgroundScheduler

        if _scheduler is not None:
            return "apscheduler"
        _scheduler = BackgroundScheduler(timezone="UTC")
        _scheduler.add_job(
            _tick,
            "interval",
            seconds=_poll_seconds,
            id="watch_rescan",
            replace_existing=True,
            max_instances=1,
            coalesce=True,
        )
        _scheduler.start()
        log.info("APScheduler started (every %ss)", _poll_seconds)
        return "apscheduler"
    except Exception as exc:  # noqa: BLE001
        log.warning("APScheduler unavailable (%s); using background thread", exc)
        if _thread and _thread.is_alive():
            return "thread"
        _stop.clear()
        _thread = threading.Thread(target=_thread_loop, name="watch-rescan", daemon=True)
        _thread.start()
        return "thread"


def stop() -> None:
    global _scheduler, _thread
    _stop.set()
    if _scheduler is not None:
        try:
            _scheduler.shutdown(wait=False)
        except Exception:  # noqa: BLE001
            pass
        _scheduler = None
    _thread = None


def status() -> dict:
    backend = "stopped"
    running = False
    if _scheduler is not None:
        backend = "apscheduler"
        running = bool(getattr(_scheduler, "running", False))
    elif _thread is not None and _thread.is_alive():
        backend = "thread"
        running = True
    return {
        "backend": backend,
        "running": running,
        "poll_seconds": _poll_seconds,
    }
