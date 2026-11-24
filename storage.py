"""SQLite persistence for watches, scan history, findings, and allowlists."""

from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from scanners.assessment import ASSESSMENT_FIELDS, enrich_findings_with_related

ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / "data" / "watchlist.db"

_lock = threading.Lock()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextmanager
def get_db() -> Iterator[sqlite3.Connection]:
    with _lock:
        conn = _connect()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()


def _column_exists(conn: sqlite3.Connection, table: str, column: str) -> bool:
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return any(r["name"] == column for r in rows)


def init_db() -> None:
    with get_db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS watches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                brand TEXT NOT NULL,
                domain TEXT NOT NULL,
                mode TEXT NOT NULL DEFAULT 'auto',
                lookalike_limit INTEGER NOT NULL DEFAULT 50,
                interval_minutes INTEGER NOT NULL DEFAULT 60,
                paused INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                last_scan_at TEXT,
                UNIQUE(brand, domain)
            );

            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                watch_id INTEGER NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT NOT NULL,
                mode TEXT NOT NULL,
                counts_json TEXT NOT NULL,
                notes_json TEXT NOT NULL,
                result_json TEXT NOT NULL,
                FOREIGN KEY (watch_id) REFERENCES watches(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                watch_id INTEGER NOT NULL,
                severity TEXT NOT NULL,
                source TEXT,
                title TEXT,
                detail TEXT,
                target TEXT,
                timestamp TEXT,
                why_it_matters TEXT,
                fingerprint TEXT NOT NULL,
                is_new INTEGER NOT NULL DEFAULT 0,
                suppressed INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
                FOREIGN KEY (watch_id) REFERENCES watches(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS allowlist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                watch_id INTEGER,
                domain TEXT NOT NULL,
                note TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (watch_id) REFERENCES watches(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS related_jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                watch_id INTEGER NOT NULL,
                scan_id INTEGER,
                status TEXT NOT NULL,          -- queued / running / done / error / interrupted
                mode TEXT NOT NULL,            -- live / demo
                trigger TEXT NOT NULL,         -- manual / auto
                requested_at TEXT NOT NULL,
                started_at TEXT,
                finished_at TEXT,
                result_json TEXT,
                error TEXT,
                FOREIGN KEY (watch_id) REFERENCES watches(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_related_watch ON related_jobs(watch_id, id DESC);
            CREATE INDEX IF NOT EXISTS idx_scans_watch ON scans(watch_id, finished_at DESC);
            CREATE INDEX IF NOT EXISTS idx_findings_watch ON findings(watch_id, scan_id);
            CREATE INDEX IF NOT EXISTS idx_findings_fp ON findings(watch_id, fingerprint);
            CREATE INDEX IF NOT EXISTS idx_allowlist_watch ON allowlist(watch_id, domain);
            CREATE INDEX IF NOT EXISTS idx_allowlist_domain ON allowlist(domain);
            """
        )
        # Soft migrations for existing DBs
        if not _column_exists(conn, "watches", "webhook_url"):
            conn.execute("ALTER TABLE watches ADD COLUMN webhook_url TEXT")
        if not _column_exists(conn, "watches", "last_viewed_at"):
            conn.execute("ALTER TABLE watches ADD COLUMN last_viewed_at TEXT")
        if not _column_exists(conn, "findings", "suppressed"):
            conn.execute("ALTER TABLE findings ADD COLUMN suppressed INTEGER NOT NULL DEFAULT 0")
        # A process restart abandons any job that was queued or running.
        conn.execute(
            "UPDATE related_jobs SET status = 'interrupted', finished_at = ? WHERE status IN ('queued', 'running')",
            (_now(),),
        )


def _fingerprint(f: dict[str, Any]) -> str:
    return f"{f.get('source','')}|{f.get('title','')}|{f.get('target','')}|{f.get('severity','')}"


def _normalize_allow_domain(domain: str) -> str:
    d = (domain or "").strip().lower()
    d = d.removeprefix("http://").removeprefix("https://")
    d = d.split("/")[0].split(":")[0]
    if d.startswith("www."):
        d = d[4:]
    return d


def allowlist_domains_for_watch(watch_id: int | None = None) -> set[str]:
    """Return domains allowlisted globally and (optionally) for a specific watch."""
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT domain FROM allowlist
            WHERE watch_id IS NULL
               OR (? IS NOT NULL AND watch_id = ?)
            """,
            (watch_id, watch_id),
        ).fetchall()
        return {_normalize_allow_domain(r["domain"]) for r in rows}


def _target_matches_allowlist(target: str | None, allowed: set[str]) -> bool:
    if not target or not allowed:
        return False
    t = _normalize_allow_domain(str(target))
    if not t:
        return False
    if t in allowed:
        return True
    # Also match if target is a subdomain of an allowlisted apex
    for a in allowed:
        if t == a or t.endswith("." + a):
            return True
    return False


def filter_allowlisted(
    findings: list[dict[str, Any]],
    watch_id: int | None = None,
    allowed: set[str] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Split findings into (kept, suppressed)."""
    allowed = allowed if allowed is not None else allowlist_domains_for_watch(watch_id)
    kept: list[dict[str, Any]] = []
    suppressed: list[dict[str, Any]] = []
    for f in findings:
        if _target_matches_allowlist(f.get("target"), allowed):
            suppressed.append({**f, "suppressed": True})
        else:
            kept.append({**f, "suppressed": False})
    return kept, suppressed


def add_watch(
    brand: str,
    domain: str,
    mode: str = "auto",
    lookalike_limit: int = 50,
    interval_minutes: int = 60,
    webhook_url: str | None = None,
) -> dict[str, Any]:
    now = _now()
    wh = (webhook_url or "").strip() or None
    with get_db() as conn:
        try:
            cur = conn.execute(
                """
                INSERT INTO watches
                  (brand, domain, mode, lookalike_limit, interval_minutes, paused,
                   created_at, updated_at, webhook_url)
                VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?)
                """,
                (brand.strip(), domain.strip().lower(), mode, lookalike_limit, interval_minutes, now, now, wh),
            )
            wid = cur.lastrowid
        except sqlite3.IntegrityError:
            row = conn.execute(
                "SELECT * FROM watches WHERE brand = ? AND domain = ?",
                (brand.strip(), domain.strip().lower()),
            ).fetchone()
            if row:
                return dict(row)
            raise
        row = conn.execute("SELECT * FROM watches WHERE id = ?", (wid,)).fetchone()
        return dict(row)


def list_watches() -> list[dict[str, Any]]:
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM watches ORDER BY brand COLLATE NOCASE, domain").fetchall()
        return [dict(r) for r in rows]


def get_watch(watch_id: int) -> dict[str, Any] | None:
    with get_db() as conn:
        row = conn.execute("SELECT * FROM watches WHERE id = ?", (watch_id,)).fetchone()
        return dict(row) if row else None


def update_watch(watch_id: int, **fields: Any) -> dict[str, Any] | None:
    allowed = {
        "mode",
        "lookalike_limit",
        "interval_minutes",
        "paused",
        "brand",
        "domain",
        "webhook_url",
        "last_viewed_at",
    }
    updates = {k: v for k, v in fields.items() if k in allowed}
    if "webhook_url" in updates:
        wh = updates["webhook_url"]
        updates["webhook_url"] = (wh or "").strip() or None
    if not updates:
        return get_watch(watch_id)
    updates["updated_at"] = _now()
    cols = ", ".join(f"{k} = ?" for k in updates)
    vals = list(updates.values()) + [watch_id]
    with get_db() as conn:
        conn.execute(f"UPDATE watches SET {cols} WHERE id = ?", vals)
        row = conn.execute("SELECT * FROM watches WHERE id = ?", (watch_id,)).fetchone()
        return dict(row) if row else None


def delete_watch(watch_id: int) -> bool:
    with get_db() as conn:
        cur = conn.execute("DELETE FROM watches WHERE id = ?", (watch_id,))
        return cur.rowcount > 0


def set_paused(watch_id: int, paused: bool) -> dict[str, Any] | None:
    return update_watch(watch_id, paused=1 if paused else 0)


def mark_watch_viewed(watch_id: int) -> dict[str, Any] | None:
    return update_watch(watch_id, last_viewed_at=_now())


def save_scan_result(watch_id: int, result: dict[str, Any]) -> dict[str, Any]:
    """Persist a scan + findings; mark findings new if fingerprint unseen; suppress allowlisted."""
    allowed = allowlist_domains_for_watch(watch_id)
    with get_db() as conn:
        prev_fps = {
            r["fingerprint"]
            for r in conn.execute(
                "SELECT DISTINCT fingerprint FROM findings WHERE watch_id = ?",
                (watch_id,),
            ).fetchall()
        }
        counts = result.get("counts") or {}
        notes = result.get("notes") or []
        # Persist full result but also annotate allowlist suppression in stored JSON
        kept, suppressed = filter_allowlisted(
            result.get("findings") or [], watch_id=watch_id, allowed=allowed
        )
        annotated = {
            **result,
            "findings": kept + suppressed,
            "counts": {
                "high": sum(1 for f in kept if f.get("severity") == "high"),
                "warn": sum(1 for f in kept if f.get("severity") == "warn"),
                "info": sum(1 for f in kept if f.get("severity") == "info"),
                "total": len(kept),
                "suppressed": len(suppressed),
            },
            "allowlist_suppressed": len(suppressed),
        }
        counts = annotated["counts"]
        cur = conn.execute(
            """
            INSERT INTO scans
              (watch_id, started_at, finished_at, mode, counts_json, notes_json, result_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                watch_id,
                result.get("started_at") or _now(),
                result.get("finished_at") or _now(),
                result.get("mode") or "auto",
                json.dumps(counts),
                json.dumps(notes),
                json.dumps(annotated),
            ),
        )
        scan_id = cur.lastrowid
        new_count = 0
        high_new = 0
        new_findings: list[dict[str, Any]] = []
        for f in kept + suppressed:
            fp = _fingerprint(f)
            is_suppressed = 1 if f.get("suppressed") else 0
            # Older scans classified some resolving variants as high. A related job can
            # also promote a variant after the scan, so recognize that prior state.
            seen = fp in prev_fps
            if f.get("source") == "DNS lookalike" and f.get("priority") == "medium" and not (f.get("raw") or {}).get("demo"):
                seen = seen or _fingerprint({**f, "severity": "high"}) in prev_fps
            is_new = 0 if seen else 1
            if is_new and not is_suppressed:
                new_count += 1
                if f.get("severity") == "high":
                    high_new += 1
                new_findings.append({**f, "is_new": True, "fingerprint": fp})
            conn.execute(
                """
                INSERT INTO findings
                  (scan_id, watch_id, severity, source, title, detail, target,
                   timestamp, why_it_matters, fingerprint, is_new, suppressed)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    watch_id,
                    f.get("severity") or "info",
                    f.get("source"),
                    f.get("title"),
                    f.get("detail"),
                    f.get("target"),
                    f.get("timestamp"),
                    f.get("why_it_matters"),
                    fp,
                    is_new,
                    is_suppressed,
                ),
            )
        finished = result.get("finished_at") or _now()
        conn.execute(
            "UPDATE watches SET last_scan_at = ?, updated_at = ? WHERE id = ?",
            (finished, finished, watch_id),
        )
        return {
            "scan_id": scan_id,
            "watch_id": watch_id,
            "new_count": new_count,
            "high_new": high_new,
            "counts": counts,
            "new_findings": new_findings,
            "suppressed_count": len(suppressed),
        }


def get_latest_scan(watch_id: int) -> dict[str, Any] | None:
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM scans WHERE watch_id = ? ORDER BY id DESC LIMIT 1",
            (watch_id,),
        ).fetchone()
        if not row:
            return None
        data = dict(row)
        data["counts"] = json.loads(data.pop("counts_json"))
        data["notes"] = json.loads(data.pop("notes_json"))
        data["result"] = json.loads(data.pop("result_json"))
        # Enrich findings with is_new / suppressed from findings table
        finding_rows = conn.execute(
            """
            SELECT fingerprint, is_new, suppressed FROM findings WHERE scan_id = ?
            """,
            (data["id"],),
        ).fetchall()
        by_fp = {r["fingerprint"]: r for r in finding_rows}
        for f in data["result"].get("findings") or []:
            fp = _fingerprint(f)
            meta = by_fp.get(fp)
            if meta:
                f["is_new"] = bool(meta["is_new"])
                f["suppressed"] = bool(meta["suppressed"])
        return data


def list_scan_history(watch_id: int, limit: int = 20) -> list[dict[str, Any]]:
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT id, watch_id, started_at, finished_at, mode, counts_json, notes_json
            FROM scans WHERE watch_id = ? ORDER BY id DESC LIMIT ?
            """,
            (watch_id, limit),
        ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["counts"] = json.loads(d.pop("counts_json"))
            d["notes"] = json.loads(d.pop("notes_json"))
            out.append(d)
        return out


def get_scan(scan_id: int) -> dict[str, Any] | None:
    with get_db() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if not row:
            return None
        data = dict(row)
        data["counts"] = json.loads(data.pop("counts_json"))
        data["notes"] = json.loads(data.pop("notes_json"))
        data["result"] = json.loads(data.pop("result_json"))
        finding_rows = conn.execute(
            "SELECT fingerprint, is_new, suppressed FROM findings WHERE scan_id = ?",
            (scan_id,),
        ).fetchall()
        by_fp = {r["fingerprint"]: r for r in finding_rows}
        for f in data["result"].get("findings") or []:
            fp = _fingerprint(f)
            meta = by_fp.get(fp)
            if meta:
                f["is_new"] = bool(meta["is_new"])
                f["suppressed"] = bool(meta["suppressed"])
        return data


def _scan_assessments(conn: sqlite3.Connection, scan_id: int) -> dict:
    row = conn.execute("SELECT result_json FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if not row:
        return {}
    return {
        _fingerprint(f): {key: f[key] for key in ASSESSMENT_FIELDS if key in f}
        for f in json.loads(row["result_json"]).get("findings", [])
    }


def get_scan_findings(
    scan_id: int,
    *,
    new_only: bool = False,
    include_suppressed: bool = False,
) -> list[dict[str, Any]]:
    with get_db() as conn:
        clauses = ["scan_id = ?"]
        params: list[Any] = [scan_id]
        if new_only:
            clauses.append("is_new = 1")
        if not include_suppressed:
            clauses.append("suppressed = 0")
        rows = conn.execute(
            f"""
            SELECT id, scan_id, watch_id, severity, source, title, detail, target,
                   timestamp, why_it_matters, fingerprint, is_new, suppressed
            FROM findings
            WHERE {' AND '.join(clauses)}
            ORDER BY
              CASE severity WHEN 'high' THEN 0 WHEN 'warn' THEN 1 ELSE 2 END,
              id
            """,
            params,
        ).fetchall()
        assessments = _scan_assessments(conn, scan_id)
        return [
            {
                **dict(r),
                **assessments.get(r["fingerprint"], {}),
                "is_new": bool(r["is_new"]),
                "suppressed": bool(r["suppressed"]),
            }
            for r in rows
        ]


def dashboard_summary(severity_filter: str | None = None) -> list[dict[str, Any]]:
    """Watches with last-scan counts and new/high finding tallies (allowlist-aware)."""
    watches = list_watches()
    out: list[dict[str, Any]] = []
    with get_db() as conn:
        for w in watches:
            latest = conn.execute(
                "SELECT * FROM scans WHERE watch_id = ? ORDER BY id DESC LIMIT 1",
                (w["id"],),
            ).fetchone()
            item: dict[str, Any] = {
                **w,
                "paused": bool(w["paused"]),
                "last_scan": None,
                "counts": {"high": 0, "warn": 0, "info": 0, "total": 0, "suppressed": 0},
                "new_count": 0,
                "high_count": 0,
                "high_new": 0,
                "unseen_new_count": 0,
            }
            if latest:
                counts = json.loads(latest["counts_json"])
                item["last_scan"] = {
                    "id": latest["id"],
                    "started_at": latest["started_at"],
                    "finished_at": latest["finished_at"],
                    "mode": latest["mode"],
                }
                item["counts"] = counts
                item["high_count"] = counts.get("high", 0)
                new_row = conn.execute(
                    """
                    SELECT
                      COUNT(*) AS new_count,
                      SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) AS high_new
                    FROM findings
                    WHERE scan_id = ? AND is_new = 1 AND suppressed = 0
                    """,
                    (latest["id"],),
                ).fetchone()
                item["new_count"] = int(new_row["new_count"] or 0)
                item["high_new"] = int(new_row["high_new"] or 0)

                # Unseen since last view (digest)
                last_viewed = w.get("last_viewed_at")
                if last_viewed:
                    unseen = conn.execute(
                        """
                        SELECT COUNT(*) AS c FROM findings f
                        JOIN scans s ON s.id = f.scan_id
                        WHERE f.watch_id = ? AND f.is_new = 1 AND f.suppressed = 0
                          AND s.finished_at > ?
                        """,
                        (w["id"], last_viewed),
                    ).fetchone()
                    item["unseen_new_count"] = int(unseen["c"] or 0)
                else:
                    item["unseen_new_count"] = item["new_count"]
            if severity_filter == "high" and item["high_count"] == 0:
                continue
            if severity_filter == "warn" and (item["counts"].get("warn", 0) + item["high_count"]) == 0:
                continue
            if severity_filter == "new" and item["new_count"] == 0:
                continue
            out.append(item)
    return out


def active_watches_due(now: datetime | None = None) -> list[dict[str, Any]]:
    """Return non-paused watches whose interval has elapsed (or never scanned)."""
    now = now or datetime.now(timezone.utc)
    due: list[dict[str, Any]] = []
    for w in list_watches():
        if w["paused"]:
            continue
        last = w.get("last_scan_at")
        if not last:
            due.append(w)
            continue
        try:
            last_dt = datetime.fromisoformat(last)
            if last_dt.tzinfo is None:
                last_dt = last_dt.replace(tzinfo=timezone.utc)
        except ValueError:
            due.append(w)
            continue
        elapsed_min = (now - last_dt).total_seconds() / 60.0
        if elapsed_min >= float(w["interval_minutes"]):
            due.append(w)
    return due


# ---- Allowlist CRUD ----

def list_allowlist(watch_id: int | None = None, include_global: bool = True) -> list[dict[str, Any]]:
    with get_db() as conn:
        if watch_id is None:
            rows = conn.execute(
                "SELECT * FROM allowlist WHERE watch_id IS NULL ORDER BY domain COLLATE NOCASE"
            ).fetchall()
        elif include_global:
            rows = conn.execute(
                """
                SELECT * FROM allowlist
                WHERE watch_id IS NULL OR watch_id = ?
                ORDER BY CASE WHEN watch_id IS NULL THEN 0 ELSE 1 END, domain COLLATE NOCASE
                """,
                (watch_id,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM allowlist WHERE watch_id = ? ORDER BY domain COLLATE NOCASE",
                (watch_id,),
            ).fetchall()
        return [dict(r) for r in rows]


def add_allowlist_entry(
    domain: str,
    watch_id: int | None = None,
    note: str | None = None,
) -> dict[str, Any]:
    domain = _normalize_allow_domain(domain)
    if not domain:
        raise ValueError("domain required")
    now = _now()
    with get_db() as conn:
        # Avoid duplicates for same scope
        if watch_id is None:
            existing = conn.execute(
                "SELECT * FROM allowlist WHERE watch_id IS NULL AND domain = ?",
                (domain,),
            ).fetchone()
        else:
            existing = conn.execute(
                "SELECT * FROM allowlist WHERE watch_id = ? AND domain = ?",
                (watch_id, domain),
            ).fetchone()
        if existing:
            return dict(existing)
        cur = conn.execute(
            "INSERT INTO allowlist (watch_id, domain, note, created_at) VALUES (?, ?, ?, ?)",
            (watch_id, domain, (note or "").strip() or None, now),
        )
        row = conn.execute("SELECT * FROM allowlist WHERE id = ?", (cur.lastrowid,)).fetchone()
        return dict(row)


def delete_allowlist_entry(entry_id: int) -> bool:
    with get_db() as conn:
        cur = conn.execute("DELETE FROM allowlist WHERE id = ?", (entry_id,))
        return cur.rowcount > 0


# ---- Digest (new since last view) ----

def digest_new_findings(
    watch_id: int | None = None,
    *,
    mark_viewed: bool = False,
) -> dict[str, Any]:
    """List new, non-suppressed findings since each watch's last_viewed_at (or all new if never viewed)."""
    watches = [get_watch(watch_id)] if watch_id else list_watches()
    watches = [w for w in watches if w]
    items: list[dict[str, Any]] = []
    total_new = 0
    assessments = {}
    with get_db() as conn:
        for w in watches:
            last_viewed = w.get("last_viewed_at")
            if last_viewed:
                rows = conn.execute(
                    """
                    SELECT f.*, s.finished_at AS scan_finished_at, s.id AS scan_id_ref
                    FROM findings f
                    JOIN scans s ON s.id = f.scan_id
                    WHERE f.watch_id = ? AND f.is_new = 1 AND f.suppressed = 0
                      AND s.finished_at > ?
                    ORDER BY
                      CASE f.severity WHEN 'high' THEN 0 WHEN 'warn' THEN 1 ELSE 2 END,
                      s.finished_at DESC, f.id
                    """,
                    (w["id"], last_viewed),
                ).fetchall()
            else:
                # Never viewed: latest scan's new findings
                latest = conn.execute(
                    "SELECT id FROM scans WHERE watch_id = ? ORDER BY id DESC LIMIT 1",
                    (w["id"],),
                ).fetchone()
                if not latest:
                    rows = []
                else:
                    rows = conn.execute(
                        """
                        SELECT f.*, s.finished_at AS scan_finished_at, s.id AS scan_id_ref
                        FROM findings f
                        JOIN scans s ON s.id = f.scan_id
                        WHERE f.scan_id = ? AND f.is_new = 1 AND f.suppressed = 0
                        ORDER BY
                          CASE f.severity WHEN 'high' THEN 0 WHEN 'warn' THEN 1 ELSE 2 END,
                          f.id
                        """,
                        (latest["id"],),
                    ).fetchall()
            for scan_id in {r["scan_id"] for r in rows}:
                assessments[scan_id] = _scan_assessments(conn, scan_id)
            findings = [
                {
                    **{k: r[k] for k in r.keys() if k not in ("is_new", "suppressed")},
                    **assessments[r["scan_id"]].get(r["fingerprint"], {}),
                    "is_new": True,
                    "suppressed": False,
                }
                for r in rows
            ]
            total_new += len(findings)
            items.append(
                {
                    "watch_id": w["id"],
                    "brand": w["brand"],
                    "domain": w["domain"],
                    "last_viewed_at": last_viewed,
                    "new_count": len(findings),
                    "findings": findings,
                }
            )
            if mark_viewed:
                conn.execute(
                    "UPDATE watches SET last_viewed_at = ?, updated_at = ? WHERE id = ?",
                    (_now(), _now(), w["id"]),
                )
    return {
        "generated_at": _now(),
        "total_new": total_new,
        "watches": items,
    }


# ---- Evidence pack helpers ----

def evidence_pack_data(watch_id: int) -> dict[str, Any] | None:
    watch = get_watch(watch_id)
    if not watch:
        return None
    latest = get_latest_scan(watch_id)
    history = list_scan_history(watch_id, limit=10)
    allow = list_allowlist(watch_id, include_global=True)
    high_findings: list[dict[str, Any]] = []
    all_kept: list[dict[str, Any]] = []
    if latest:
        for f in latest["result"].get("findings") or []:
            if f.get("suppressed"):
                continue
            all_kept.append(f)
            if f.get("severity") == "high":
                high_findings.append(f)
    return {
        "exported_at": _now(),
        "product": "Domain & Brand Alert",
        "version": "0.5.0",
        "watch": {
            "id": watch["id"],
            "brand": watch["brand"],
            "domain": watch["domain"],
            "mode": watch["mode"],
            "interval_minutes": watch["interval_minutes"],
            "paused": bool(watch["paused"]),
            "created_at": watch["created_at"],
            "last_scan_at": watch.get("last_scan_at"),
            "webhook_url_set": bool(watch.get("webhook_url")),
        },
        "latest_scan": {
            "id": latest["id"] if latest else None,
            "started_at": latest["started_at"] if latest else None,
            "finished_at": latest["finished_at"] if latest else None,
            "mode": latest["mode"] if latest else None,
            "counts": latest["counts"] if latest else {},
            "notes": latest["notes"] if latest else [],
        }
        if latest
        else None,
        "high_findings": high_findings,
        "all_findings": all_kept,
        "related_infrastructure": (lambda j: {
            "job_id": j["id"], "status": j["status"], "mode": j["mode"],
            "finished_at": j["finished_at"], "result": j.get("result"),
        } if j else None)(get_latest_related_job(watch_id, finished_only=True)),
        "scan_history": history,
        "allowlist": [{"domain": a["domain"], "scope": "global" if a["watch_id"] is None else "watch", "note": a.get("note")} for a in allow],
        "disclaimer": (
            "Personal project demo using public DNS, Certificate Transparency (crt.sh), "
            "and RDAP/WHOIS only. Not enterprise threat intelligence. Expect false positives."
        ),
    }


# ---- Related-infrastructure jobs ----

def _related_row(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if not row:
        return None
    d = dict(row)
    raw = d.pop("result_json", None)
    d["result"] = json.loads(raw) if raw else None
    return d


def create_related_job(watch_id: int, scan_id: int | None, mode: str, trigger: str) -> dict[str, Any]:
    with get_db() as conn:
        cur = conn.execute(
            """
            INSERT INTO related_jobs (watch_id, scan_id, status, mode, trigger, requested_at)
            VALUES (?, ?, 'queued', ?, ?, ?)
            """,
            (watch_id, scan_id, mode, trigger, _now()),
        )
        row = conn.execute("SELECT * FROM related_jobs WHERE id = ?", (cur.lastrowid,)).fetchone()
        return _related_row(row) or {}


def update_related_job(job_id: int, **fields: Any) -> None:
    allowed = {"status", "started_at", "finished_at", "error", "mode"}
    updates = {k: v for k, v in fields.items() if k in allowed}
    if "result" in fields:
        updates["result_json"] = json.dumps(fields["result"])
    if not updates:
        return
    cols = ", ".join(f"{k} = ?" for k in updates)
    with get_db() as conn:
        conn.execute(f"UPDATE related_jobs SET {cols} WHERE id = ?", list(updates.values()) + [job_id])


def complete_related_job(job_id: int, scan_id: int, mode: str, related: dict) -> dict | None:
    """Persist a completed map and its assessments in the same transaction."""
    with get_db() as conn:
        row = conn.execute("SELECT result_json FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if not row:
            return None
        result = json.loads(row["result_json"])
        findings = result["findings"]
        before = [_fingerprint(f) for f in findings]
        enrich_findings_with_related(findings, related, reassess=(mode == "live"))
        for old_fp, finding in zip(before, findings):
            new_fp = _fingerprint(finding)
            if new_fp != old_fp:
                conn.execute(
                    "UPDATE findings SET severity = ?, fingerprint = ? WHERE scan_id = ? AND fingerprint = ?",
                    (finding["severity"], new_fp, scan_id, old_fp),
                )
        counts = result["counts"]
        for severity in ("high", "warn", "info"):
            counts[severity] = sum(f["severity"] == severity for f in findings if not f.get("suppressed"))
        conn.execute(
            "UPDATE scans SET result_json = ?, counts_json = ? WHERE id = ?",
            (json.dumps(result), json.dumps(counts), scan_id),
        )
        conn.execute(
            "UPDATE related_jobs SET status = 'done', mode = ?, result_json = ?, finished_at = ? WHERE id = ?",
            (mode, json.dumps(related), _now(), job_id),
        )
        return counts


def get_related_job(job_id: int) -> dict[str, Any] | None:
    with get_db() as conn:
        return _related_row(conn.execute("SELECT * FROM related_jobs WHERE id = ?", (job_id,)).fetchone())


def get_latest_related_job(watch_id: int, finished_only: bool = False) -> dict[str, Any] | None:
    q = "SELECT * FROM related_jobs WHERE watch_id = ?"
    if finished_only:
        q += " AND status = 'done'"
    q += " ORDER BY id DESC LIMIT 1"
    with get_db() as conn:
        return _related_row(conn.execute(q, (watch_id,)).fetchone())


def get_active_related_job(watch_id: int) -> dict[str, Any] | None:
    with get_db() as conn:
        return _related_row(conn.execute(
            "SELECT * FROM related_jobs WHERE watch_id = ? AND status IN ('queued', 'running') ORDER BY id DESC LIMIT 1",
            (watch_id,),
        ).fetchone())
