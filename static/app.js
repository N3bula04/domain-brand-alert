/* Domain & Brand Alert v0.4 — dashboard + allowlist + diff + evidence pack + related infrastructure */

const panels = {
  dashboard: document.getElementById("panel-dashboard"),
  scan: document.getElementById("panel-scan"),
  detail: document.getElementById("panel-detail"),
};

let currentWatchId = null;
let detailNewOnly = false;

function escapeHtml(s) {
  return String(s ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function formatTs(iso) {
  if (!iso) return "—";
  try {
    const d = new Date(iso);
    return d.toLocaleString("en-SG", { timeZone: "Asia/Singapore" }) + " SGT";
  } catch {
    return iso;
  }
}

function severityRank(s) {
  return { high: 0, warn: 1, info: 2 }[s] ?? 9;
}

function showPanel(name) {
  Object.entries(panels).forEach(([k, el]) => {
    el.classList.toggle("hidden", k !== name);
  });
  document.querySelectorAll(".tab").forEach((btn) => {
    const active = btn.dataset.tab === name;
    btn.classList.toggle("active", active);
    btn.setAttribute("aria-selected", active ? "true" : "false");
    if (btn.dataset.tab === "detail") {
      btn.disabled = !currentWatchId;
    }
  });
}

document.querySelectorAll(".tab").forEach((btn) => {
  btn.addEventListener("click", () => {
    if (btn.disabled) return;
    showPanel(btn.dataset.tab);
    if (btn.dataset.tab === "dashboard") loadDashboard();
  });
});

/* ---- Findings render (shared) ---- */

function renderFindings(data, opts = {}) {
  const summaryEl = opts.summaryEl || document.getElementById("summary");
  const resultsEl = opts.resultsEl || document.getElementById("results");
  const statusEl = opts.statusEl || document.getElementById("status");

  const c = data.counts || {};
  summaryEl.classList.remove("hidden");
  summaryEl.innerHTML = `
    <div class="stat high"><div class="n">${c.high ?? 0}</div><div class="l">High priority</div></div>
    <div class="stat warn"><div class="n">${c.warn ?? 0}</div><div class="l">Medium priority</div></div>
    <div class="stat info"><div class="n">${c.info ?? 0}</div><div class="l">Low priority</div></div>
    <div class="stat"><div class="n">${c.total ?? 0}</div><div class="l">Total · mode ${escapeHtml(data.mode || "?")}${data.diff ? " · <span class='pill new'>diff</span>" : ""}${c.suppressed ? ` · ${c.suppressed} suppressed` : ""}</div></div>
  `;

  const notes = (data.notes || []).map((n) => `<p class="why">Note: ${escapeHtml(n)}</p>`).join("");
  const disclaimer = data.disclaimer
    ? `<p class="why">${escapeHtml(data.disclaimer)}</p>`
    : "";

  let findings = (data.findings || [])
    .filter((f) => !f.suppressed)
    .slice()
    .sort((a, b) => severityRank(a.severity) - severityRank(b.severity));
  if (opts.severityFilter) {
    findings = findings.filter((f) => f.severity === opts.severityFilter);
  }
  if (opts.newOnly) {
    findings = findings.filter((f) => f.is_new);
  }

  resultsEl.innerHTML =
    notes +
    disclaimer +
    (findings.length
      ? findings
          .map((f) => {
            const sev = escapeHtml(f.severity || "info");
            const priority = f.priority || ({high: "high", warn: "medium", info: "low"}[f.severity] || "low");
            const isNew = f.is_new ? `<span class="pill new">new</span>` : "";
            return `
        <article class="finding ${sev}${f.is_new ? " is-new" : ""}">
          <div class="finding-head">
            <span class="sev ${sev}">Priority · ${escapeHtml(priority)}</span>
            ${f.confidence ? `<span class="sev confidence ${escapeHtml(f.confidence)}">Confidence · ${escapeHtml(f.confidence)}</span>` : ""}
            ${isNew}
            <span class="src">${escapeHtml(f.source || "")}</span>
            <span class="ts">${escapeHtml(formatTs(f.timestamp))}</span>
          </div>
          <h3>${escapeHtml(f.title || "")}</h3>
          <p>${escapeHtml(f.detail || "")}</p>
          <p class="why"><strong>Why it matters:</strong> ${escapeHtml(f.why_it_matters || "")}</p>
          ${f.trigger ? `<p class="assessment"><strong>Triggered by</strong> ${escapeHtml(f.trigger)}</p>` : ""}
          ${f.what_would_change ? `<p class="assessment"><strong>What would change this assessment</strong> ${escapeHtml(f.what_would_change)}</p>` : ""}
          ${f.next_action ? `<p class="assessment"><strong>Next action</strong> ${escapeHtml(f.next_action)}</p>` : ""}
          <p class="why">Target: <code>${escapeHtml(f.target || "")}</code>
            ${opts.watchId ? `<button type="button" class="linkish btn-allow" data-target="${escapeHtml(f.target || "")}" data-watch="${opts.watchId}">Allowlist</button>` : ""}
          </p>
        </article>`;
          })
          .join("")
      : `<p class="hint">No findings${opts.newOnly ? " (diff: no new since last scan)" : ""}${opts.severityFilter ? " for this priority filter" : ""}.</p>`);

  resultsEl.querySelectorAll(".btn-allow").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const target = btn.dataset.target;
      const wid = Number(btn.dataset.watch);
      if (!target) return;
      if (!confirm(`Allowlist "${target}" for this watch? Future scans will suppress it.`)) return;
      await fetch("/api/allowlist", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: target, watch_id: wid }),
      });
      openWatch(wid);
    });
  });

  if (statusEl) {
    statusEl.classList.remove("hidden");
    statusEl.textContent = `Scan finished for ${data.brand} / ${data.domain} at ${formatTs(data.finished_at)} (${data.mode}).`;
  }
}

/* ---- Manual scan (preserved) ---- */

const form = document.getElementById("scan-form");
const runBtn = document.getElementById("run-btn");
const demoBtn = document.getElementById("demo-btn");
const statusEl = document.getElementById("status");

function showStatus(msg, busy = false) {
  statusEl.classList.remove("hidden");
  statusEl.textContent = msg;
  runBtn.disabled = busy;
  demoBtn.disabled = busy;
}

async function runScan(payload) {
  showStatus("Scanning public sources… (DNS + crt.sh + RDAP). This can take 15–60s.", true);
  document.getElementById("results").innerHTML = "";
  document.getElementById("summary").classList.add("hidden");
  try {
    const res = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!res.ok) throw new Error((await res.text()) || `HTTP ${res.status}`);
    const data = await res.json();
    renderFindings(data);
  } catch (err) {
    showStatus(`Scan failed: ${err.message || err}`);
  } finally {
    runBtn.disabled = false;
    demoBtn.disabled = false;
  }
}

form.addEventListener("submit", (e) => {
  e.preventDefault();
  runScan({
    brand: document.getElementById("brand").value.trim(),
    domain: document.getElementById("domain").value.trim(),
    mode: document.getElementById("mode").value,
    lookalike_limit: Number(document.getElementById("lookalike_limit").value) || 40,
  });
});

demoBtn.addEventListener("click", () => {
  document.getElementById("brand").value = "Northwind Bakery";
  document.getElementById("domain").value = "northwind-bakery.test";
  document.getElementById("mode").value = "demo";
  runScan({ brand: "Northwind Bakery", domain: "northwind-bakery.test", mode: "demo", lookalike_limit: 40 });
});

document.getElementById("watch-from-scan-btn").addEventListener("click", async () => {
  const payload = {
    brand: document.getElementById("brand").value.trim(),
    domain: document.getElementById("domain").value.trim(),
    mode: document.getElementById("mode").value,
    lookalike_limit: Number(document.getElementById("lookalike_limit").value) || 50,
    interval_minutes: 60,
    scan_now: false,
  };
  try {
    const res = await fetch("/api/watches", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!res.ok) throw new Error(await res.text());
    showStatus(`Added ${payload.brand} / ${payload.domain} to watchlist.`);
    showPanel("dashboard");
    loadDashboard();
  } catch (err) {
    showStatus(`Could not add watch: ${err.message || err}`);
  }
});

/* ---- Dashboard ---- */

const watchGrid = document.getElementById("watch-grid");
const watchEmpty = document.getElementById("watch-empty");

async function loadDashboard() {
  const filter = document.getElementById("severity-filter").value;
  const q = filter ? `?severity=${encodeURIComponent(filter)}` : "";
  try {
    const [wRes, sRes] = await Promise.all([
      fetch(`/api/watches${q}`),
      fetch("/api/scheduler"),
    ]);
    const wData = await wRes.json();
    const sData = await sRes.json();
    document.getElementById("scheduler-status").textContent =
      `Scheduler: ${sData.backend}${sData.running ? " · running" : " · stopped"} · poll ${sData.poll_seconds}s`;
    renderWatchCards(wData.watches || []);
  } catch (err) {
    watchGrid.innerHTML = `<p class="hint">Failed to load watches: ${escapeHtml(err.message || err)}</p>`;
  }
}

function renderWatchCards(watches) {
  watchEmpty.classList.toggle("hidden", watches.length > 0);
  watchGrid.innerHTML = watches
    .map((w) => {
      const counts = w.counts || {};
      const paused = w.paused ? `<span class="pill paused">paused</span>` : `<span class="pill live">active</span>`;
      const newBadge =
        (w.new_count ?? 0) > 0
          ? `<span class="pill new" title="New since last scan">${w.new_count} new</span>`
          : "";
      const unseen =
        (w.unseen_new_count ?? 0) > 0
          ? `<span class="pill unseen" title="Unseen since last view">${w.unseen_new_count} unseen</span>`
          : "";
      return `
      <article class="watch-card ${w.paused ? "is-paused" : ""} ${(w.new_count ?? 0) > 0 ? "has-new" : ""}" data-id="${w.id}" id="watch-${w.id}">
        <div class="watch-top">
          <div>
            <h3>${escapeHtml(w.brand)} ${newBadge} ${unseen}</h3>
            <p class="domain"><code>${escapeHtml(w.domain)}</code></p>
          </div>
          ${paused}
        </div>
        <div class="watch-stats">
          <span class="chip high">${counts.high ?? 0} high priority</span>
          <span class="chip warn">${counts.warn ?? 0} medium priority</span>
          <span class="chip new">${w.new_count ?? 0} new</span>
          <span class="chip">${counts.total ?? 0} total</span>
        </div>
        <p class="muted small">Last scan: ${escapeHtml(formatTs(w.last_scan_at || (w.last_scan && w.last_scan.finished_at)))}</p>
        <p class="muted small">Every ${w.interval_minutes} min · mode ${escapeHtml(w.mode)}${w.webhook_url ? " · webhook on" : ""}</p>
        <div class="actions tight">
          <button type="button" class="btn-open" data-id="${w.id}">Open</button>
          <button type="button" class="secondary btn-rescan" data-id="${w.id}">Re-scan</button>
          <a class="linkbtn" href="/api/watches/${w.id}/evidence-pack">Evidence pack</a>
          <button type="button" class="secondary btn-toggle" data-id="${w.id}" data-paused="${w.paused ? 1 : 0}">
            ${w.paused ? "Resume" : "Pause"}
          </button>
          <button type="button" class="danger secondary btn-delete" data-id="${w.id}">Remove</button>
        </div>
      </article>`;
    })
    .join("");

  watchGrid.querySelectorAll(".btn-open").forEach((b) =>
    b.addEventListener("click", () => openWatch(Number(b.dataset.id)))
  );
  watchGrid.querySelectorAll(".btn-rescan").forEach((b) =>
    b.addEventListener("click", () => rescanWatch(Number(b.dataset.id), b))
  );
  watchGrid.querySelectorAll(".btn-toggle").forEach((b) =>
    b.addEventListener("click", () => togglePause(Number(b.dataset.id), b.dataset.paused === "1"))
  );
  watchGrid.querySelectorAll(".btn-delete").forEach((b) =>
    b.addEventListener("click", () => deleteWatch(Number(b.dataset.id)))
  );
}

document.getElementById("severity-filter").addEventListener("change", loadDashboard);
document.getElementById("watch-refresh-btn").addEventListener("click", loadDashboard);

document.getElementById("watch-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = document.getElementById("watch-add-btn");
  btn.disabled = true;
  btn.textContent = "Scanning…";
  try {
    const payload = {
      brand: document.getElementById("w-brand").value.trim(),
      domain: document.getElementById("w-domain").value.trim(),
      mode: document.getElementById("w-mode").value,
      interval_minutes: Number(document.getElementById("w-interval").value) || 60,
      lookalike_limit: Number(document.getElementById("w-limit").value) || 50,
      webhook_url: document.getElementById("w-webhook").value.trim() || null,
      scan_now: true,
    };
    const res = await fetch("/api/watches", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!res.ok) throw new Error(await res.text());
    const data = await res.json();
    await loadDashboard();
    if (data.watch && data.watch.id) openWatch(data.watch.id);
  } catch (err) {
    alert(`Add watch failed: ${err.message || err}`);
  } finally {
    btn.disabled = false;
    btn.textContent = "Add & scan now";
  }
});

async function togglePause(id, currentlyPaused) {
  const path = currentlyPaused ? "resume" : "pause";
  await fetch(`/api/watches/${id}/${path}`, { method: "POST" });
  loadDashboard();
}

async function deleteWatch(id) {
  if (!confirm("Remove this watch and its scan history?")) return;
  await fetch(`/api/watches/${id}`, { method: "DELETE" });
  if (currentWatchId === id) {
    currentWatchId = null;
    showPanel("dashboard");
  }
  loadDashboard();
}

async function rescanWatch(id, btn) {
  if (btn) {
    btn.disabled = true;
    btn.textContent = "Scanning…";
  }
  try {
    const res = await fetch(`/api/watches/${id}/scan`, { method: "POST" });
    if (!res.ok) throw new Error(await res.text());
    await openWatch(id);
    loadDashboard();
  } catch (err) {
    alert(`Re-scan failed: ${err.message || err}`);
  } finally {
    if (btn) {
      btn.disabled = false;
      btn.textContent = "Re-scan";
    }
  }
}

/* ---- Brand detail ---- */

function renderAllowlist(allowlist, watchId) {
  const el = document.getElementById("detail-allowlist");
  el.classList.remove("hidden");
  el.innerHTML = `
    <h3 class="section-title">Allowlist</h3>
    <p class="hint">Suppressed domains (this watch + global). Matching finding targets are hidden from alerts.</p>
    <form id="allow-form" class="allow-form">
      <input id="allow-domain" type="text" placeholder="domain to allowlist" required maxlength="120" />
      <label class="inline checkbox">
        <input type="checkbox" id="allow-global" /> Global
      </label>
      <button type="submit">Add</button>
    </form>
    <ul class="allow-list">
      ${(allowlist || [])
        .map(
          (a) => `
        <li>
          <code>${escapeHtml(a.domain)}</code>
          <span class="chip">${a.watch_id == null ? "global" : "watch"}</span>
          ${a.note ? `<span class="muted small">${escapeHtml(a.note)}</span>` : ""}
          <button type="button" class="secondary danger btn-allow-del" data-id="${a.id}">Remove</button>
        </li>`
        )
        .join("") || "<li class='muted small'>No allowlist entries yet.</li>"}
    </ul>
  `;
  document.getElementById("allow-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const domain = document.getElementById("allow-domain").value.trim();
    const global = document.getElementById("allow-global").checked;
    await fetch("/api/allowlist", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ domain, watch_id: global ? null : watchId }),
    });
    openWatch(watchId);
  });
  el.querySelectorAll(".btn-allow-del").forEach((b) =>
    b.addEventListener("click", async () => {
      await fetch(`/api/allowlist/${b.dataset.id}`, { method: "DELETE" });
      openWatch(watchId);
    })
  );
}

async function openWatch(id) {
  currentWatchId = id;
  document.getElementById("tab-detail").disabled = false;
  showPanel("detail");

  const header = document.getElementById("detail-header");
  const status = document.getElementById("detail-status");
  const summary = document.getElementById("detail-summary");
  const history = document.getElementById("detail-history");
  const results = document.getElementById("detail-results");

  status.classList.remove("hidden");
  status.textContent = "Loading watch…";
  summary.classList.add("hidden");
  results.innerHTML = "";
  history.innerHTML = "";

  try {
    const q = detailNewOnly ? "?new_only=true" : "";
    const res = await fetch(`/api/watches/${id}${q}`);
    if (!res.ok) throw new Error(await res.text());
    const data = await res.json();
    const viewed = await fetch(`/api/watches/${id}/viewed`, { method: "POST" });
    if (!viewed.ok) throw new Error(await viewed.text());
    const w = data.watch;
    let latest = data.latest;

    header.innerHTML = `
      <div class="detail-head-row">
        <div>
          <h2>${escapeHtml(w.brand)} <span class="muted">/ ${escapeHtml(w.domain)}</span></h2>
          <p class="muted small">
            ${w.paused ? "Paused" : "Active"} · every ${w.interval_minutes} min · mode ${escapeHtml(w.mode)}
            · lookalike limit ${w.lookalike_limit}
          </p>
        </div>
        <div class="actions tight">
          <button type="button" id="detail-rescan">Re-scan now</button>
          <button type="button" class="secondary" id="detail-toggle">${w.paused ? "Resume" : "Pause"}</button>
          <a class="linkbtn" href="/api/watches/${id}/evidence-pack">Evidence pack ZIP</a>
          <a class="linkbtn" href="/api/export/json">Export JSON</a>
          <a class="linkbtn" href="/api/export/csv">Export CSV</a>
          <button type="button" class="secondary" id="detail-back">← Dashboard</button>
        </div>
      </div>
      <div class="row" style="margin-top:0.75rem">
        <label>
          Webhook URL
          <input id="detail-webhook" type="url" maxlength="500"
                 value="${escapeHtml(w.webhook_url || "")}"
                 placeholder="https://… (empty = skip)" />
        </label>
        <div class="actions" style="align-items:flex-end">
          <button type="button" class="secondary" id="detail-save-webhook">Save webhook</button>
        </div>
      </div>
      <div class="toolbar">
        <label class="inline">
          Finding priority
          <select id="detail-sev-filter">
            <option value="">All</option>
            <option value="high">High priority</option>
            <option value="warn">Medium priority</option>
            <option value="info">Low priority</option>
          </select>
        </label>
        <label class="inline checkbox">
          <input type="checkbox" id="detail-diff-only" ${detailNewOnly ? "checked" : ""} />
          Diff only (new since last scan)
        </label>
      </div>
    `;

    document.getElementById("detail-back").onclick = () => {
      showPanel("dashboard");
      loadDashboard();
    };
    document.getElementById("detail-rescan").onclick = () => rescanWatch(id);
    document.getElementById("detail-toggle").onclick = async () => {
      await togglePause(id, !!w.paused);
      openWatch(id);
    };
    document.getElementById("detail-save-webhook").onclick = async () => {
      const url = document.getElementById("detail-webhook").value.trim();
      await fetch(`/api/watches/${id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ webhook_url: url }),
      });
      status.textContent = url ? "Webhook saved." : "Webhook cleared (will skip POSTs).";
    };
    document.getElementById("detail-diff-only").onchange = (e) => {
      detailNewOnly = e.target.checked;
      openWatch(id);
    };

    renderAllowlist(data.allowlist || [], id);
    let selectedScan = latest?.id;

    history.innerHTML = `
      <h3 class="section-title">Scan history</h3>
      <div class="history-list">
        ${(data.history || [])
          .map((h) => {
            const c = h.counts || {};
            return `<button type="button" class="history-item" data-scan="${h.id}">
              <span>${escapeHtml(formatTs(h.finished_at))}</span>
              <span class="chip high">${c.high ?? 0}H</span>
              <span class="chip warn">${c.warn ?? 0}M</span>
              <span class="chip">${c.total ?? 0}</span>
              <span class="muted">${escapeHtml(h.mode)}</span>
            </button>`;
          })
          .join("") || '<p class="hint">No scans yet.</p>'}
      </div>
    `;

    history.querySelectorAll(".history-item").forEach((btn) => {
      btn.addEventListener("click", async () => {
        selectedScan = Number(btn.dataset.scan);
        const scanRes = await fetch(`/api/scans/${btn.dataset.scan}${detailNewOnly ? "?new_only=true" : ""}`);
        const scan = await scanRes.json();
        const result = { ...(scan.result || scan), diff: !!scan.diff || detailNewOnly };
        renderFindings(result, {
          summaryEl: summary,
          resultsEl: results,
          statusEl: status,
          severityFilter: document.getElementById("detail-sev-filter").value || null,
          newOnly: detailNewOnly,
          watchId: id,
        });
      });
    });

    const applyFilter = () => {
      if (!latest || !latest.result) {
        status.textContent = "No scan results yet for this watch.";
        return;
      }
      selectedScan = latest.id;
      const result = { ...latest.result, diff: !!latest.diff || detailNewOnly };
      renderFindings(result, {
        summaryEl: summary,
        resultsEl: results,
        statusEl: status,
        severityFilter: document.getElementById("detail-sev-filter").value || null,
        newOnly: detailNewOnly,
        watchId: id,
      });
    };

    document.getElementById("detail-sev-filter").addEventListener("change", applyFilter);
    applyFilter();
    loadRelated(id, async (scanId) => {
      if (latest?.id !== scanId) return;
      const res = await fetch(`/api/scans/${scanId}${detailNewOnly ? "?new_only=true" : ""}`);
      if (!res.ok) return;
      const updated = await res.json();
      if (currentWatchId !== id || !results.isConnected) return;
      latest = updated;
      if (selectedScan === scanId) applyFilter();
      loadDashboard();
    });
  } catch (err) {
    status.textContent = `Failed to load watch: ${err.message || err}`;
  }
}

/* ---- Related infrastructure (v0.5.0) ---- */

let relatedPollTimer = null;

function relList(items, empty = "—") {
  return items && items.length ? items.map((x) => `<code>${escapeHtml(x)}</code>`).join(" ") : `<span class="muted">${empty}</span>`;
}

function renderRelatedDomain(d) {
  const notable = (d.overlaps || []).filter((o) => o.strength === "notable");
  const weak = (d.overlaps || []).filter((o) => o.strength !== "notable");
  const chips = [
    notable.length ? `<span class="chip warn">${notable.length} overlap${notable.length > 1 ? "s" : ""} to check</span>` : "",
    weak.length ? `<span class="chip">${weak.length} weak overlap${weak.length > 1 ? "s" : ""}</span>` : "",
    (d.shared_flags || []).length ? `<span class="chip shared" title="${escapeHtml(d.shared_flags.join("; "))}">shared CDN/hosting</span>` : "",
    !(d.overlaps || []).length ? `<span class="chip">no overlap with brand</span>` : "",
  ].join(" ");
  const addrRows = (d.addresses || []).map((a) => `
      <tr>
        <td><code>${escapeHtml(a.ip)}</code></td>
        <td>${relList(a.ptr, "no PTR")}</td>
        <td>${escapeHtml((a.network || {}).holder || "—")}<br><span class="muted small">${escapeHtml((a.network || {}).block || "")}</span></td>
        <td>${a.shared ? `<span class="chip shared">shared</span> <span class="muted small">${escapeHtml(a.shared)}</span>` : '<span class="muted small">not on a known shared range</span>'}</td>
      </tr>`).join("");
  const nsRows = (d.ns || []).map((ns) => {
    const sh = (d.nameserver_shared || {})[ns];
    return `<li><code>${escapeHtml(ns)}</code>${sh ? ` <span class="chip shared">shared</span> <span class="muted small">${escapeHtml(sh)}</span>` : ""}</li>`;
  }).join("") || '<li class="muted">—</li>';
  const overlaps = (d.overlaps || []).map((o) => `
      <li class="overlap ${o.strength}">
        <span class="sev ${o.strength === "notable" ? "warn" : "info"}">${o.strength === "notable" ? "check" : "weak"}</span>
        ${escapeHtml(o.label)}: <code>${escapeHtml(o.value)}</code>
        ${o.shared_reason ? `<span class="muted small">(played down: ${escapeHtml(o.shared_reason)})</span>` : ""}
      </li>`).join("") || '<li class="muted">No shared IP, nameserver, registrar or certificate name with the brand.</li>';
  return `
    <details class="related-item">
      <summary><code>${escapeHtml(d.domain)}</code> ${chips}</summary>
      <div class="related-body">
        <h4>Overlaps with the brand</h4>
        <ul class="overlaps">${overlaps}</ul>
        <h4>Addresses (A/AAAA) · reverse DNS · RDAP network holder</h4>
        ${addrRows ? `<table class="rel-table"><thead><tr><th>IP</th><th>Reverse DNS</th><th>Network holder</th><th>Shared?</th></tr></thead><tbody>${addrRows}</tbody></table>` : '<p class="muted small">No A/AAAA records.</p>'}
        <div class="rel-grid">
          <div><h4>Nameservers</h4><ul class="plain">${nsRows}</ul></div>
          <div><h4>Mail (MX)</h4><p>${relList(d.mx)}</p></div>
          <div><h4>Registrar (RDAP)</h4><p>${escapeHtml(d.registrar || "—")}</p></div>
        </div>
        <h4>Other names on the same certificates (crt.sh)</h4>
        <p>${d.cert_count ? `${d.cert_count} certificate(s); ` : ""}${relList(d.cert_names, d.cert_count ? "no other names" : "no certificates found")}${d.cert_names_total > (d.cert_names || []).length ? ` <span class="muted small">+${d.cert_names_total - d.cert_names.length} more</span>` : ""}</p>
        ${(d.notes || []).map((n) => `<p class="muted small">Note: ${escapeHtml(n)}</p>`).join("")}
      </div>
    </details>`;
}

function renderRelated(data, watchId, onComplete) {
  const el = document.getElementById("detail-related");
  el.classList.remove("hidden");
  const job = data.job;
  const done = data.last_done;
  const busy = job && (job.status === "queued" || job.status === "running");
  const r = done && done.result;
  let status = r ? "" : "Not mapped yet. Mapping runs automatically after a scan that finds lookalikes, or use the button.";
  if (busy) status = `Mapping in the background (${escapeHtml(job.status)})…`;
  else if (job && job.status === "error") status = `Last job failed: ${escapeHtml(job.error || "unknown error")}`;
  else if (job && job.status === "interrupted") status = "Last job was interrupted by a restart.";
  const usage = r ? `${r.usage.crtsh_queries}/${r.limits.crtsh_queries} crt.sh · ${r.usage.rdap_requests}/${r.limits.rdap_requests} RDAP lookups (cached answers are free)` : "";
  const b = r ? r.brand : null;
  el.innerHTML = `
    <div class="detail-head-row">
      <div>
        <h3 class="section-title">Related infrastructure</h3>
        <p class="muted small">${r ? `Mapped ${escapeHtml(formatTs(done.finished_at))} · ${escapeHtml(r.mode)} · ${(r.domains || []).length} lookalike(s) (cap ${r.limits.lookalikes}) · ${usage}` : ""}</p>
        ${status ? `<p class="muted small">${status}</p>` : ""}
      </div>
      <div class="actions tight">
        <button type="button" id="related-run" ${busy ? "disabled" : ""}>${r ? "Re-map" : "Map related infrastructure"}</button>
      </div>
    </div>
    ${r && r.demo_note ? `<p class="why demo-note">${escapeHtml(r.demo_note)}</p>` : ""}
    <p class="why">${escapeHtml((r && r.sources_note) || "Public data only: DNS via your resolver, crt.sh, RDAP. No connections to the lookalike's own servers. Overlaps are leads to verify, not proof of common ownership.")}</p>
    ${b ? `<div class="brand-baseline">
      <strong>${escapeHtml(b.domain)}</strong> (your domain):
      IPs ${relList(b.ips)} · NS ${relList(b.ns)} · MX ${relList(b.mx)} · registrar ${escapeHtml(b.registrar || "—")}
    </div>` : ""}
    ${r ? ((r.domains || []).map(renderRelatedDomain).join("") || '<p class="hint">No resolving lookalikes in the latest scan, so there is nothing to map.</p>') : ""}
    ${r && (r.not_mapped || []).length ? `<p class="muted small">Not mapped (per-job cap of ${r.limits.lookalikes}): ${r.not_mapped.map(escapeHtml).join(", ")}</p>` : ""}
    ${r && (r.log || []).length ? `<details class="related-log"><summary class="muted small">${r.log.length} lookup note(s): errors, skips, caps</summary><ul class="plain small">${r.log.map((l) => `<li>${escapeHtml(l.source)} ${escapeHtml(l.query)}: ${escapeHtml(l.status)} (${escapeHtml(l.detail)})</li>`).join("")}</ul></details>` : ""}
  `;
  document.getElementById("related-run").onclick = async () => {
    const res = await fetch(`/api/watches/${watchId}/related`, { method: "POST" });
    if (!res.ok) {
      alert(`Could not start mapping: ${await res.text()}`);
      return;
    }
    loadRelated(watchId, onComplete);
  };
  clearTimeout(relatedPollTimer);
  if (busy && currentWatchId === watchId) {
    relatedPollTimer = setTimeout(() => loadRelated(watchId, onComplete), 2500);
  }
}

async function loadRelated(watchId, onComplete) {
  try {
    const res = await fetch(`/api/watches/${watchId}/related`);
    if (!res.ok) throw new Error(await res.text());
    const data = await res.json();
    if (currentWatchId !== watchId) return;
    renderRelated(data, watchId, onComplete);
    if (data.job?.status === "done") {
      await onComplete?.(data.job.result?.scan_id);
    }
  } catch (err) {
    const el = document.getElementById("detail-related");
    el.classList.remove("hidden");
    el.innerHTML = `<p class="hint">Related infrastructure unavailable: ${escapeHtml(err.message || err)}</p>`;
  }
}

/* boot */
showPanel("dashboard");
loadDashboard();

// Deep-link #watch-N
if (location.hash.startsWith("#watch-")) {
  const id = Number(location.hash.replace("#watch-", ""));
  if (id) openWatch(id);
}
