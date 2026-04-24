/**
 * Offline SIEM — live dashboard + AI SOC Assistant
 */

const API = {
  logs: "/api/logs?limit=200",
  alerts: "/api/alerts?limit=100",
  incidents: "/api/incidents?limit=100",
  chat: "/api/chat",
  uploaded: "/api/logs/uploaded?limit=500",
};

// ── Severity / level colours ────────────────────────────────────────────────
const LEVEL_BADGE = {
  ERROR: { bg: "#ffe0e0", color: "#c0392b", label: "ERROR" },
  WARNING: { bg: "#fff3cd", color: "#856404", label: "WARN" },
  CRITICAL: { bg: "#f8d7da", color: "#842029", label: "CRIT" },
  INFO: { bg: "#e8f4fd", color: "#0c5460", label: "INFO" },
  DEBUG: { bg: "#e9ecef", color: "#495057", label: "DEBUG" },
};
const SEVERITY_BADGE = {
  CRITICAL: { bg: "#842029", color: "#fff" },
  HIGH: { bg: "#c0392b", color: "#fff" },
  MEDIUM: { bg: "#fd7e14", color: "#fff" },
  LOW: { bg: "#0d6efd", color: "#fff" },
};

// ── High-priority Windows Security Event IDs ──────────────────────────────────
// 4624 (Successful Login) is intentionally EXCLUDED — silent per policy.
const INTERESTING_EVENT_IDS = new Set([
  4625, 4648, 4672, 4768, 4769, 4771, 4776,
  4720, 4722, 4723, 4724, 4725, 4726, 4728, 4732, 4756,
  4697, 4698, 4702, 4719, 4739,
  4663, 4688, 4689,
  4634, 4740, 4767,
]);

// Event IDs that are explicitly silenced
const SILENCED_EVENT_IDS = new Set([
  4624, // Successful Logon — suppress per policy
]);

function isHighPriority(l) {
  const lvl = (l.level || "").toUpperCase();
  const src = (l.source || "").toLowerCase();
  const meta = (() => {
    try { return typeof l.metadata === "string" ? JSON.parse(l.metadata) : (l.metadata || {}); }
    catch { return {}; }
  })();
  const eventId = Number(meta.event_id || l.event_id || 0);

  if (SILENCED_EVENT_IDS.has(eventId)) return false;
  if (lvl === "ERROR" || lvl === "CRITICAL") return true;
  if (src === "security" && INTERESTING_EVENT_IDS.has(eventId)) return true;

  const msg = (l.message || l.raw_line || "").toLowerCase();
  if (
    (msg.includes("powershell") && (msg.includes("obfuscat") || msg.includes("encoded") || msg.includes("-enc"))) ||
    msg.includes("credential dump") ||
    msg.includes("mimikatz") ||
    (msg.includes("lsass") && msg.includes("access")) ||
    msg.includes("invoke-expression") ||
    msg.includes("iex(")
  ) return true;

  return false;
}

// ════════════════════════════════════════════════════════════════════════════
// TOAST NOTIFICATION SYSTEM (replaces browser Notification() API)
// ════════════════════════════════════════════════════════════════════════════

const TOAST_SEVERITY_STYLE = {
  critical: { icon: "🚨", border: "#842029", accent: "#c0392b", label: "CRITICAL" },
  high: { icon: "⚠️", border: "#c0392b", accent: "#e74c3c", label: "HIGH" },
  medium: { icon: "🔔", border: "#fd7e14", accent: "#e67e22", label: "MEDIUM" },
  low: { icon: "ℹ️", border: "#0d6efd", accent: "#2980b9", label: "LOW" },
  info: { icon: "🛡️", border: "#198754", accent: "#27ae60", label: "INFO" },
};

function showToast(title, message, severity = "high") {
  const container = document.getElementById("toast-container");
  if (!container) return;

  const s = TOAST_SEVERITY_STYLE[severity.toLowerCase()] || TOAST_SEVERITY_STYLE.high;
  const toast = document.createElement("div");
  toast.className = "siem-toast";
  toast.style.cssText = `
    display:flex;align-items:flex-start;gap:10px;
    background:#1a1d2e;color:#e8eaf0;
    border-left:4px solid ${s.border};
    border-radius:8px;padding:13px 14px 13px 12px;
    box-shadow:0 4px 20px rgba(0,0,0,.45);
    font-family:var(--font);font-size:13px;
    max-width:340px;width:100%;
    animation:toastSlideIn .22s ease;
    position:relative;
  `;
  toast.innerHTML = `
    <span style="font-size:20px;line-height:1;flex-shrink:0;margin-top:1px;">${s.icon}</span>
    <div style="flex:1;min-width:0;">
      <div style="display:flex;align-items:center;gap:6px;margin-bottom:3px;">
        <span style="font-weight:700;font-size:12px;color:${s.accent};
          text-transform:uppercase;letter-spacing:.5px;">${s.label}</span>
        <span style="font-weight:700;color:#f0f2f8;font-size:13px;">${escHtml(title)}</span>
      </div>
      <div style="color:#b0b8d0;font-size:12px;line-height:1.45;word-break:break-word;">
        ${escHtml(truncate(message, 160))}
      </div>
    </div>
    <button onclick="this.closest('.siem-toast').remove()" style="
      background:none;border:none;color:#666;cursor:pointer;
      font-size:16px;line-height:1;flex-shrink:0;padding:0 2px;
      margin-top:-1px;transition:color .1s;" title="Dismiss">✕</button>
  `;

  container.appendChild(toast);

  const dismiss = () => {
    toast.style.animation = "toastSlideOut .2s ease forwards";
    toast.addEventListener("animationend", () => toast.remove(), { once: true });
  };

  let timer = setTimeout(dismiss, 6000);
  toast.addEventListener("mouseenter", () => clearTimeout(timer));
  toast.addEventListener("mouseleave", () => { timer = setTimeout(dismiss, 2000); });
}

// ── Serial number counters — reset on populate, increment on prepend ──────────
let _logSerial = 0;   // live logs-tbody
let _forensicSerial = 0;   // forensic-tbody

// ── Counters ─────────────────────────────────────────────────────────────────
let stats = { logs: 0, alerts: 0, incidents: 0, liveEvents: 0 };
function updateStat(key, delta = 1) {
  stats[key] += delta;
  const el = document.getElementById(`stat-${key}`);
  if (el) el.textContent = stats[key].toLocaleString();
}
function setStat(key, val) {
  stats[key] = val;
  const el = document.getElementById(`stat-${key}`);
  if (el) el.textContent = val.toLocaleString();
}

// ── Helpers ─────────────────────────────────────────────────────────────────
function fmtTs(ts) {
  if (!ts) return "—";
  try { return new Date(ts).toLocaleString("en-GB", { hour12: false }).replace(",", ""); }
  catch { return ts; }
}
function badge(text, bg, color) {
  return `<span style="background:${bg};color:${color};padding:2px 7px;border-radius:4px;
    font-size:11px;font-weight:600;letter-spacing:.4px;white-space:nowrap;">${text}</span>`;
}
function levelBadge(level = "INFO") {
  const c = LEVEL_BADGE[level.toUpperCase()] || LEVEL_BADGE.INFO;
  return badge(c.label, c.bg, c.color);
}
function severityBadge(sev = "LOW") {
  const c = SEVERITY_BADGE[sev.toUpperCase()] || SEVERITY_BADGE.LOW;
  return badge(sev, c.bg, c.color);
}
function truncate(str, n = 120) {
  if (!str) return "";
  return str.length > n ? str.slice(0, n) + "…" : str;
}
function escHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

// ── Tab switching ────────────────────────────────────────────────────────────
function showTab(name) {
  document.querySelectorAll(".tab-panel").forEach(p => p.style.display = "none");
  document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
  document.getElementById(`panel-${name}`).style.display = "block";
  document.querySelector(`.tab-btn[data-tab="${name}"]`).classList.add("active");
}

// ── View switching ────────────────────────────────────────────────────────────
function switchView(view) {
  document.getElementById("live-view").style.display = view === "live" ? "block" : "none";
  document.getElementById("forensic-view").style.display = view === "forensic" ? "block" : "none";
  document.getElementById("nav-live").classList.toggle("active", view === "live");
  document.getElementById("nav-forensic").classList.toggle("active", view === "forensic");
  document.querySelector(".topbar h1").textContent =
    view === "live" ? "SOC Dashboard" : "🔬 Log Forensic Lab";
  if (view === "forensic") loadForensicLogs();
}

async function loadForensicLogs() {
  const tbody = document.getElementById("forensic-tbody");
  const count = document.getElementById("forensic-count");
  tbody.innerHTML = `<tr><td colspan="5" class="empty-state">Loading…</td></tr>`;
  try {
    const data = await fetch(API.uploaded).then(r => r.json());
    const logs = data.logs || [];
    tbody.innerHTML = "";
    if (!logs.length) {
      tbody.innerHTML = `<tr><td colspan="5" class="empty-state">No uploaded logs yet — drop a file above.</td></tr>`;
    } else {
      _forensicSerial = logs.length;
      logs.forEach((l, i) => tbody.appendChild(buildLogRow(l, i + 1)));
    }
    count.textContent = `${logs.length} entries · Click a row to pin as AI context`;
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="5" class="empty-state">Error: ${err.message}</td></tr>`;
  }
}

function forensicDrop(event) {
  event.preventDefault();
  const dz = document.getElementById("forensic-dropzone");
  dz.style.borderColor = "var(--border)";
  dz.style.background = "";
  const file = event.dataTransfer.files[0];
  if (file) uploadFile(file);
}

// ════════════════════════════════════════════════════════════════════════════
// CONTEXT LOCK
// ════════════════════════════════════════════════════════════════════════════
let currentLogContext = null;
let _selectedRow = null;

function lockContext(rowData, labelText) {
  currentLogContext = rowData;
  if (_selectedRow) _selectedRow.classList.remove("row-selected");
  _selectedRow = rowData._tr;
  if (_selectedRow) _selectedRow.classList.add("row-selected");
  const banner = document.getElementById("context-banner");
  const label = document.getElementById("context-label");
  label.textContent = "📌 " + truncate(labelText, 60);
  banner.classList.add("visible");
  document.getElementById("chat-panel").classList.remove("hidden");
}

function clearContext() {
  currentLogContext = null;
  if (_selectedRow) { _selectedRow.classList.remove("row-selected"); _selectedRow = null; }
  document.getElementById("context-banner").classList.remove("visible");
  document.getElementById("context-label").textContent = "";
}

// ── Logs table ───────────────────────────────────────────────────────────────
function buildLogRow(logData, serialNum = null) {
  const highPriority = isHighPriority(logData);
  const isSecure = (logData.source || "").toLowerCase() === "security";
  const tr = document.createElement("tr");
  if (highPriority) tr.style.backgroundColor = "#fff5f5";
  const rowId = logData.id || logData.alert_id || logData.timestamp || Math.random();
  tr.dataset.rowId = rowId;
  tr.dataset.rowJson = JSON.stringify(logData);
  if (serialNum != null) tr.dataset.serial = serialNum;
  const serialCell = serialNum != null
    ? `<td class="serial-col" onclick="event.stopPropagation()" style="color:#888;font-size:11px;text-align:right;padding-right:8px;user-select:none;white-space:nowrap;">${serialNum}</td>`
    : `<td class="serial-col" style="color:#ccc;font-size:11px;text-align:right;padding-right:8px;">-</td>`;
  tr.innerHTML = `
    <td class="cb-col" onclick="event.stopPropagation()">
      <input type="checkbox" class="row-cb" data-id="${rowId}">
    </td>
    ${serialCell}
    <td>${fmtTs(logData.timestamp)}</td>
    <td>${levelBadge(logData.level)}</td>
    <td style="${highPriority && isSecure ? "color:#c0392b;font-weight:600;" : ""}">
      ${escHtml(logData.source || "")}</td>
    <td>${escHtml(logData.logger || "")}</td>
    <td style="max-width:420px;word-break:break-word;">
      ${escHtml(truncate(logData.message || logData.raw_line || ""))}</td>
  `;
  tr.addEventListener("click", () => {
    logData._tr = tr;
    lockContext(logData, `[${logData.source}] ${logData.message || logData.raw_line || ""}`);
  });
  return tr;
}

function prependLogRow(logData) {
  const tbody = document.getElementById("logs-tbody");
  _logSerial++;
  const tr = buildLogRow(logData, _logSerial);
  tr.classList.add("row-flash");
  tbody.insertBefore(tr, tbody.firstChild);
  _renumberTbody(tbody);   // keep #1 = newest after prepend
  while (tbody.rows.length > 500) tbody.deleteRow(tbody.rows.length - 1);
}

function populateLogs(logs) {
  const tbody = document.getElementById("logs-tbody");
  tbody.innerHTML = "";
  _logSerial = logs.length;
  logs.forEach((l, i) => tbody.appendChild(buildLogRow(l, i + 1)));
  setStat("logs", logs.length);
}

// ── Renumber serial cells top-down (called after prepend) ───────────────────
// Ensures #1 = topmost visible row regardless of insertion order.
function _renumberTbody(tbody) {
  Array.from(tbody.rows).forEach((tr, i) => {
    tr.dataset.serial = i + 1;
    const cell = tr.querySelector(".serial-col");
    if (cell) cell.textContent = i + 1;
  });
}

// ── Alerts table ─────────────────────────────────────────────────────────────
function buildAlertRow(a) {
  const tr = document.createElement("tr");
  tr.innerHTML = `
    <td>${fmtTs(a.timestamp)}</td>
    <td>${severityBadge(a.severity)}</td>
    <td>${escHtml(a.alert_type || "")}</td>
    <td>${escHtml(truncate(a.reason || "", 100))}</td>
    <td style="max-width:300px;word-break:break-word;">
      ${escHtml(truncate(a.description || "", 140))}</td>
    <td style="font-size:11px;color:#888;">${(a.confidence * 100 | 0)}%</td>
  `;
  tr.addEventListener("click", () => {
    a._tr = tr;
    lockContext(a, `[${a.alert_type}] ${a.reason || ""}`);
  });
  return tr;
}

function populateAlerts(alerts) {
  const tbody = document.getElementById("alerts-tbody");
  tbody.innerHTML = "";
  alerts.forEach(a => tbody.appendChild(buildAlertRow(a)));
  setStat("alerts", alerts.length);
}

// ── Incidents table ───────────────────────────────────────────────────────────
const STATUS_STYLE = {
  NEW: "background:#e8f4fd;color:#0c5460;",
  ACKNOWLEDGED: "background:#fff3cd;color:#856404;",
  RESOLVED: "background:#d4edda;color:#155724;",
  open: "background:#e9ecef;color:#495057;",
};
function stStyle(st) { return STATUS_STYLE[st] || "background:#e9ecef;color:#495057;"; }

function buildIncidentRow(inc) {
  const st = inc.status || "open";
  const alertIds = Array.isArray(inc.alert_ids)
    ? inc.alert_ids
    : JSON.parse(inc.alert_ids || "[]");
  const tr = document.createElement("tr");
  tr.innerHTML = `
    <td style="font-family:monospace;font-size:12px;">${escHtml(inc.incident_id)}</td>
    <td>${escHtml(truncate(inc.title || "", 80))}</td>
    <td>${severityBadge(inc.severity)}</td>
    <td><span style="padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600;${stStyle(st)}">${st}</span></td>
    <td style="text-align:center;">${alertIds.length}</td>
    <td>${fmtTs(inc.created_at)}</td>
    <td>${inc.resolved_at ? fmtTs(inc.resolved_at) : "—"}</td>
  `;
  return tr;
}

function populateIncidents(incidents) {
  const tbody = document.getElementById("incidents-tbody");
  tbody.innerHTML = "";
  incidents.forEach(i => tbody.appendChild(buildIncidentRow(i)));
  setStat("incidents", incidents.length);
}

// ════════════════════════════════════════════════════════════════════════════
// AI CHAT
// ════════════════════════════════════════════════════════════════════════════

function appendMessage(role, text, isThinking = false) {
  const container = document.getElementById("chat-messages");
  const div = document.createElement("div");
  div.className = `msg ${role}${isThinking ? " thinking" : ""}`;
  const welcome = container.querySelector(".chat-welcome");
  if (welcome) welcome.remove();
  const now = new Date().toLocaleTimeString("en-GB", { hour12: false });
  div.innerHTML = `
    <div class="msg-bubble">${escHtml(text).replace(/\n/g, "<br>")}</div>
    <div class="msg-meta">${now}</div>
  `;
  container.appendChild(div);
  container.scrollTop = container.scrollHeight;
  return div;
}

async function sendChatMessage() {
  const input = document.getElementById("chat-input");
  const sendBtn = document.getElementById("chat-send");
  const message = input.value.trim();
  if (!message) return;
  appendMessage("user", message);
  input.value = "";
  input.style.height = "auto";
  sendBtn.disabled = true;
  const thinkingDiv = appendMessage("assistant", "Analysing…", true);
  try {
    const body = { message };
    if (currentLogContext) {
      const { _tr, ...ctx } = currentLogContext;
      body.log_context = ctx;
    }
    const res = await fetch(API.chat, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(err.detail || "Request failed");
    }
    const data = await res.json();
    thinkingDiv.remove();
    appendMessage("assistant", data.reply);
  } catch (err) {
    thinkingDiv.remove();
    appendMessage("assistant", `⚠️ Error: ${err.message}`);
  } finally {
    sendBtn.disabled = false;
    input.focus();
  }
}

function initChatWidget() {
  const toggle = document.getElementById("chat-toggle");
  const panel = document.getElementById("chat-panel");
  const close = document.getElementById("chat-close");
  const send = document.getElementById("chat-send");
  const input = document.getElementById("chat-input");
  const ctxClear = document.getElementById("context-clear");
  toggle.addEventListener("click", () => panel.classList.toggle("hidden"));
  close.addEventListener("click", () => panel.classList.add("hidden"));
  ctxClear.addEventListener("click", clearContext);
  send.addEventListener("click", sendChatMessage);
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendChatMessage(); }
  });
  input.addEventListener("input", () => {
    input.style.height = "auto";
    input.style.height = Math.min(input.scrollHeight, 90) + "px";
  });
}

// ── Data loading ─────────────────────────────────────────────────────────────
async function loadAll() {
  setStatus("loading", "Loading data…");
  try {
    const [logsRes, alertsRes, incRes] = await Promise.all([
      fetch(API.logs), fetch(API.alerts), fetch(API.incidents),
    ]);
    const [logsData, alertsData, incData] = await Promise.all([
      logsRes.json(), alertsRes.json(), incRes.json(),
    ]);
    populateLogs(logsData.logs || []);
    populateAlerts(alertsData.alerts || []);
    populateIncidents(incData.incidents || []);
    setStatus("ok", "Connected");
  } catch (err) {
    setStatus("error", "Failed to load: " + err.message);
  }
}

// ════════════════════════════════════════════════════════════════════════════
// SECURITY ALERT TRIGGER  (toast + sound + flash — NO browser Notification)
// ════════════════════════════════════════════════════════════════════════════
function triggerSecurityAlert(msg, severity = "high") {
  showToast("Security Alert", msg, severity);
  const snd = document.getElementById("alert-sound");
  if (snd) snd.cloneNode(true).play().catch(() => { });
  const topbar = document.querySelector(".topbar");
  if (topbar) {
    topbar.classList.remove("topbar-flash");
    void topbar.offsetWidth;
    topbar.classList.add("topbar-flash");
    topbar.addEventListener("animationend",
      () => topbar.classList.remove("topbar-flash"), { once: true });
  }
}

// ── WebSocket ─────────────────────────────────────────────────────────────────
let ws, wsRetries = 0;
function connectWS() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  ws = new WebSocket(`${proto}://${location.host}/ws/live`);

  ws.onopen = () => {
    wsRetries = 0;
    setStatus("ok", "Live  ●");
    ws._ping = setInterval(
      () => { if (ws.readyState === WebSocket.OPEN) ws.send("ping"); }, 20000
    );
  };

  ws.onmessage = (evt) => {
    let msg;
    try { msg = JSON.parse(evt.data); } catch { return; }

    // ── Real-time log stream ─────────────────────────────────────────────────
    if (msg.type === "new_logs" && Array.isArray(msg.data)) {
      msg.data.forEach(l => {
        prependLogRow(l);
        updateStat("logs");
        updateStat("liveEvents");

        // RULE: Silently skip Event ID 4624 (Successful Login) — no toast, no sound
        const meta = (() => { try { return typeof l.metadata === "string" ? JSON.parse(l.metadata) : (l.metadata || {}); } catch { return {}; } })();
        const eventId = Number(meta.event_id || l.event_id || 0);
        if (eventId === 4624) return;

        if (isHighPriority(l)) {
          triggerSecurityAlert(l.message || l.raw_line || "High-priority security event");
        }
      });
    }

    // ── Engine-generated alerts (brute-force, PowerShell obfuscation, cred dump)
    if (msg.type === "new_alerts" && Array.isArray(msg.data)) {
      msg.data.forEach(a => {
        const sev = (a.severity || "HIGH").toLowerCase();
        showToast(a.alert_type || "Threat Detected", a.reason || a.description || "", sev);
        const snd = document.getElementById("alert-sound");
        if (snd) snd.cloneNode(true).play().catch(() => { });
        const topbar = document.querySelector(".topbar");
        if (topbar) {
          topbar.classList.remove("topbar-flash");
          void topbar.offsetWidth;
          topbar.classList.add("topbar-flash");
          topbar.addEventListener("animationend",
            () => topbar.classList.remove("topbar-flash"), { once: true });
        }
        const tbody = document.getElementById("alerts-tbody");
        if (tbody) {
          const tr = buildAlertRow(a);
          tr.classList.add("row-flash");
          tbody.insertBefore(tr, tbody.firstChild);
          while (tbody.rows.length > 500) tbody.deleteRow(tbody.rows.length - 1);
        }
        updateStat("alerts");
      });
    }
  };

  ws.onclose = () => {
    clearInterval(ws._ping);
    setStatus("warn", "Reconnecting…");
    setTimeout(connectWS, Math.min(30000, 1000 * 2 ** wsRetries++));
  };
  ws.onerror = () => ws.close();
}

// ── Status indicator ─────────────────────────────────────────────────────────
function setStatus(type, text) {
  const el = document.getElementById("connection-status");
  if (!el) return;
  const colours = { ok: "#198754", error: "#dc3545", warn: "#fd7e14", loading: "#0d6efd" };
  el.textContent = text;
  el.style.color = colours[type] || "#495057";
}

// ════════════════════════════════════════════════════════════════════════════
// FILE UPLOADER — ONE batched summary toast, never one-per-alert
// ════════════════════════════════════════════════════════════════════════════
async function uploadFile(file) {
  const status = document.getElementById("upload-status");
  status.style.color = "var(--accent2)";
  status.textContent = `⏳ Uploading ${file.name}…`;

  const fd = new FormData();
  fd.append("file", file);

  try {
    const res = await fetch("/api/upload", { method: "POST", body: fd });
    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || res.statusText);

    status.style.color = "#198754";
    status.textContent = `✔ ${data.filename}: ${data.inserted} rows`;

    // ── BATCH SUMMARY — exactly ONE toast regardless of alert count ───────────
    const alertCount = data.alert_count || 0;
    const filename = data.filename || file.name;
    const highCount = data.high_count || 0;
    const critCount = data.critical_count || 0;

    if (alertCount > 0) {
      let detail = `${alertCount} threat${alertCount !== 1 ? "s" : ""} detected`;
      if (critCount > 0) detail += ` · ${critCount} Critical`;
      if (highCount > 0) detail += ` · ${highCount} High`;
      showToast(
        "Import Complete",
        `${detail} in ${filename}`,
        alertCount >= 10 ? "critical" : alertCount >= 3 ? "high" : "medium"
      );
      const snd = document.getElementById("alert-sound");
      if (snd) snd.cloneNode(true).play().catch(() => { });
    } else {
      showToast(
        "Import Complete",
        `${data.inserted} log entries loaded from ${filename} — no threats detected.`,
        "info"
      );
    }

    setTimeout(() => { loadAll(); loadForensicLogs(); }, 800);

  } catch (err) {
    status.style.color = "var(--accent)";
    status.textContent = `✖ ${err.message}`;
    showToast("Upload Failed", err.message, "medium");
  }
}

function initUploader() {
  const input = document.getElementById("upload-input");
  input.addEventListener("change", () => {
    if (input.files[0]) { uploadFile(input.files[0]); input.value = ""; }
  });
}

// ════════════════════════════════════════════════════════════════════════════
// DATA MANAGEMENT — Clear & Selective Export
// ════════════════════════════════════════════════════════════════════════════

function openClearModal() {
  document.getElementById("clear-modal-backdrop").classList.add("open");
  document.getElementById("clear-confirm-btn").focus();
}
function closeClearModal(evt) {
  if (evt && evt.target !== document.getElementById("clear-modal-backdrop")) return;
  document.getElementById("clear-modal-backdrop").classList.remove("open");
}
document.addEventListener("keydown", e => {
  if (e.key === "Escape") closeClearModal();
});

async function confirmClear() {
  const btn = document.getElementById("clear-confirm-btn");
  btn.textContent = "Deleting…";
  btn.disabled = true;
  try {
    const res = await fetch("/api/logs/clear", { method: "DELETE" });
    if (!res.ok) throw new Error((await res.json()).detail || res.statusText);
    ["logs-tbody", "alerts-tbody", "incidents-tbody", "forensic-tbody"].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.innerHTML = `<tr><td colspan="10" class="empty-state">Database cleared.</td></tr>`;
    });
    ["logs", "alerts", "incidents", "liveEvents"].forEach(k => setStat(k, 0));
    ["logs-select-all", "forensic-select-all"].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.checked = false;
    });
    showToast("Data Cleared", "All logs, alerts, and incidents have been deleted.", "info");
    closeClearModal();
  } catch (err) {
    btn.textContent = "Error — retry";
    btn.style.background = "#c0392b";
    showToast("Clear Failed", err.message, "medium");
    console.error("Clear failed:", err);
  } finally {
    btn.disabled = false;
    if (btn.textContent === "Deleting…") btn.textContent = "Yes, delete everything";
  }
}

function toggleSelectAll(tbodyId, checked) {
  document.querySelectorAll(`#${tbodyId} .row-cb`).forEach(cb => cb.checked = checked);
}

function exportSelected() {
  // ── Read range inputs ─────────────────────────────────────────────────────
  const fromInput = document.getElementById("export-from");
  const toInput = document.getElementById("export-to");
  const fromVal = fromInput ? parseInt(fromInput.value, 10) : NaN;
  const toVal = toInput ? parseInt(toInput.value, 10) : NaN;
  const useRange = !isNaN(fromVal) && !isNaN(toVal) && fromVal > 0 && toVal >= fromVal;

  const tbodies = ["logs-tbody", "forensic-tbody", "alerts-tbody"];
  const rows = [];

  tbodies.forEach(id => {
    const tbody = document.getElementById(id);
    if (!tbody) return;

    if (useRange) {
      // Range mode: include every row whose data-serial is in [fromVal, toVal]
      Array.from(tbody.rows).forEach(tr => {
        const serial = parseInt(tr.dataset.serial, 10);
        if (!isNaN(serial) && serial >= fromVal && serial <= toVal) {
          if (tr.dataset.rowJson) {
            try {
              const data = JSON.parse(tr.dataset.rowJson);
              delete data._tr;
              data["#"] = serial;
              rows.push(data);
            } catch { }
          }
        }
      });
    } else {
      // Checkbox mode: include checked rows
      tbody.querySelectorAll(".row-cb:checked").forEach(cb => {
        const tr = cb.closest("tr");
        if (tr && tr.dataset.rowJson) {
          try {
            const data = JSON.parse(tr.dataset.rowJson);
            const serial = parseInt(tr.dataset.serial, 10);
            delete data._tr;
            if (!isNaN(serial)) data["#"] = serial;
            rows.push(data);
          } catch { }
        }
      });
    }
  });

  if (rows.length === 0) {
    const btn = document.querySelector(".action-btn-export");
    const orig = btn.textContent;
    btn.textContent = useRange ? "\u26a0 No rows in that range" : "\u26a0 Select rows first";
    btn.style.background = "#fff3cd";
    btn.style.color = "#856404";
    setTimeout(() => {
      btn.textContent = orig;
      btn.style.background = "";
      btn.style.color = "";
    }, 2000);
    return;
  }

  // Sort by serial so CSV order matches screen order
  rows.sort((a, b) => (a["#"] ?? 0) - (b["#"] ?? 0));

  // Build CSV with # column first
  const allKeys = ["#", ...new Set(rows.flatMap(r => Object.keys(r)).filter(k => k !== "#"))];
  const escape = v => {
    const s = v == null ? "" : String(v).replace(/"/g, '""');
    return /[,\n"]/.test(s) ? `"${s}"` : s;
  };
  const csv = [
    allKeys.join(","),
    ...rows.map(r => allKeys.map(k => escape(r[k])).join(","))
  ].join("\n");

  const modeLabel = useRange ? `rows_${fromVal}-${toVal}` : "selected";
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `siem_export_${modeLabel}_${new Date().toISOString().slice(0, 10)}.csv`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);

  showToast(
    "Export Complete",
    `${rows.length} row${rows.length !== 1 ? "s" : ""} exported${useRange ? ` (range #${fromVal}\u2013#${toVal})` : ""}.`,
    "info"
  );
}

// ── Boot ──────────────────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll(".tab-btn").forEach(btn => {
    btn.addEventListener("click", () => showTab(btn.dataset.tab));
  });
  switchView("live");
  loadAll();
  connectWS();
  initChatWidget();
  initUploader();
  // NOTE: browser Notification API removed — toasts are fully in-dashboard.
});