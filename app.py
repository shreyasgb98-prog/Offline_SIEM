"""Offline SIEM — FastAPI backend with WebSocket live feed + local AI assistant."""

import asyncio
import json
import logging
import sqlite3
import threading
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, UploadFile, File
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# ---------------------------------------------------------------------------
# Paths  (DB path strictly: data/offline_siem.db)
# ---------------------------------------------------------------------------
BASE_DIR    = Path(__file__).parent
DB_PATH     = BASE_DIR / "data" / "offline_siem.db"
STATIC      = BASE_DIR / "static"
MODEL_PATH  = BASE_DIR / "models" / "Phi-3-mini-4k-instruct-q4_k_m.gguf"
UPLOAD_DIR  = BASE_DIR / "uploads"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("siem")

# ---------------------------------------------------------------------------
# ── AI: llama-cpp-python (offline, air-gapped) ──────────────────────────────
# ---------------------------------------------------------------------------
_llm = None          # lazy-loaded on first /api/chat request
_llm_lock = threading.Lock()

SOC_SYSTEM_PROMPT = """You are an expert Senior SOC (Security Operations Center) Analyst \
with 15+ years of experience in threat hunting, incident response, and Windows event log \
analysis. Your role is to help junior analysts understand security events and logs.

When given a log entry or security event:
- Identify what the event means in plain language
- Assess potential threat level and explain why
- Reference relevant MITRE ATT&CK techniques when applicable
- Suggest concrete next investigation steps
- Flag any immediate actions required

Be concise, technical, and actionable. Avoid speculation — base analysis on the evidence provided."""


def _load_llm():
    """Load the GGUF model once, return None if unavailable."""
    global _llm
    if _llm is not None:
        return _llm
    with _llm_lock:
        if _llm is not None:        # double-checked locking
            return _llm
        try:
            from llama_cpp import Llama  # type: ignore
            if not MODEL_PATH.exists():
                log.warning("Model not found at %s — AI assistant disabled.", MODEL_PATH)
                return None
            log.info("Loading LLM from %s …", MODEL_PATH)
            _llm = Llama(
                model_path=str(MODEL_PATH),
                n_ctx=2048,
                n_threads=4,
                verbose=False,
            )
            log.info("LLM loaded successfully.")
        except ImportError:
            log.warning("llama-cpp-python not installed — AI assistant disabled.")
        except Exception as exc:
            log.error("Failed to load LLM: %s", exc)
    return _llm


def _run_inference(user_message: str, log_context: dict | None) -> str:
    """Build prompt and run inference. Runs in a thread pool."""
    llm = _load_llm()
    if llm is None:
        return ("AI assistant is offline. Place `phi-3-mini-4k-instruct-q4.gguf` "
                "in the `models/` folder and install `llama-cpp-python`.")

    # Build context block if a log row was pinned
    context_block = ""
    if log_context:
        context_block = "\n\n[PINNED LOG CONTEXT]\n" + json.dumps(log_context, indent=2)

    # Phi-3 chat format
    prompt = (
        f"<|system|>\n{SOC_SYSTEM_PROMPT}<|end|>\n"
        f"<|user|>\n{user_message}{context_block}<|end|>\n"
        f"<|assistant|>\n"
    )

    output = llm(
        prompt,
        max_tokens=512,
        temperature=0.2,
        top_p=0.9,
        stop=["<|end|>", "<|user|>"],
        echo=False,
    )
    return output["choices"][0]["text"].strip()


# ---------------------------------------------------------------------------
# ── Request/response models ──────────────────────────────────────────────────
# ---------------------------------------------------------------------------
class ChatRequest(BaseModel):
    message: str
    log_context: dict | None = None   # pinned log row from the table


class ChatResponse(BaseModel):
    reply: str
    model: str


# ---------------------------------------------------------------------------
# Thread-safe SQLite (WAL mode, check_same_thread=False)
# ---------------------------------------------------------------------------
_db_lock = threading.Lock()


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def _query(sql: str, params: tuple = ()) -> list[dict]:
    with _db_lock:
        conn = _get_conn()
        try:
            cur = conn.execute(sql, params)
            return [dict(r) for r in cur.fetchall()]
        finally:
            conn.close()


def _insert_log(row: dict) -> None:
    sql = """
        INSERT INTO logs
            (session_id, timestamp, level, message, logger, source,
             function, line_number, metadata, raw_line, format, created_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
    """
    now = datetime.now().isoformat()
    with _db_lock:
        conn = _get_conn()
        try:
            conn.execute(sql, (
                row.get("session_id", "winmon"),
                row.get("timestamp", now),
                row.get("level", "INFO"),
                row.get("message", ""),
                row.get("logger", ""),
                row.get("source", ""),
                None, None,
                json.dumps(row.get("metadata", {})),
                row.get("raw_line", ""),
                row.get("format", "windows_event"),
                now,
            ))
            conn.commit()
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# WebSocket connection manager
# ---------------------------------------------------------------------------
class ConnectionManager:
    def __init__(self) -> None:
        self._clients: list[WebSocket] = []

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self._clients.append(ws)
        log.info("WS client connected (%d total)", len(self._clients))

    def disconnect(self, ws: WebSocket) -> None:
        self._clients = [c for c in self._clients if c is not ws]
        log.info("WS client disconnected (%d total)", len(self._clients))

    async def broadcast(self, payload: dict) -> None:
        dead: list[WebSocket] = []
        for ws in list(self._clients):
            try:
                await ws.send_text(json.dumps(payload))
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


manager = ConnectionManager()

# ---------------------------------------------------------------------------
# Windows Event Log monitor
# ---------------------------------------------------------------------------
_CHANNELS = ["System", "Application", "Security"]
_last_record: dict[str, int] = {}   # channel → last seen RecordNumber


def _poll_windows_once(loop: asyncio.AbstractEventLoop) -> None:
    try:
        import win32evtlog      # type: ignore
        import win32evtlogutil  # type: ignore
    except ImportError:
        log.warning("pywin32 not available — Windows event polling disabled.")
        return

    new_logs: list[dict] = []

    for channel in _CHANNELS:
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        try:
            handle = win32evtlog.OpenEventLog(None, channel)
            total  = win32evtlog.GetNumberOfEventLogRecords(handle)
            last   = _last_record.get(channel, total)   # first run: skip history

            if total > last:
                records   = win32evtlog.ReadEventLog(handle, flags, 0)
                new_count = total - last

                for rec in (records or [])[:new_count]:
                    event_id = getattr(rec, "EventID", 0) & 0xFFFF
                    ts_raw   = rec.TimeGenerated
                    try:
                        ts = datetime.fromtimestamp(int(ts_raw)).isoformat()
                    except Exception:
                        ts = datetime.now().isoformat()

                    try:
                        msg = win32evtlogutil.SafeFormatMessage(rec, channel) or ""
                    except Exception:
                        msg = str(getattr(rec, "StringInserts", "") or "")

                    level_map = {1: "ERROR", 2: "WARNING", 4: "INFO",
                                 8: "DEBUG", 16: "ERROR", 32: "INFO"}
                    level = level_map.get(getattr(rec, "EventType", 4), "INFO")

                    row = {
                        "session_id": "winmon",
                        "timestamp":  ts,
                        "level":      level,
                        "message":    msg.strip()[:500],
                        "logger":     getattr(rec, "SourceName", channel),
                        "source":     channel,
                        "metadata":   {"event_id": event_id, "channel": channel},
                        "raw_line":   f"[{channel}] EventID={event_id} {msg[:200]}",
                        "format":     "windows_event",
                    }
                    try:
                        _insert_log(row)
                        new_logs.append(row)
                    except Exception as exc:
                        log.debug("DB insert error: %s", exc)

            _last_record[channel] = total
            win32evtlog.CloseEventLog(handle)

        except Exception as exc:
            log.error("Error reading channel '%s': %s", channel, exc)

    if new_logs:
        asyncio.run_coroutine_threadsafe(
            manager.broadcast({"type": "new_logs", "data": new_logs}),
            loop,
        )
        log.info("Broadcast %d new Windows events", len(new_logs))


async def monitor_windows_logs() -> None:
    """Asyncio background task: poll Windows Event Logs every 5 s."""
    loop = asyncio.get_running_loop()
    log.info("Windows Event Log monitor started")
    while True:
        await loop.run_in_executor(None, _poll_windows_once, loop)
        await asyncio.sleep(5)


# ---------------------------------------------------------------------------
# App lifespan
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    task = asyncio.create_task(monitor_windows_logs())
    log.info("SIEM backend ready — DB: %s", DB_PATH)
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------
app = FastAPI(title="Offline SIEM", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")


@app.get("/")
async def serve_index():
    return FileResponse(str(STATIC / "index.html"))


# ── REST ────────────────────────────────────────────────────────────────────

@app.get("/api/logs")
async def get_logs(limit: int = 500, source: str | None = None, level: str | None = None):
    sql = "SELECT * FROM logs"
    where, params = [], []
    if source:
        where.append("source = ?"); params.append(source)
    if level:
        where.append("level = ?"); params.append(level.upper())
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)
    rows = _query(sql, tuple(params))
    return JSONResponse({"count": len(rows), "logs": rows})


@app.get("/api/alerts")
async def get_alerts(limit: int = 200, severity: str | None = None, alert_type: str | None = None):
    sql = "SELECT * FROM alerts"
    where, params = [], []
    if severity:
        where.append("severity = ?"); params.append(severity.upper())
    if alert_type:
        where.append("alert_type = ?"); params.append(alert_type.upper())
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY timestamp DESC LIMIT ?"
    params.append(limit)
    rows = _query(sql, tuple(params))
    return JSONResponse({"count": len(rows), "alerts": rows})


@app.get("/api/incidents")
async def get_incidents(limit: int = 200, status: str | None = None):
    sql = "SELECT * FROM incidents"
    params: list[Any] = []
    if status:
        sql += " WHERE status = ?"; params.append(status)
    sql += " ORDER BY created_at DESC LIMIT ?"; params.append(limit)
    rows = _query(sql, tuple(params))
    return JSONResponse({"count": len(rows), "incidents": rows})


# ── AI chat endpoint ─────────────────────────────────────────────────────────

@app.post("/api/chat", response_model=ChatResponse)
async def chat(req: ChatRequest):
    """Run local Phi-3 inference. Offloaded to thread pool to avoid blocking."""
    loop = asyncio.get_running_loop()
    reply = await loop.run_in_executor(
        None, _run_inference, req.message, req.log_context
    )
    return ChatResponse(reply=reply, model=MODEL_PATH.name)


# ── File Upload ──────────────────────────────────────────────────────────────

@app.post("/api/upload")
async def upload_log(file: UploadFile = File(...)):
    """Accept a log file, save to uploads/, parse via existing ingestion pipeline,
    insert rows into DB, and broadcast new entries over WebSocket."""
    safe_name = Path(file.filename).name          # strip any path traversal
    dest = UPLOAD_DIR / safe_name

    content_bytes = await file.read()
    dest.write_bytes(content_bytes)
    log.info("Uploaded file saved: %s (%d bytes)", dest, len(content_bytes))

    inserted = 0
    broadcast_rows: list[dict] = []
    try:
        from src.ingestion import LogIngestor
        ingestor = LogIngestor()
        content_str = content_bytes.decode("utf-8", errors="replace")
        for entry in ingestor.ingest_content(content_str, filename=safe_name):
            _lvl = getattr(entry, "level", None)
            _lvl_str = (_lvl.value if hasattr(_lvl, "value") else str(_lvl or "INFO")).upper()
            row = {
                "session_id": "upload",
                "timestamp":  getattr(entry, "timestamp", None) or datetime.now().isoformat(),
                "level":      _lvl_str,
                "message":    getattr(entry, "message", "") or "",
                "logger":     getattr(entry, "logger_name", "") or "",
                "source":     getattr(entry, "source", safe_name) or safe_name,
                "metadata":   getattr(entry, "metadata", {}) or {},
                "raw_line":   getattr(entry, "raw_line", "") or "",
                "format":     getattr(entry, "format", "uploaded") or "uploaded",
            }
            try:
                _insert_log(row)
                broadcast_rows.append(row)
                inserted += 1
            except Exception as exc:
                log.debug("DB insert error during upload: %s", exc)
    except Exception as exc:
        log.error("Ingestion error for %s: %s", safe_name, exc)
        return JSONResponse(
            {"status": "error", "filename": safe_name, "detail": str(exc)},
            status_code=422,
        )

    if broadcast_rows:
        # Tag rows so the Forensic Lab frontend can identify them
        for r in broadcast_rows:
            r["category"] = "uploaded"
        asyncio.ensure_future(
            manager.broadcast({"type": "new_logs", "data": broadcast_rows})
        )

    return JSONResponse({
        "status":   "ok",
        "filename": safe_name,
        "inserted": inserted,
    })


# ── Forensic Lab — uploaded logs only ────────────────────────────────────────

@app.get("/api/logs/uploaded")
async def get_uploaded_logs(limit: int = 500):
    """Return only logs ingested via file upload (session_id = 'upload')."""
    rows = _query(
        "SELECT * FROM logs WHERE session_id = 'upload' ORDER BY timestamp DESC LIMIT ?",
        (limit,),
    )
    return JSONResponse({"count": len(rows), "logs": rows})


# ── WebSocket ────────────────────────────────────────────────────────────────


@app.delete("/api/logs/clear")
async def clear_all_data():
    """
    Truncate logs, alerts, and incidents tables.
    The DB file and schema are preserved — only row data is removed.

    FIX: VACUUM cannot run inside a transaction (SQLite constraint).
    We commit() the DELETEs first, close, then open a second connection
    for VACUUM so it runs in autocommit mode outside any transaction.
    """
    from fastapi import HTTPException

    tables = ["logs", "alerts", "incidents"]
    counts = {}

    # Phase 1: DELETE rows and commit
    try:
        with _db_lock:
            conn = _get_conn()
            try:
                for table in tables:
                    cur = conn.execute(f"SELECT COUNT(*) FROM {table}")
                    counts[table] = cur.fetchone()[0]
                    conn.execute(f"DELETE FROM {table}")
                conn.commit()          # commit BEFORE close — data is gone
            except Exception as exc:
                try:
                    conn.rollback()
                except Exception:
                    pass
                raise exc
            finally:
                conn.close()
    except Exception as exc:
        log.exception("Failed to clear database tables")
        from fastapi import HTTPException
        raise HTTPException(status_code=500, detail=f"Clear failed: {exc}")

    # Phase 2: VACUUM in a fresh connection (autocommit — required by SQLite)
    try:
        with _db_lock:
            vconn = _get_conn()
            try:
                vconn.isolation_level = None   # enables autocommit mode
                vconn.execute("VACUUM")
            finally:
                vconn.close()
    except Exception as exc:
        log.warning("VACUUM after clear failed (non-fatal): %s", exc)

    log.info("Database cleared — removed %s", counts)
    return JSONResponse({"status": "cleared", "removed": counts})


@app.websocket("/ws/live")
async def ws_live(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()   # block; handles client pings
    except WebSocketDisconnect:
        manager.disconnect(websocket)


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=False)