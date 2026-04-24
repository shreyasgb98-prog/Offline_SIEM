# Offline SIEM — Security Operations Center

An advanced offline Security Information and Event Management (SIEM) system designed for air-gapped environments and critical infrastructure protection. Built as a 3rd-year Engineering project.

---

## Features

- **Scalable Log Processing** — Streaming ingestion for large log files (5 GB+) with bounded memory usage
- **Advanced Detection Engine** — Statistical and rule-based threat detection
  - Brute force attack detection with Z-score anomaly analysis
  - Failed login tracking with time-window logic
  - Suspicious keyword detection
  - Threat intelligence matching with offline updates
  - Statistical anomaly detection (Z-score based)
- **Live SOC Dashboard** — FastAPI + WebSocket real-time event feed; Streamlit-themed UI
- **Offline AI SOC Assistant** — Local Phi-3 Mini (GGUF) chatbot; fully air-gapped, zero cloud calls
- **Universal File Uploader** — Upload `.log`, `.txt`, `.json`, `.csv`, or `.syslog` files directly from the dashboard; auto-routed through the existing parser registry
- **High-Performance Search** — Inverted index for O(1) keyword lookups
- **Analytics** — Search, filter, group, correlate, and timeline analysis
- **Incident Management** — Create, track, and resolve security incidents
- **Offline Threat Intelligence** — Versioned updates with SHA-256 integrity verification
- **Cryptographic Security** — SHA-256 file integrity, HMAC support, constant-time comparisons
- **Reporting** — HTML and TXT reports with cryptographic signing

---

## Installation

### Prerequisites

- Python 3.10+
- Windows / macOS / Linux

### Setup

```bash
# Create virtual environment
python -m venv .venv

# Activate
# Windows:
.venv\Scripts\activate
# macOS / Linux:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### AI Model Setup

The AI assistant requires a GGUF model file placed in the `models/` directory.

**Step 1 — Download the model**

```
models/Phi-3-mini-4k-instruct-q4_k_m.gguf
```

Download from: https://huggingface.co/microsoft/Phi-3-mini-4k-instruct-gguf

**Step 2 — Install `llama-cpp-python` for your hardware**

| Hardware | Command |
|---|---|
| CPU only (default) | `pip install llama-cpp-python` |
| NVIDIA GPU (CUDA) | `CMAKE_ARGS="-DGGML_CUDA=on" pip install llama-cpp-python --force-reinstall --no-cache-dir` |
| Apple Silicon (Metal) | `CMAKE_ARGS="-DGGML_METAL=on" pip install llama-cpp-python --force-reinstall --no-cache-dir` |

If the model file is absent or `llama-cpp-python` is not installed, the dashboard loads normally — the AI chat window will display an offline warning instead of crashing.

---

## Running the Application

```bash
python app.py
```

Dashboard available at: **http://127.0.0.1:8000**

---

## Usage

### Live Dashboard

The dashboard connects automatically via WebSocket on load. On Windows, it polls the System, Application, and Security event log channels every 5 seconds and streams new events to all connected browser tabs in real time.

### AI SOC Assistant

1. Click the **🤖** floating button (bottom-right) to open the chat panel.
2. Optionally, **click any log or alert row** to pin it as context — a blue banner confirms the lock.
3. Type your question and press **Enter** or **➤**.
4. The assistant (Phi-3 Mini) analyses the pinned log and responds with threat assessment, MITRE ATT&CK mappings, and recommended next steps.
5. Click **✕** in the banner to clear the pinned context.

The model runs entirely on-device. No data leaves the machine.

### File Upload

1. Click **📤 Upload Logs** in the sidebar.
2. Select a `.log`, `.txt`, `.json`, `.csv`, or `.syslog` file.
3. The file is saved to `uploads/`, parsed by the existing `LogIngestor` (parser auto-selected by extension), and inserted into the database.
4. New rows appear in the Live Logs table automatically via WebSocket broadcast — no page reload needed.
5. The sidebar status line confirms how many rows were ingested (e.g. `✔ auth.log: 412 rows`).

---

## Project Structure

```
offline-siem/
├── app.py                    # FastAPI backend — WebSocket, REST, AI chat, file upload
├── config.yaml               # Configuration
├── requirements.txt          # Dependencies
├── models/                   # GGUF model files (not committed to git)
│   └── Phi-3-mini-4k-instruct-q4_k_m.gguf
├── uploads/                  # Uploaded log files (created on first run)
├── data/                     # SQLite database (created on first run)
│   └── offline_siem.db
├── static/
│   ├── index.html            # Dashboard UI (Streamlit light theme)
│   └── app.js                # WebSocket client, AI chat widget, file uploader
└── src/
    ├── schema.py             # Common log schema
    ├── config.py             # Config loader
    ├── logging_config.py     # Logging setup
    ├── ingestion/
    │   └── __init__.py       # LogIngestor — file, streaming, incremental, directory
    ├── parsers/
    │   ├── base.py           # BaseParser
    │   ├── json_parser.py    # JSON parser
    │   ├── syslog_parser.py  # Syslog parser
    │   ├── text_parser.py    # Plain-text parser
    │   ├── csv_parser.py     # CSV parser
    │   └── __init__.py       # ParserRegistry
    ├── detection/
    │   ├── alert.py          # Alert schema
    │   ├── base.py           # BaseDetector
    │   ├── brute_force.py    # BruteForceDetector
    │   ├── failed_login.py   # FailedLoginDetector
    │   ├── keyword_detector.py
    │   ├── threat_intel.py   # ThreatIntelDetector
    │   ├── anomaly.py        # AnomalyDetector
    │   ├── engine.py         # DetectionEngine
    │   └── __init__.py
    ├── storage/
    │   ├── database.py       # SQLite manager
    │   ├── session.py        # SessionManager
    │   ├── file_tracker.py   # FileTracker
    │   ├── log_storage.py    # LogStorage
    │   ├── alert_storage.py  # AlertStorage
    │   ├── incident.py       # IncidentManager
    │   ├── audit.py          # AuditLogger
    │   └── __init__.py
    ├── analytics/
    │   ├── search.py         # SearchEngine
    │   ├── filter.py         # FilterBuilder
    │   ├── grouping.py       # GroupingEngine
    │   ├── correlation.py    # CorrelationEngine
    │   ├── timeline.py       # TimelineBuilder
    │   └── __init__.py
    ├── reporting/
    │   ├── base.py           # BaseReport
    │   ├── html_report.py    # HTMLReport
    │   ├── text_report.py    # TextReport
    │   ├── generator.py      # ReportGenerator
    │   └── __init__.py
    └── security/
        ├── validation.py     # InputValidator
        ├── password_gate.py  # PasswordGate
        ├── signing.py        # ReportSigner
        ├── file_handler.py   # SafeFileHandler
        └── __init__.py
```

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/` | Serves the dashboard (`static/index.html`) |
| `GET` | `/api/logs` | Fetch logs (`?limit=&source=&level=`) |
| `GET` | `/api/alerts` | Fetch alerts (`?limit=&severity=&alert_type=`) |
| `GET` | `/api/incidents` | Fetch incidents (`?limit=&status=`) |
| `POST` | `/api/chat` | AI inference — body: `{message, log_context?}` |
| `POST` | `/api/upload` | Upload a log file — `multipart/form-data` field: `file` |
| `WS` | `/ws/live` | WebSocket — streams `{type:"new_logs", data:[...]}` |

---

## Detection Reference

| Attack Type | Log Pattern | Detector |
|-------------|-------------|----------|
| Brute Force | 15+ failed logins in 30 s | `BruteForceDetector` |
| SQL Injection | `"SQL injection attempt"` | `KeywordDetector` |
| XSS | `"XSS attack detected"` | `KeywordDetector` |
| Suspicious IP | e.g. `185.220.101.1` | `ThreatIntelDetector` |
| Statistical Anomaly | Unusual volume/pattern | `AnomalyDetector` |

---

## Security Notes

- All inference is local — the GGUF model never makes network calls.
- Uploaded filenames are sanitised (`Path(filename).name`) to prevent path traversal.
- The `uploads/` and `models/` directories should be added to `.gitignore` if the project is version-controlled.

---

## License

MIT License