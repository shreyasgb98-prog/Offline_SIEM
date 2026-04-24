"""Stateful threat detection: Brute Force, PowerShell obfuscation, Credential Dumping.

This module runs ALONGSIDE the existing DetectionEngine detectors.
It maintains process-lifetime state (sliding window counters) and
produces alert dicts that app.py can INSERT into the alerts table
and broadcast over WebSocket directly — no ORM needed.
"""

import json
import re
import threading
import uuid
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any

# ---------------------------------------------------------------------------
# Brute-force tracker  (global, thread-safe)
# ---------------------------------------------------------------------------
_bf_lock = threading.Lock()

# Structure: { key -> [(timestamp, raw_line), ...] }
# key = "IP:<ip>" or "USER:<username>" extracted from the log
failed_logon_tracker: dict[str, list[tuple[datetime, str]]] = defaultdict(list)

BRUTE_FORCE_THRESHOLD = 5        # failures before alert
BRUTE_FORCE_WINDOW_SEC = 60      # sliding window in seconds


def _extract_key(log: dict) -> str:
    """Pull the best identifier (IP or username) from a log dict."""
    meta = log.get("metadata", {})
    if isinstance(meta, str):
        try:
            meta = json.loads(meta)
        except Exception:
            meta = {}

    ip = meta.get("ip") or meta.get("source_ip") or meta.get("IpAddress", "")
    user = meta.get("user") or meta.get("username") or meta.get("TargetUserName", "")

    if ip and ip not in ("-", ""):
        return f"IP:{ip}"
    if user and user not in ("-", ""):
        return f"USER:{user}"
    return f"SRC:{log.get('source', 'unknown')}"


def _is_failed_logon(log: dict) -> bool:
    """Return True if this log represents a failed logon attempt."""
    msg = (log.get("message") or log.get("raw_line") or "").upper()
    meta = log.get("metadata", {})
    if isinstance(meta, str):
        try:
            meta = json.loads(meta)
        except Exception:
            meta = {}

    event_id = int(meta.get("event_id", 0))
    if event_id == 4625:
        return True
    if "FAILED LOGON" in msg or "FAILED LOGIN" in msg or "AUTHENTICATION FAILURE" in msg:
        return True
    return False


def check_brute_force(log: dict) -> dict | None:
    """
    Update sliding-window counter. Returns an alert dict if threshold crossed,
    else None.  Thread-safe.
    """
    if not _is_failed_logon(log):
        return None

    key = _extract_key(log)
    now = datetime.now()
    cutoff = now - timedelta(seconds=BRUTE_FORCE_WINDOW_SEC)
    raw = log.get("raw_line") or log.get("message") or ""

    with _bf_lock:
        # Append and prune old events
        failed_logon_tracker[key].append((now, raw))
        failed_logon_tracker[key] = [
            (ts, r) for ts, r in failed_logon_tracker[key] if ts >= cutoff
        ]
        count = len(failed_logon_tracker[key])

    # Only fire alert exactly when crossing the threshold (not on every subsequent hit)
    if count == BRUTE_FORCE_THRESHOLD:
        return _make_alert(
            alert_type="BRUTE_FORCE",
            severity="HIGH",
            reason=f"Brute Force Detected — {count} failed logons in {BRUTE_FORCE_WINDOW_SEC}s for {key}",
            description=(
                f"Threshold of {BRUTE_FORCE_THRESHOLD} failed authentication attempts "
                f"within {BRUTE_FORCE_WINDOW_SEC} seconds reached for {key}. "
                "Possible credential stuffing or brute-force attack. "
                "MITRE ATT&CK: T1110 — Brute Force."
            ),
            indicators={"target": key, "count": count, "window_sec": BRUTE_FORCE_WINDOW_SEC},
            matched_pattern="FAILED LOGON / EventID 4625",
            source_logs=[raw],
            session_id=log.get("session_id", "winmon"),
        )
    return None


# ---------------------------------------------------------------------------
# Enhanced command analysis  (stateless — single-log pattern matching)
# ---------------------------------------------------------------------------

# PowerShell obfuscation patterns
_PS_OBFUSCATION = re.compile(
    r"powershell.*?(-enc|-encodedcommand|bypass|-nop|-windowstyle\s+hidden)",
    re.IGNORECASE | re.DOTALL,
)

# Credential dumping signals
_CRED_DUMP = re.compile(
    r"mimikatz|sekurlsa|lsass\.exe|procdump.*lsass|comsvcs.*minidump",
    re.IGNORECASE,
)


def check_powershell_obfuscation(log: dict) -> dict | None:
    text = f"{log.get('message', '')} {log.get('raw_line', '')}"
    if _PS_OBFUSCATION.search(text):
        matched = _PS_OBFUSCATION.search(text).group(0)[:120]
        return _make_alert(
            alert_type="SUSPICIOUS_KEYWORD",
            severity="CRITICAL",
            reason="PowerShell Obfuscation / AMSI Bypass Detected",
            description=(
                "A PowerShell command containing obfuscation flags (-enc, -EncodedCommand, "
                "-ExecutionPolicy Bypass, -WindowStyle Hidden) was detected. "
                "This is a strong indicator of malicious script execution. "
                "MITRE ATT&CK: T1059.001 — Command and Scripting Interpreter: PowerShell."
            ),
            indicators={"flags_detected": matched},
            matched_pattern=matched,
            source_logs=[text[:300]],
            session_id=log.get("session_id", "winmon"),
        )
    return None


def check_credential_dumping(log: dict) -> dict | None:
    text = f"{log.get('message', '')} {log.get('raw_line', '')}"
    if _CRED_DUMP.search(text):
        matched = _CRED_DUMP.search(text).group(0)[:80]
        return _make_alert(
            alert_type="SUSPICIOUS_KEYWORD",
            severity="CRITICAL",
            reason="Credential Dumping Tool / LSASS Access Detected",
            description=(
                "Activity consistent with credential dumping was detected "
                f"(matched: '{matched}'). Tools like Mimikatz or direct LSASS memory access "
                "are used to harvest plaintext passwords and NTLM hashes. "
                "MITRE ATT&CK: T1003 — OS Credential Dumping."
            ),
            indicators={"tool_signature": matched},
            matched_pattern=matched,
            source_logs=[text[:300]],
            session_id=log.get("session_id", "winmon"),
        )
    return None


# ---------------------------------------------------------------------------
# Unified entry point
# ---------------------------------------------------------------------------

def analyze_log(log: dict) -> list[dict]:
    """
    Run all stateful/enhanced checks on a single log dict.
    Returns a list of alert dicts (may be empty).
    Each alert dict is ready to INSERT into the alerts table.
    """
    alerts = []
    for check in (check_brute_force, check_powershell_obfuscation, check_credential_dumping):
        try:
            result = check(log)
            if result:
                alerts.append(result)
        except Exception:
            pass
    return alerts


# ---------------------------------------------------------------------------
# Internal helper
# ---------------------------------------------------------------------------

def _make_alert(
    alert_type: str,
    severity: str,
    reason: str,
    description: str,
    indicators: dict[str, Any],
    matched_pattern: str,
    source_logs: list[str],
    session_id: str,
) -> dict:
    now = datetime.now().isoformat()
    return {
        # DB columns
        "session_id":      session_id,
        "alert_id":        f"SA-{uuid.uuid4().hex[:10].upper()}",
        "alert_type":      alert_type,
        "severity":        severity,
        "reason":          reason,
        "description":     description,
        "timestamp":       now,
        "source_logs":     json.dumps(source_logs),
        "indicators":      json.dumps(indicators),
        "matched_pattern": matched_pattern,
        "confidence":      1.0,
        "metadata":        json.dumps({"engine": "stateful_detector"}),
        "created_at":      now,
    }