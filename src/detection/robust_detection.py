"""Robust detection engine for log analysis."""

import logging
import re
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List

logger = logging.getLogger(__name__)


class Alert:
    """Simple alert structure."""

    def __init__(self, alert_type: str, severity: str, reason: str, description: str = "",
                 ip: str = "", count: int = 0):
        self.alert_type = alert_type
        self.severity = severity
        self.reason = reason
        self.description = description
        self.ip = ip
        self.count = count


class RobustDetectionEngine:
    """Detection engine that works with simple log dicts."""

    def __init__(self):
        self.brute_force_threshold = 5
        self.brute_force_window_minutes = 5

    def detect(self, logs: List[dict]) -> List[Alert]:
        """Run detection on logs and return alerts."""
        alerts = []

        # Brute force detection
        brute_alerts = self._detect_brute_force(logs)
        alerts.extend(brute_alerts)

        return alerts

    def _detect_brute_force(self, logs: List[dict]) -> List[Alert]:
        """Detect brute force attacks."""
        # Group failures by IP
        failures_by_ip: Dict[str, List[dict]] = defaultdict(list)

        for log in logs:
            if self._is_failure_log(log):
                ip = log.get("ip", "")
                if ip:
                    failures_by_ip[ip].append(log)

        alerts = []
        for ip, failures in failures_by_ip.items():
            if len(failures) >= self.brute_force_threshold:
                # Check if they are within time window
                if self._are_failures_recent(failures):
                    severity = "HIGH" if len(failures) >= 10 else "MEDIUM"
                    alert = Alert(
                        alert_type="BRUTE_FORCE",
                        severity=severity,
                        reason=f"Brute force suspected from {ip}",
                        description=f"Detected {len(failures)} authentication failures",
                        ip=ip,
                        count=len(failures)
                    )
                    alerts.append(alert)

        return alerts

    def _is_failure_log(self, log: dict) -> bool:
        """Check if log indicates a failure."""
        event = log.get("event", "").lower()
        raw = log.get("raw", "").lower()

        failure_keywords = ["fail", "failed", "failure", "error"]
        return any(keyword in event for keyword in failure_keywords) or \
               any(keyword in raw for keyword in failure_keywords)

    def _are_failures_recent(self, failures: List[dict]) -> bool:
        """Check if failures are within the time window."""
        if len(failures) < 2:
            return True  # Single failure is recent enough

        # Try to parse timestamps
        timestamps = []
        for failure in failures:
            ts_str = failure.get("timestamp", "")
            if ts_str:
                try:
                    dt = datetime.fromisoformat(ts_str)
                    timestamps.append(dt)
                except ValueError:
                    pass

        if len(timestamps) < 2:
            return True  # Can't determine time, assume recent

        timestamps.sort()
        time_span = timestamps[-1] - timestamps[0]
        return time_span <= timedelta(minutes=self.brute_force_window_minutes)


def detect_alerts(logs: List[dict]) -> List[Alert]:
    """Main entry point for detection."""
    engine = RobustDetectionEngine()
    return engine.detect(logs)