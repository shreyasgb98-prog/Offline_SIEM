"""Brute force detection with statistical analysis."""

import logging
import statistics
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, Iterator, List

from src.detection.alert import Alert, AlertSeverity, AlertType
from src.detection.base import BaseDetector
from src.schema import LogLevel, NormalizedLog

logger = logging.getLogger(__name__)


class BruteForceDetector(BaseDetector):
    """Advanced brute force detection with statistical analysis.

    Features:
    - Time-window based detection (N events within T seconds)
    - Moving average analysis for baseline comparison
    - Frequency deviation detection
    - Configurable thresholds via config file
    - Reduced false positives through statistical validation
    """

    def __init__(
        self,
        threshold: int = None,
        window_seconds: int = None,
        severity_threshold: int = None,
        moving_avg_window: int = None,
        deviation_threshold: float = None,
        min_baseline_events: int = None,
    ):
        """Initialize detector with statistical parameters.

        Args:
            threshold: Number of failures to trigger alert (absolute).
            window_seconds: Time window in seconds for analysis.
            severity_threshold: Number of failures for CRITICAL severity.
            moving_avg_window: Number of time windows to maintain for baseline.
            deviation_threshold: Standard deviations above mean for anomaly detection.
            min_baseline_events: Minimum events needed before statistical analysis.

            If None, values are loaded from config.yaml
        """
        # Load from config if not provided
        if threshold is None:
            from src.config import load_config
            config = load_config()
            bf_config = config.get('detection', {}).get('brute_force', {})

            threshold = bf_config.get('threshold', 5)
            window_seconds = bf_config.get('window_seconds', 300)
            severity_threshold = bf_config.get('severity_threshold', 20)
            moving_avg_window = bf_config.get('moving_avg_window', 10)
            deviation_threshold = bf_config.get('deviation_threshold', 2.0)
            min_baseline_events = bf_config.get('min_baseline_events', 50)

        self.threshold = threshold
        self.window_seconds = window_seconds
        self.severity_threshold = severity_threshold
        self.moving_avg_window = moving_avg_window
        self.deviation_threshold = deviation_threshold
        self.min_baseline_events = min_baseline_events

        # Statistical tracking per source
        self.baseline_data: Dict[str, deque] = defaultdict(lambda: deque(maxlen=moving_avg_window))

    @property
    def name(self) -> str:
        return "BruteForceDetector"

    @property
    def description(self) -> str:
        return "Advanced brute force detection with statistical analysis"

    def detect(self, logs: Iterator[NormalizedLog]) -> Iterator[Alert]:
        """Detect brute force patterns using statistical analysis."""
        # Track failures by source with timestamps
        failures: Dict[str, List[datetime]] = defaultdict(list)

        # Convert iterator to list for multiple passes (could be optimized with streaming)
        log_list = list(logs)

        # First pass: collect all failure timestamps
        for log in log_list:
            if self._is_auth_failure(log):
                key = self._get_identifier(log)
                if key:
                    failures[key].append(log.timestamp)

        # Analyze each source
        for source, timestamps in failures.items():
            alerts = self._analyze_failures_statistical(source, timestamps)
            yield from alerts

    def _analyze_failures_statistical(self, source: str, timestamps: List[datetime]) -> Iterator[Alert]:
        """Analyze failures using statistical methods."""
        if len(timestamps) < 2:
            return

        # Sort timestamps
        timestamps.sort()

        # Calculate failure frequency in sliding windows
        window_start = timestamps[0]
        window_failures = []

        for ts in timestamps:
            # Check if we're still in current window
            if ts <= window_start + timedelta(seconds=self.window_seconds):
                window_failures.append(ts)
            else:
                # Process current window
                if window_failures:
                    alerts = self._process_window(source, window_failures)
                    yield from alerts

                # Start new window
                window_start = ts
                window_failures = [ts]

        # Process final window
        if window_failures:
            alerts = self._process_window(source, window_failures)
            yield from alerts

    def _process_window(self, source: str, window_timestamps: List[datetime]) -> Iterator[Alert]:
        """Process a single time window of failures."""
        failure_count = len(window_timestamps)

        # Absolute threshold check
        if failure_count >= self.threshold:
            # Statistical validation
            is_statistical_anomaly = self._is_statistical_anomaly(source, failure_count)

            if is_statistical_anomaly or failure_count >= self.severity_threshold:
                severity = self._calculate_severity(failure_count, is_statistical_anomaly)

                yield Alert(
                    id=self._generate_alert_id("BRUTE", source, str(failure_count)),
                    alert_type=AlertType.BRUTE_FORCE,
                    severity=severity,
                    reason=f"Brute force attack detected from {source}",
                    description=self._generate_description(failure_count, is_statistical_anomaly),
                    source_logs=[],  # Would need raw logs, but we only have timestamps here
                    indicators={
                        "source": source,
                        "failure_count": failure_count,
                        "time_window_seconds": self.window_seconds,
                        "statistical_anomaly": is_statistical_anomaly
                    },
                    matched_pattern=f"{failure_count} failures in {self.window_seconds}s window",
                    confidence=self._calculate_confidence(failure_count, is_statistical_anomaly),
                    metadata={
                        "threshold": self.threshold,
                        "window_seconds": self.window_seconds,
                        "first_failure": window_timestamps[0].isoformat(),
                        "last_failure": window_timestamps[-1].isoformat(),
                        "failure_rate": failure_count / self.window_seconds,  # failures per second
                    },
                )

    def _is_statistical_anomaly(self, source: str, current_count: int) -> bool:
        """Check if current failure count is statistically anomalous."""
        baseline = self.baseline_data[source]

        if len(baseline) < max(3, self.min_baseline_events // 10):  # Need some baseline data
            # Update baseline with current count
            baseline.append(current_count)
            return False  # Not enough data for statistical analysis

        try:
            # Calculate statistical measures
            mean = statistics.mean(baseline)
            stdev = statistics.stdev(baseline) if len(baseline) > 1 else 0

            if stdev == 0:
                # All baseline values are the same, compare to mean
                is_anomaly = current_count > mean * 1.5
            else:
                # Z-score based anomaly detection
                z_score = (current_count - mean) / stdev
                is_anomaly = z_score > self.deviation_threshold

            # Update baseline with current count
            baseline.append(current_count)

            return is_anomaly

        except statistics.StatisticsError:
            # Not enough data for statistics
            baseline.append(current_count)
            return False

    def _calculate_severity(self, failure_count: int, is_statistical_anomaly: bool) -> AlertSeverity:
        """Calculate alert severity based on failure count and statistical anomaly."""
        if failure_count >= self.severity_threshold:
            return AlertSeverity.CRITICAL
        elif is_statistical_anomaly or failure_count >= self.threshold * 2:
            return AlertSeverity.HIGH
        elif failure_count >= self.threshold * 1.5:
            return AlertSeverity.MEDIUM
        else:
            return AlertSeverity.LOW

    def _generate_description(self, failure_count: int, is_statistical_anomaly: bool) -> str:
        """Generate detailed alert description."""
        base_desc = f"Detected {failure_count} authentication failures within {self.window_seconds} seconds"

        if is_statistical_anomaly:
            base_desc += " (statistically anomalous compared to baseline)"
        else:
            base_desc += f" (exceeds threshold of {self.threshold})"

        return base_desc

    def _calculate_confidence(self, failure_count: int, is_statistical_anomaly: bool) -> float:
        """Calculate confidence score for the alert."""
        base_confidence = min(0.9, failure_count / (self.threshold * 2))  # Scale with severity

        if is_statistical_anomaly:
            return min(0.95, base_confidence + 0.1)  # Boost confidence for statistical anomalies
        else:
            return base_confidence
        # Track failures by source IP / identifier
        failures: dict[str, list[NormalizedLog]] = defaultdict(list)

        for log in logs:
            # Look for authentication failure indicators
            if self._is_auth_failure(log):
                key = self._get_identifier(log)
                if key:
                    failures[key].append(log)

        # Analyze each source
        for source, log_entries in failures.items():
            alerts = self._analyze_failures(source, log_entries)
            yield from alerts

    def _is_auth_failure(self, log: NormalizedLog) -> bool:
        """Check if log indicates an authentication failure."""
        msg_lower = log.message.lower()
        failure_indicators = [
            "fail", "failed", "failure", "error",
            "invalid credentials",
            "authentication failed",
            "login failed",
            "bad credentials",
            "wrong password",
            "invalid username",
            "account locked",
            "access denied",
            "unauthorized",
            "failed login",
            "登入失败",  # Chinese
            "认证失败",
        ]
        return any(ind in msg_lower for ind in failure_indicators)

    def _get_identifier(self, log: NormalizedLog) -> str | None:
        """Get source identifier (IP, user, etc.) from log."""
        # Try metadata first
        if ip := log.metadata.get("ip") or log.metadata.get("source_ip"):
            return ip

        # Try to extract IP from raw line
        import re
        ip_pattern = re.compile(r"\b\d{1,3}(\.\d{1,3}){3}\b")
        match = ip_pattern.search(log.raw_line)
        if match:
            return match.group(0)

        # Try from logger name
        if log.logger:
            return log.logger

        # Try from source
        if log.source:
            return log.source

        return None

    def _analyze_failures(self, source: str, log_entries: list[NormalizedLog]) -> Iterator[Alert]:
        """Analyze failures from a single source."""
        if not log_entries:
            return

        # Sort by timestamp
        log_entries.sort(key=lambda x: x.timestamp)

        # Check for rapid failures within time window
        window_start = log_entries[0].timestamp
        window_end = window_start + timedelta(minutes=self.window_minutes)

        recent_failures = [l for l in log_entries if window_start <= l.timestamp <= window_end]

        if len(recent_failures) >= self.threshold:
            # Determine severity
            if len(recent_failures) >= self.severity_threshold:
                severity = AlertSeverity.CRITICAL
            elif len(recent_failures) >= self.threshold * 1.5:
                severity = AlertSeverity.HIGH
            else:
                severity = AlertSeverity.MEDIUM

            # Create alert
            yield Alert(
                id=self._generate_alert_id("BRUTE", source, str(len(recent_failures))),
                alert_type=AlertType.BRUTE_FORCE,
                severity=severity,
                reason=f"Brute force attack detected from {source}",
                description=f"Detected {len(recent_failures)} authentication failures within {self.window_minutes} minutes",
                source_logs=[log.raw_line for log in recent_failures[:5]],  # First 5 as samples
                indicators={"source": source, "failure_count": len(recent_failures)},
                matched_pattern=f"{len(recent_failures)} failures in {self.window_minutes}min window",
                confidence=0.9,
                metadata={
                    "threshold": self.threshold,
                    "window_minutes": self.window_minutes,
                    "first_failure": recent_failures[0].timestamp.isoformat(),
                    "last_failure": recent_failures[-1].timestamp.isoformat(),
                },
            )