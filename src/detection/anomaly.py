"""Anomaly detection using statistical methods (Z-score based)."""

import logging
import statistics
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict, Iterator, List, Tuple

from src.detection.alert import Alert, AlertSeverity, AlertType
from src.detection.base import BaseDetector
from src.schema import LogLevel, NormalizedLog

logger = logging.getLogger(__name__)


class AnomalyDetector(BaseDetector):
    """Detect anomalies using statistical methods (Z-score based).

    This detector implements formal mathematical anomaly detection:
    - Z-score = (x - μ) / σ
    - Where μ is mean and σ is standard deviation
    - Anomalies are points where |Z-score| > threshold

    Features monitored:
    - Log frequency by time window
    - Error rate patterns
    - Message length variations
    - IP address diversity

    Works completely offline with no external dependencies.
    """

    def __init__(
        self,
        z_score_threshold: float = None,  # Standard deviations for anomaly
        time_window_minutes: int = None,   # Analysis window
        baseline_window_hours: int = None, # Hours of data for baseline
        min_baseline_samples: int = None,  # Minimum samples for statistics
    ):
        """Initialize statistical anomaly detector.

        Args:
            z_score_threshold: Z-score threshold for anomaly detection.
            time_window_minutes: Time window for analysis (minutes).
            baseline_window_hours: Hours of historical data for baseline.
            min_baseline_samples: Minimum samples needed for statistical analysis.

            If None, values are loaded from config.yaml
        """
        # Load from config if not provided
        if z_score_threshold is None:
            from src.config import load_config
            config = load_config()
            anomaly_config = config.get('detection', {}).get('anomaly', {})

            z_score_threshold = anomaly_config.get('z_score_threshold', 3.0)
            time_window_minutes = anomaly_config.get('time_window_minutes', 10)
            baseline_window_hours = anomaly_config.get('baseline_window_hours', 24)
            min_baseline_samples = anomaly_config.get('min_baseline_samples', 50)

        self.z_score_threshold = z_score_threshold
        self.time_window_minutes = time_window_minutes
        self.baseline_window_hours = baseline_window_hours
        self.min_baseline_samples = min_baseline_samples

        # Statistical baselines for different metrics
        self.frequency_baseline: deque = deque(maxlen=1000)  # Log frequency per window
        self.error_rate_baseline: deque = deque(maxlen=1000)  # Error log ratio
        self.message_length_baseline: deque = deque(maxlen=1000)  # Average message length
        self.ip_diversity_baseline: deque = deque(maxlen=1000)  # Unique IPs per window

        # Track recent activity
        self.recent_logs: List[Tuple[datetime, NormalizedLog]] = []

    @property
    def name(self) -> str:
        return "AnomalyDetector"

    @property
    def description(self) -> str:
        return "Statistical anomaly detection using Z-score analysis"

    def detect(self, logs: Iterator[NormalizedLog]) -> Iterator[Alert]:
        """Detect anomalies using statistical analysis."""
        # Convert to list for analysis (could be optimized for streaming)
        log_list = list(logs)

        if len(log_list) < 10:  # Need minimum data for analysis
            return

        # Update baselines with historical data
        self._update_baselines(log_list)

        # Analyze current window
        current_window = self._get_current_window(log_list)

        if not current_window:
            return

        # Check different anomaly types
        yield from self._detect_frequency_anomaly(current_window)
        yield from self._detect_error_rate_anomaly(current_window)
        yield from self._detect_message_length_anomaly(current_window)
        yield from self._detect_ip_diversity_anomaly(current_window)

    def _update_baselines(self, logs: List[NormalizedLog]) -> None:
        """Update statistical baselines with log data."""
        # Group logs by time windows
        window_size = timedelta(minutes=self.time_window_minutes)
        windows = self._group_by_windows(logs, window_size)

        for window_logs in windows.values():
            # Frequency (logs per window)
            self.frequency_baseline.append(len(window_logs))

            # Error rate (ratio of error/critical logs)
            error_count = sum(1 for log in window_logs
                            if log.level in [LogLevel.ERROR, LogLevel.CRITICAL])
            error_rate = error_count / len(window_logs) if window_logs else 0
            self.error_rate_baseline.append(error_rate)

            # Message length (average)
            if window_logs:
                avg_length = sum(len(log.message) for log in window_logs) / len(window_logs)
                self.message_length_baseline.append(avg_length)

            # IP diversity (unique IPs)
            unique_ips = set()
            for log in window_logs:
                ip = self._extract_ip(log)
                if ip:
                    unique_ips.add(ip)
            self.ip_diversity_baseline.append(len(unique_ips))

    def _get_current_window(self, logs: List[NormalizedLog]) -> List[NormalizedLog]:
        """Get logs from the most recent time window."""
        if not logs:
            return []

        # Sort by timestamp
        logs.sort(key=lambda x: x.timestamp)

        # Get most recent window
        window_size = timedelta(minutes=self.time_window_minutes)
        latest_time = logs[-1].timestamp
        window_start = latest_time - window_size

        return [log for log in logs if log.timestamp >= window_start]

    def _detect_frequency_anomaly(self, current_window: List[NormalizedLog]) -> Iterator[Alert]:
        """Detect anomalous log frequency using Z-score."""
        if len(self.frequency_baseline) < self.min_baseline_samples:
            return

        current_frequency = len(current_window)

        try:
            mean = statistics.mean(self.frequency_baseline)
            stdev = statistics.stdev(self.frequency_baseline)

            if stdev > 0:
                z_score = abs(current_frequency - mean) / stdev

                if z_score > self.z_score_threshold:
                    direction = "high" if current_frequency > mean else "low"

                    yield Alert(
                        id=self._generate_alert_id("FREQ_ANOMALY", "system", str(current_frequency)),
                        alert_type=AlertType.ANOMALY,
                        severity=AlertSeverity.MEDIUM if z_score < 4 else AlertSeverity.HIGH,
                        reason=f"Anomalous log frequency detected ({direction})",
                        description=self._format_frequency_description(
                            current_frequency, mean, stdev, z_score
                        ),
                        source_logs=[log.raw_line for log in current_window[:3]],
                        indicators={
                            "metric": "frequency",
                            "current_value": current_frequency,
                            "mean": mean,
                            "z_score": z_score,
                            "direction": direction
                        },
                        matched_pattern=f"Z-score: {z_score:.2f} > {self.z_score_threshold}",
                        confidence=min(0.9, z_score / (self.z_score_threshold * 2)),
                        metadata={
                            "anomaly_type": "frequency",
                            "z_score_threshold": self.z_score_threshold,
                            "baseline_samples": len(self.frequency_baseline),
                            "time_window_minutes": self.time_window_minutes
                        },
                    )
        except statistics.StatisticsError:
            pass  # Not enough data for statistics

    def _detect_error_rate_anomaly(self, current_window: List[NormalizedLog]) -> Iterator[Alert]:
        """Detect anomalous error rates."""
        if len(self.error_rate_baseline) < self.min_baseline_samples or not current_window:
            return

        error_count = sum(1 for log in current_window
                         if log.level in [LogLevel.ERROR, LogLevel.CRITICAL])
        current_error_rate = error_count / len(current_window)

        try:
            mean = statistics.mean(self.error_rate_baseline)
            stdev = statistics.stdev(self.error_rate_baseline)

            if stdev > 0:
                z_score = abs(current_error_rate - mean) / stdev

                if z_score > self.z_score_threshold:
                    direction = "high" if current_error_rate > mean else "low"

                    yield Alert(
                        id=self._generate_alert_id("ERROR_RATE_ANOMALY", "system", f"{error_count}/{len(current_window)}"),
                        alert_type=AlertType.ANOMALY,
                        severity=AlertSeverity.HIGH,  # Error rate anomalies are concerning
                        reason=f"Anomalous error rate detected ({direction})",
                        description=self._format_error_rate_description(
                            current_error_rate, error_count, len(current_window), mean, stdev, z_score
                        ),
                        source_logs=[log.raw_line for log in current_window if log.level in [LogLevel.ERROR, LogLevel.CRITICAL]][:3],
                        indicators={
                            "metric": "error_rate",
                            "current_error_rate": current_error_rate,
                            "error_count": error_count,
                            "total_logs": len(current_window),
                            "mean": mean,
                            "z_score": z_score
                        },
                        matched_pattern=f"Error rate Z-score: {z_score:.2f}",
                        confidence=min(0.95, z_score / (self.z_score_threshold * 2)),
                        metadata={
                            "anomaly_type": "error_rate",
                            "z_score_threshold": self.z_score_threshold,
                            "baseline_samples": len(self.error_rate_baseline)
                        },
                    )
        except statistics.StatisticsError:
            pass

    def _detect_message_length_anomaly(self, current_window: List[NormalizedLog]) -> Iterator[Alert]:
        """Detect anomalous message length patterns."""
        if len(self.message_length_baseline) < self.min_baseline_samples or not current_window:
            return

        current_avg_length = sum(len(log.message) for log in current_window) / len(current_window)

        try:
            mean = statistics.mean(self.message_length_baseline)
            stdev = statistics.stdev(self.message_length_baseline)

            if stdev > 0:
                z_score = abs(current_avg_length - mean) / stdev

                if z_score > self.z_score_threshold:
                    direction = "long" if current_avg_length > mean else "short"

                    yield Alert(
                        id=self._generate_alert_id("MSG_LEN_ANOMALY", "system", f"{current_avg_length:.1f}"),
                        alert_type=AlertType.ANOMALY,
                        severity=AlertSeverity.LOW,  # Message length anomalies are less critical
                        reason=f"Anomalous message length pattern ({direction})",
                        description=self._format_message_length_description(
                            current_avg_length, mean, stdev, z_score
                        ),
                        source_logs=[log.raw_line for log in current_window[:2]],
                        indicators={
                            "metric": "message_length",
                            "current_avg_length": current_avg_length,
                            "mean": mean,
                            "z_score": z_score
                        },
                        matched_pattern=f"Message length Z-score: {z_score:.2f}",
                        confidence=min(0.8, z_score / (self.z_score_threshold * 2)),
                        metadata={
                            "anomaly_type": "message_length",
                            "z_score_threshold": self.z_score_threshold
                        },
                    )
        except statistics.StatisticsError:
            pass

    def _detect_ip_diversity_anomaly(self, current_window: List[NormalizedLog]) -> Iterator[Alert]:
        """Detect anomalous IP diversity patterns."""
        if len(self.ip_diversity_baseline) < self.min_baseline_samples:
            return

        unique_ips = set()
        for log in current_window:
            ip = self._extract_ip(log)
            if ip:
                unique_ips.add(ip)

        current_diversity = len(unique_ips)

        try:
            mean = statistics.mean(self.ip_diversity_baseline)
            stdev = statistics.stdev(self.ip_diversity_baseline)

            if stdev > 0:
                z_score = abs(current_diversity - mean) / stdev

                if z_score > self.z_score_threshold:
                    direction = "high" if current_diversity > mean else "low"

                    yield Alert(
                        id=self._generate_alert_id("IP_DIVERSITY_ANOMALY", "system", str(current_diversity)),
                        alert_type=AlertType.ANOMALY,
                        severity=AlertSeverity.MEDIUM,
                        reason=f"Anomalous IP diversity detected ({direction})",
                        description=self._format_ip_diversity_description(
                            current_diversity, mean, stdev, z_score
                        ),
                        source_logs=[log.raw_line for log in current_window[:3]],
                        indicators={
                            "metric": "ip_diversity",
                            "current_diversity": current_diversity,
                            "unique_ips": list(unique_ips),
                            "mean": mean,
                            "z_score": z_score
                        },
                        matched_pattern=f"IP diversity Z-score: {z_score:.2f}",
                        confidence=min(0.85, z_score / (self.z_score_threshold * 2)),
                        metadata={
                            "anomaly_type": "ip_diversity",
                            "z_score_threshold": self.z_score_threshold
                        },
                    )
        except statistics.StatisticsError:
            pass

    def _extract_ip(self, log: NormalizedLog) -> str | None:
        """Extract IP address from log."""
        # Try metadata first
        if ip := log.metadata.get("ip") or log.metadata.get("source_ip"):
            return ip

        # Try to extract from raw line
        import re
        ip_pattern = re.compile(r"\b\d{1,3}(\.\d{1,3}){3}\b")
        match = ip_pattern.search(log.raw_line)
        return match.group(0) if match else None

    def _group_by_windows(self, logs: List[NormalizedLog], window_size: timedelta) -> Dict[datetime, List[NormalizedLog]]:
        """Group logs by time windows."""
        windows = defaultdict(list)

        for log in logs:
            # Round timestamp to window boundary
            window_start = log.timestamp.replace(second=0, microsecond=0)
            minutes = (log.timestamp.minute // self.time_window_minutes) * self.time_window_minutes
            window_start = window_start.replace(minute=minutes)

            windows[window_start].append(log)

        return windows

    def _format_frequency_description(self, current: int, mean: float, stdev: float, z_score: float) -> str:
        """Format frequency anomaly description."""
        return (
            f"Log frequency of {current} events in {self.time_window_minutes}min window "
            f"is anomalous (Z-score: {z_score:.2f}). "
            f"Baseline: μ={mean:.1f}, σ={stdev:.1f}"
        )

    def _format_error_rate_description(self, rate: float, errors: int, total: int, mean: float, stdev: float, z_score: float) -> str:
        """Format error rate anomaly description."""
        return (
            f"Error rate of {rate:.3f} ({errors}/{total} logs) in {self.time_window_minutes}min window "
            f"is anomalous (Z-score: {z_score:.2f}). "
            f"Baseline: μ={mean:.3f}, σ={stdev:.3f}"
        )

    def _format_message_length_description(self, current: float, mean: float, stdev: float, z_score: float) -> str:
        """Format message length anomaly description."""
        return (
            f"Average message length of {current:.1f} characters "
            f"is anomalous (Z-score: {z_score:.2f}). "
            f"Baseline: μ={mean:.1f}, σ={stdev:.1f}"
        )

    def _format_ip_diversity_description(self, current: int, mean: float, stdev: float, z_score: float) -> str:
        """Format IP diversity anomaly description."""
        return (
            f"IP diversity of {current} unique addresses "
            f"is anomalous (Z-score: {z_score:.2f}). "
            f"Baseline: μ={mean:.1f}, σ={stdev:.1f}"
        )


class MLAnomalyDetector(BaseDetector):
    """Anomaly detection using Isolation Forest (requires scikit-learn).

    Optional ML-based detector complementing the statistical AnomalyDetector.
    Install scikit-learn to enable: pip install scikit-learn
    """

    def __init__(
        self,
        contamination: float = 0.1,
        n_estimators: int = 100,
        threshold: float = 0.5,
    ):
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.threshold = threshold
        self._model = None

    @property
    def name(self) -> str:
        return "MLAnomalyDetector"

    @property
    def description(self) -> str:
        return "Anomaly detection using Isolation Forest (requires scikit-learn)"

    def detect(self, logs: Iterator[NormalizedLog]) -> Iterator[Alert]:
        """Detect anomalies using Isolation Forest."""
        log_list = list(logs)

        if len(log_list) < 10:
            logger.warning("Not enough logs for ML anomaly detection")
            return

        features = self._extract_features(log_list)
        if features.shape[0] == 0:
            return

        try:
            from sklearn.ensemble import IsolationForest
            import numpy as np  # noqa: F401 — guarded by ImportError below

            self._model = IsolationForest(
                contamination=self.contamination,
                n_estimators=self.n_estimators,
                random_state=42,
            )
            self._model.fit(features)
            predictions = self._model.predict(features)
            scores = self._model.score_samples(features)

            for log, pred, score in zip(log_list, predictions, scores):
                if pred == -1 and score < (1 - self.threshold):
                    yield self._create_alert(log, score)
        except ImportError:
            logger.error("sklearn not installed. Install with: pip install scikit-learn")
        except Exception as e:
            logger.error(f"ML anomaly detection error: {e}")

    def _extract_features(self, logs: list) -> "np.ndarray":
        """Extract numerical features from logs."""
        try:
            import numpy as np
        except ImportError:
            raise RuntimeError("numpy required for MLAnomalyDetector: pip install numpy")

        level_map = {"DEBUG": 0, "INFO": 1, "WARNING": 2, "ERROR": 3, "CRITICAL": 4, "UNKNOWN": 0}
        features = []
        for log in logs:
            features.append([
                log.timestamp.hour,
                log.timestamp.weekday(),
                level_map.get(log.level.value, 0),
                len(log.message),
                1 if any(k in log.metadata for k in ["ip", "source_ip", "client_ip", "remote_addr"]) else 0,
                1 if any(k in log.metadata for k in ["username", "user", "account"]) else 0,
            ])
        return np.array(features)

    def _create_alert(self, log: NormalizedLog, score: float) -> Alert:
        """Create alert for anomalous log."""
        anomaly_score = abs(score)
        severity = (
            AlertSeverity.HIGH if anomaly_score > 0.8
            else AlertSeverity.MEDIUM if anomaly_score > 0.6
            else AlertSeverity.LOW
        )
        return Alert(
            id=self._generate_alert_id("ML_ANO", str(int(score * 100))),
            alert_type=AlertType.ANOMALY,
            severity=severity,
            reason="Anomalous log pattern detected (ML)",
            description=f"Log entry deviates from normal patterns (anomaly score: {anomaly_score:.2f})",
            source_logs=[log.raw_line],
            indicators={"anomaly_score": float(anomaly_score), "timestamp": log.timestamp.isoformat()},
            matched_pattern=f"score={score:.3f}",
            confidence=float(anomaly_score),
            metadata={
                "log_level": log.level.value,
                "logger": log.logger,
                "message_length": len(log.message),
            },
        )