"""Detection engine that combines all detectors."""

import logging
from typing import Iterator, List

from src.detection.alert import Alert
from src.detection.anomaly import AnomalyDetector
from src.detection.base import BaseDetector
from src.detection.brute_force import BruteForceDetector
from src.detection.failed_login import FailedLoginDetector
from src.detection.keyword_detector import KeywordDetector
from src.detection.threat_intel import ThreatIntelDetector
from src.schema import NormalizedLog

logger = logging.getLogger(__name__)


class DetectionEngine:
    """Unified detection engine combining all detectors.

    Runs multiple detection strategies and aggregates results.
    """

    def __init__(
        self,
        enable_brute_force: bool = True,
        enable_failed_login: bool = True,
        enable_keyword: bool = True,
        enable_threat_intel: bool = True,
        enable_anomaly: bool = True,
        config: dict | None = None,
        **detector_kwargs,
    ):
        """Initialize detection engine.

        Args:
            enable_brute_force: Enable brute force detector.
            enable_failed_login: Enable failed login detector.
            enable_keyword: Enable keyword detector.
            enable_threat_intel: Enable threat intel detector.
            enable_anomaly: Enable anomaly detector.
            config: Optional configuration dictionary.
            **detector_kwargs: Arguments passed to detectors.
        """
        config = config or load_config()
        detection_config = config.get("detection", {})
        brute_conf = detection_config.get("brute_force", {})
        anomaly_conf = detection_config.get("anomaly", {})
        failed_conf = detection_config.get("failed_login", {})
        threat_conf = detection_config.get("threat_intel", {})

        self.detectors: List[BaseDetector] = []

        if enable_brute_force:
            self.detectors.append(
                BruteForceDetector(
                    threshold=detector_kwargs.get("threshold", brute_conf.get("threshold", 5)),
                    window_seconds=detector_kwargs.get("window_seconds", brute_conf.get("window_seconds", 300)),
                    severity_threshold=detector_kwargs.get("severity_threshold", brute_conf.get("severity_threshold", 20)),
                    moving_avg_window=detector_kwargs.get("moving_avg_window", brute_conf.get("moving_avg_window", 10)),
                    deviation_threshold=detector_kwargs.get("deviation_threshold", brute_conf.get("deviation_threshold", 2.0)),
                    min_baseline_events=detector_kwargs.get("min_baseline_events", brute_conf.get("min_baseline_events", 50)),
                )
            )

        if enable_failed_login:
            self.detectors.append(
                FailedLoginDetector(
                    user_threshold=detector_kwargs.get("user_threshold", failed_conf.get("user_threshold", 5)),
                    window_minutes=detector_kwargs.get("window_minutes", failed_conf.get("window_minutes", 30)),
                )
            )

        if enable_keyword:
            self.detectors.append(
                KeywordDetector(
                    keywords=detector_kwargs.get("keywords", None),
                    case_sensitive=detector_kwargs.get("case_sensitive", False),
                )
            )

        if enable_threat_intel:
            intel_dir = threat_conf.get("intel_dir")
            intel_manager = ThreatIntelManager(Path(intel_dir)) if intel_dir else ThreatIntelManager()
            self.detectors.append(ThreatIntelDetector(intel_manager=intel_manager))

        if enable_anomaly:
            self.detectors.append(
                AnomalyDetector(
                    z_score_threshold=detector_kwargs.get("z_score_threshold", anomaly_conf.get("z_score_threshold", 3.0)),
                    time_window_minutes=detector_kwargs.get("time_window_minutes", anomaly_conf.get("time_window_minutes", 10)),
                    baseline_window_hours=detector_kwargs.get("baseline_window_hours", anomaly_conf.get("baseline_window_hours", 24)),
                    min_baseline_samples=detector_kwargs.get("min_baseline_samples", anomaly_conf.get("min_baseline_samples", 50)),
                )
            )

        logger.info(f"Initialized DetectionEngine with {len(self.detectors)} detectors")

    @property
    def detector_names(self) -> list[str]:
        """Get list of enabled detector names."""
        return [d.name for d in self.detectors]

    def detect(self, logs: Iterator[NormalizedLog]) -> Iterator[Alert]:
        """Run all detectors on log stream.

        Args:
            logs: Iterator of normalized log entries.

        Yields:
            Alert instances from all detectors.
        """
        # Convert to list for multiple passes
        log_list = list(logs)
        logger.info(f"Processing {len(log_list)} logs with {len(self.detectors)} detectors")

        # Run each detector
        for detector in self.detectors:
            logger.info(f"Running detector: {detector.name}")
            try:
                yield from detector.detect(iter(log_list))
            except Exception as e:
                logger.error(f"Error in {detector.name}: {e}")

    def detect_batch(self, logs: list[NormalizedLog]) -> list[Alert]:
        """Run all detectors on a batch of logs.

        Args:
            logs: List of normalized log entries.

        Returns:
            List of all alerts.
        """
        alerts = list(self.detect(iter(logs)))
        logger.info(f"Generated {len(alerts)} alerts")
        return alerts

    def get_alerts_by_severity(self, alerts: list[Alert], severity: str) -> list[Alert]:
        """Filter alerts by severity."""
        from src.detection.alert import AlertSeverity

        try:
            sev = AlertSeverity(severity.upper())
            return [a for a in alerts if a.severity == sev]
        except ValueError:
            return []

    def get_alerts_by_type(self, alerts: list[Alert], alert_type: str) -> list[Alert]:
        """Filter alerts by type."""
        from src.detection.alert import AlertType

        try:
            at = AlertType(alert_type.upper())
            return [a for a in alerts if a.alert_type == at]
        except ValueError:
            return []

    def get_alert_summary(self, alerts: list[Alert]) -> dict:
        """Get summary statistics of alerts."""
        from src.detection.alert import AlertSeverity, AlertType

        summary = {
            "total": len(alerts),
            "by_severity": {s.value: 0 for s in AlertSeverity},
            "by_type": {t.value: 0 for t in AlertType},
        }

        for alert in alerts:
            summary["by_severity"][alert.severity.value] += 1
            summary["by_type"][alert.alert_type.value] += 1

        return summary