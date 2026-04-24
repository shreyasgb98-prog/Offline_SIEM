"""Suspicious keyword detection."""

import logging
import re
from typing import Iterator

from src.detection.alert import Alert, AlertSeverity, AlertType
from src.detection.base import BaseDetector
from src.schema import NormalizedLog

logger = logging.getLogger(__name__)


class KeywordDetector(BaseDetector):
    """Detect suspicious keywords in log messages.

    Monitors for security-relevant keywords and patterns.
    """

    # Default suspicious keywords with severity mapping
    DEFAULT_KEYWORDS = {
        # Critical - immediate security concern
        AlertSeverity.CRITICAL: [
            r"sql\s+injection",
            r"xss\s+attack",
            r"command\s+injection",
            r"remote\s+code\s+execution",
            r"rce\b",
            r"buffer\s+overflow",
            r"zero.?day",
            r"exploit\s+kit",
        ],
        # High - serious security concern
        AlertSeverity.HIGH: [
            r"unauthorized\s+access",
            r"privilege\s+escalation",
            r"data\s+exfiltration",
            r"data\s+breach",
            r"credential\s+theft",
            r"password\s+dump",
            r"reverse\s+shell",
            r"bind\s+shell",
        ],
        # Medium - potential security concern
        AlertSeverity.MEDIUM: [
            r"injection",
            r"script\s+injection",
            r"path\s+traversal",
            r"directory\s+traversal",
            r"csrf",
            r"cross[\-\s]site",
            r"session\s+hijack",
            r"man[\-\s]in[\-\s]the[\-\s]middle",
        ],
        # Low - informational
        AlertSeverity.LOW: [
            r"suspicious",
            r"anomal",
            r"unusual\s+activity",
            r"failed\s+attempt",
            r"blocked",
            r"denied",
            r"forbidden",
        ],
    }

    def __init__(
        self,
        keywords: dict[AlertSeverity, list[str]] | None = None,
        case_sensitive: bool = False,
    ):
        """Initialize detector.

        Args:
            keywords: Custom keywords dict mapping severity to patterns.
                If None, uses default keywords.
            case_sensitive: Whether matching is case-sensitive.
        """
        self.keywords = keywords or self.DEFAULT_KEYWORDS
        self.case_sensitive = case_sensitive

        # Compile patterns
        self._compiled_patterns: dict[AlertSeverity, list[re.Pattern]] = {}
        for severity, patterns in self.keywords.items():
            self._compiled_patterns[severity] = [
                re.compile(p, re.IGNORECASE if not case_sensitive else 0)
                for p in patterns
            ]

    @property
    def name(self) -> str:
        return "KeywordDetector"

    @property
    def description(self) -> str:
        return "Detects suspicious keywords and patterns"

    def detect(self, logs: Iterator[NormalizedLog]) -> Iterator[Alert]:
        """Detect suspicious keywords."""
        for log in logs:
            yield from self._check_log(log)

    def _check_log(self, log: NormalizedLog) -> Iterator[Alert]:
        """Check a single log for suspicious keywords."""
        message = log.message
        if not self.case_sensitive:
            message = message.lower()

        # Check each severity level
        for severity, patterns in self._compiled_patterns.items():
            for pattern in patterns:
                match = pattern.search(log.message)
                if match:
                    yield self._create_alert(log, severity, pattern.pattern, match.group(0))

    def _create_alert(
        self,
        log: NormalizedLog,
        severity: AlertSeverity,
        pattern: str,
        matched: str,
    ) -> Alert:
        """Create an alert for a matched keyword."""
        return Alert(
            id=self._generate_alert_id("KW", matched[:10], str(hash(pattern))[:6]),
            alert_type=AlertType.SUSPICIOUS_KEYWORD,
            severity=severity,
            reason=f"Suspicious keyword detected: {matched}",
            description=f"Log message contains suspicious pattern: '{matched}'",
            source_logs=[log.raw_line],
            indicators={
                "keyword": matched,
                "pattern": pattern,
            },
            matched_pattern=matched,
            confidence=0.95,
            metadata={
                "log_level": log.level.value,
                "logger": log.logger,
            },
        )