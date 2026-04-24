"""Repeated failed login detection."""

import logging
from collections import defaultdict
from datetime import timedelta
from typing import Iterator

from src.detection.alert import Alert, AlertSeverity, AlertType
from src.detection.base import BaseDetector
from src.schema import LogLevel, NormalizedLog

logger = logging.getLogger(__name__)


class FailedLoginDetector(BaseDetector):
    """Detect repeated failed login attempts per user account.

    Tracks failed logins by username to identify compromised accounts.
    """

    def __init__(
        self,
        user_threshold: int = 5,
        window_minutes: int = 30,
    ):
        """Initialize detector.

        Args:
            user_threshold: Number of failures per user to trigger alert.
            window_minutes: Time window to analyze.
        """
        self.user_threshold = user_threshold
        self.window_minutes = window_minutes

    @property
    def name(self) -> str:
        return "FailedLoginDetector"

    @property
    def description(self) -> str:
        return "Detects repeated failed login attempts per user"

    def detect(self, logs: Iterator[NormalizedLog]) -> Iterator[Alert]:
        """Detect repeated failed logins per user."""
        # Track failures by username
        user_failures: dict[str, list[NormalizedLog]] = defaultdict(list)

        for log in logs:
            if self._is_login_failure(log):
                username = self._extract_username(log)
                if username:
                    user_failures[username].append(log)

        # Analyze each user
        for username, log_entries in user_failures.items():
            yield from self._analyze_user_failures(username, log_entries)

    def _is_login_failure(self, log: NormalizedLog) -> bool:
        """Check if log indicates a login failure."""
        msg_lower = log.message.lower()
        login_indicators = [
            "login failed",
            "failed login",
            "authentication failed",
            "invalid credentials",
            "wrong password",
            "bad password",
            "invalid username",
            "account locked",
            "user not found",
        ]
        return any(ind in msg_lower for ind in login_indicators)

    def _extract_username(self, log: NormalizedLog) -> str | None:
        """Extract username from log."""
        # Check metadata
        if username := log.metadata.get("username") or log.metadata.get("user"):
            return username

        # Try to extract from message
        import re

        # Common patterns: "user=admin", "username: admin", "for user admin"
        patterns = [
            r"user[=:\s]+(\S+)",
            r"username[=:\s]+(\S+)",
            r"for\s+(\S+)\s+failed",
            r"account[=:\s]+(\S+)",
        ]

        for pattern in patterns:
            match = re.search(pattern, log.message, re.IGNORECASE)
            if match:
                return match.group(1)

        return None

    def _analyze_user_failures(self, username: str, log_entries: list[NormalizedLog]) -> Iterator[Alert]:
        """Analyze failures for a single user."""
        if not log_entries:
            return

        # Sort by timestamp
        log_entries.sort(key=lambda x: x.timestamp)

        # Check recent failures within window
        now = log_entries[-1].timestamp
        window_start = now - timedelta(minutes=self.window_minutes)

        recent = [l for l in log_entries if window_start <= l.timestamp <= now]

        if len(recent) >= self.user_threshold:
            # Determine severity
            if len(recent) >= self.user_threshold * 3:
                severity = AlertSeverity.HIGH
            elif len(recent) >= self.user_threshold * 2:
                severity = AlertSeverity.MEDIUM
            else:
                severity = AlertSeverity.LOW

            yield Alert(
                id=self._generate_alert_id("FAIL", username, str(len(recent))),
                alert_type=AlertType.FAILED_LOGIN,
                severity=severity,
                reason=f"Repeated login failures for user: {username}",
                description=f"User '{username}' has {len(recent)} failed login attempts in {self.window_minutes} minutes",
                source_logs=[log.raw_line for log in recent[:3]],
                indicators={
                    "username": username,
                    "failure_count": len(recent),
                },
                matched_pattern=f"{len(recent)} failures",
                confidence=0.85,
                metadata={
                    "threshold": self.user_threshold,
                    "window_minutes": self.window_minutes,
                },
            )