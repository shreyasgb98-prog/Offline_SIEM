"""Plain text log parser."""

import logging
import re
from datetime import datetime
from typing import Iterator

from src.parsers.base import BaseParser
from src.schema import LogLevel, NormalizedLog


class PlainTextParser(BaseParser):
    """Parser for plain text logs.

    Supports common patterns and extracts IP addresses.
    """

    # IP address pattern
    IP_PATTERN = re.compile(r"\b\d{1,3}(\.\d{1,3}){3}\b")

    # Pattern: YYYY-MM-DD HH:MM:SS,ms LEVEL [logger] message
    ISO_PATTERN = re.compile(
        r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,6})?)\s+"
        r"(?P<level>DEBUG|INFO|WARN(?:ING)?|ERROR|CRITICAL|FATAL|TRACE)\s+"
        r"(?:\[(?P<logger>[^\]]+)\]\s+)?"
        r"(?P<message>.*)$"
    )

    # Pattern: [timestamp] [level] message
    BRACKETED_PATTERN = re.compile(
        r"^\[(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,6})?)\]\s+"
        r"\[(?P<level>DEBUG|INFO|WARN(?:ING)?|ERROR|CRITICAL|FATAL|TRACE)\]\s+"
        r"(?P<message>.*)$"
    )

    # Pattern: Simple date time level message (same as ISO but kept for clarity)
    SIMPLE_PATTERN = re.compile(
        r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,6})?)\s+"
        r"(?P<level>DEBUG|INFO|WARN(?:ING)?|ERROR|CRITICAL|FATAL|TRACE)\s+"
        r"(?P<message>.*)$"
    )

    @property
    def name(self) -> str:
        return "text"

    @property
    def supported_extensions(self) -> list[str]:
        return [".txt", ".log"]

    def parse(self, content: str) -> Iterator[NormalizedLog]:
        """Parse plain text log content."""
        for line in content.split("\n"):
            line = line.strip()
            if not line:
                continue
            entry = self._parse_line(line)
            if entry:
                yield entry

    def parse_line(self, raw_line: str) -> NormalizedLog | None:
        """Parse a single text log line (public API used by streaming ingestor)."""
        line = raw_line.strip()
        if not line:
            return None
        return self._parse_line(line)

    def _parse_line(self, line: str) -> NormalizedLog | None:
        """Core line parser — tries structured patterns then falls back to generic.

        Args:
            line: A single stripped, non-empty log line.

        Returns:
            NormalizedLog with timestamp, level, source, logger, and message fields.
        """
        # Try ISO pattern  (e.g. "2024-01-15 12:34:56 ERROR [app] msg")
        match = self.ISO_PATTERN.match(line)
        if match:
            return self._create_entry(match.groupdict(), line)

        # Try bracketed pattern  (e.g. "[2024-01-15 12:34:56] [ERROR] msg")
        match = self.BRACKETED_PATTERN.match(line)
        if match:
            return self._create_entry(match.groupdict(), line)

        # Try simple pattern  (e.g. "2024-01-15T12:34:56 INFO msg")
        match = self.SIMPLE_PATTERN.match(line)
        if match:
            return self._create_entry(match.groupdict(), line)

        # No structured match — create a generic entry so no line is silently dropped
        return self._create_generic_entry(line)

    # ── Entry builders ────────────────────────────────────────────────────────

    def _create_entry(self, groups: dict, raw_line: str) -> NormalizedLog:
        """Create a NormalizedLog from a regex match's named groups."""
        timestamp = self._parse_timestamp(groups.get("timestamp", ""))
        level     = self._parse_level(groups.get("level", "UNKNOWN"))
        message   = groups.get("message", raw_line)
        logger    = groups.get("logger", "")

        ip_match  = self.IP_PATTERN.search(raw_line)
        metadata  = {"ip": ip_match.group(0)} if ip_match else {}

        return NormalizedLog(
            timestamp=timestamp,
            level=level,
            message=message,
            logger=logger,
            source="",
            raw_line=raw_line,
            format="text",
            metadata=metadata,
        )

    def _create_generic_entry(self, raw_line: str) -> NormalizedLog:
        """Create a generic NormalizedLog for unstructured / unrecognised lines."""
        ip_match = self.IP_PATTERN.search(raw_line)
        metadata = {"ip": ip_match.group(0)} if ip_match else {}

        return NormalizedLog(
            timestamp=datetime.now(),
            level=self._infer_level(raw_line),
            message=raw_line,
            logger="",
            source="",
            raw_line=raw_line,
            format="text",
            metadata=metadata,
        )

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _parse_timestamp(self, ts: str) -> datetime:
        """Parse a timestamp string; returns datetime.now() on failure."""
        ts = ts.replace(",", ".")
        for fmt in [
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
        ]:
            try:
                return datetime.strptime(ts, fmt)
            except ValueError:
                continue
        return datetime.now()

    def _infer_level(self, raw_line: str) -> LogLevel:
        """Infer log level from keywords in an unstructured line."""
        ll = raw_line.lower()
        if any(w in ll for w in ["critical", "fatal"]):
            return LogLevel.CRITICAL
        if any(w in ll for w in ["error", "fail", "failed", "failure", "exception"]):
            return LogLevel.ERROR
        if any(w in ll for w in ["warn", "warning"]):
            return LogLevel.WARNING
        if any(w in ll for w in ["debug"]):
            return LogLevel.DEBUG
        if any(w in ll for w in ["info", "information"]):
            return LogLevel.INFO
        return LogLevel.UNKNOWN

    def _parse_level(self, level_str: str) -> LogLevel:
        """Map a level string to a LogLevel enum value."""
        level_str = level_str.upper()
        if "WARNING" in level_str or "WARN" in level_str:
            return LogLevel.WARNING
        if "CRITICAL" in level_str or "FATAL" in level_str:
            return LogLevel.CRITICAL
        try:
            return LogLevel(level_str)
        except ValueError:
            return LogLevel.UNKNOWN