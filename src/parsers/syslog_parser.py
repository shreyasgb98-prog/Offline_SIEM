"""Syslog-style log parser."""

import logging
import re
from datetime import datetime
from typing import Iterator

from src.parsers.base import BaseParser
from src.schema import LogLevel, NormalizedLog


class SyslogParser(BaseParser):
    """Parser for syslog-formatted logs.

    Common syslog format:
    <priority>timestamp hostname process[pid]: message
    Or:
    timestamp hostname process[pid]: message
    """

    # Syslog pattern with named groups
    SYSLOG_PATTERN = re.compile(
        r"^(?:<(?P<priority>\d+)>)?"
        r"(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+"
        r"(?P<hostname>\S+)\s+"
        r"(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s*"
        r"(?P<message>.*)$"
    )

    # Alternative: ISO timestamp syslog
    ISO_SYSLOG_PATTERN = re.compile(
        r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
        r"(?P<hostname>\S+)\s+"
        r"(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s*"
        r"(?P<message>.*)$"
    )

    @property
    def name(self) -> str:
        return "syslog"

    @property
    def supported_extensions(self) -> list[str]:
        return [".log", ".syslog"]

    def parse(self, content: str) -> Iterator[NormalizedLog]:
        """Parse syslog-formatted content."""
        for line in content.split("\n"):
            line = line.strip()
            if not line:
                continue

            entry = self._parse_line(line)
            if entry:
                yield entry

    def _parse_line(self, raw_line: str) -> NormalizedLog | None:
        """Parse a single syslog line."""
        # Try ISO format first
        match = self.ISO_SYSLOG_PATTERN.match(raw_line)
        if match:
            return self._create_entry(match.groupdict(), raw_line)

        # Try standard syslog format
        match = self.SYSLOG_PATTERN.match(raw_line)
        if match:
            return self._create_entry(match.groupdict(), raw_line)

        # No match - return as unknown
        ip_match = re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", raw_line)
        ip_address = ip_match.group(0) if ip_match else None
        if ip_address and (ip_address == "0.0.0.0" or ip_address.startswith("127.")):
            ip_address = None
        latitude, longitude = None, None
        if ip_address:
            from src.geoip import get_geoip_location
            latitude, longitude = get_geoip_location(ip_address)

        return NormalizedLog(
            timestamp=datetime.now(),
            level=LogLevel.UNKNOWN,
            message=raw_line,
            raw_line=raw_line,
            format="syslog",
            ip_address=ip_address,
            latitude=latitude,
            longitude=longitude,
        )

    def _create_entry(self, groups: dict, raw_line: str) -> NormalizedLog:
        """Create normalized entry from parsed groups."""
        # Parse timestamp
        if "timestamp" in groups and groups["timestamp"]:
            timestamp = self._parse_timestamp(groups)
        else:
            timestamp = self._parse_legacy_timestamp(groups)

        # Extract message
        message = groups.get("message", "")

        # Determine level from message content or priority
        level = self._extract_level(groups, message)

        # Build metadata
        metadata = {}
        if pid := groups.get("pid"):
            metadata["pid"] = int(pid)
        if hostname := groups.get("hostname"):
            metadata["hostname"] = hostname
        if priority := groups.get("priority"):
            metadata["priority"] = int(priority)

        # Extract IP address from message
        ip_match = re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", message)
        ip_address = ip_match.group(0) if ip_match else None
        if ip_address and (ip_address == "0.0.0.0" or ip_address.startswith("127.")):
            ip_address = None
        latitude, longitude = None, None
        if ip_address:
            from src.geoip import get_geoip_location
            latitude, longitude = get_geoip_location(ip_address)

        return NormalizedLog(
            timestamp=timestamp,
            level=level,
            message=message,
            logger=groups.get("process", ""),
            source=groups.get("hostname", ""),
            metadata=metadata,
            raw_line=raw_line,
            format="syslog",
            ip_address=ip_address,
            latitude=latitude,
            longitude=longitude,
        )

    def _parse_timestamp(self, groups: dict) -> datetime:
        """Parse ISO timestamp."""
        ts = groups.get("timestamp", "")
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            return datetime.now()

    def _parse_legacy_timestamp(self, groups: dict) -> datetime:
        """Parse legacy syslog timestamp (Month Day Time)."""
        try:
            month_str = groups.get("month", "")
            day = int(groups.get("day", 1))
            time_str = groups.get("time", "00:00:00")

            # Use current year for legacy timestamps
            now = datetime.now()
            month_map = {
                "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
                "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
            }
            month = month_map.get(month_str, now.month)

            hour, minute, second = map(int, time_str.split(":"))
            return datetime(now.year, month, day, hour, minute, second)
        except (ValueError, TypeError):
            return datetime.now()

    def _extract_level(self, groups: dict, message: str) -> LogLevel:
        """Extract log level from message or priority."""
        # Check priority if available
        if priority := groups.get("priority"):
            # Syslog priority = facility * 8 + severity
            severity = int(priority) % 8
            level_map = {0: LogLevel.DEBUG, 1: LogLevel.INFO, 2: LogLevel.INFO, 3: LogLevel.WARNING, 4: LogLevel.ERROR, 5: LogLevel.CRITICAL}
            return level_map.get(severity, LogLevel.UNKNOWN)

        # Infer from message content
        message_lower = message.lower()
        if any(kw in message_lower for kw in ["crit", "critical", "emerg"]):
            return LogLevel.CRITICAL
        if any(kw in message_lower for kw in ["err", "error", "fail"]):
            return LogLevel.ERROR
        if any(kw in message_lower for kw in ["warn", "warning"]):
            return LogLevel.WARNING
        if any(kw in message_lower for kw in ["info", "notice"]):
            return LogLevel.INFO
        if any(kw in message_lower for kw in ["debug", "trace"]):
            return LogLevel.DEBUG

        return LogLevel.UNKNOWN