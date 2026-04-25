"""JSON log parser."""

import json
import logging
from datetime import datetime
from typing import Iterator

from src.parsers.base import BaseParser
from src.schema import LogLevel, NormalizedLog


class JSONParser(BaseParser):
    """Parser for JSON-formatted logs."""

    @property
    def name(self) -> str:
        return "json"

    @property
    def supported_extensions(self) -> list[str]:
        return [".json", ".jsonl"]

    def parse(self, content: str) -> Iterator[NormalizedLog]:
        """Parse JSON log content.

        Supports both single JSON objects and JSON Lines format.
        """
        # Try JSON Lines first (one JSON object per line)
        lines = content.strip().split("\n")
        for line in lines:
            line = line.strip()
            if not line:
                continue

            try:
                entry = json.loads(line)
                yield self._parse_entry(entry, line)
            except json.JSONDecodeError:
                # Try as single JSON object
                try:
                    entry = json.loads(content)
                    yield self._parse_entry(entry, content)
                    return
                except json.JSONDecodeError:
                    continue

    def _parse_entry(self, entry: dict, raw_line: str) -> NormalizedLog:
        """Parse a single JSON log entry."""
        # Extract timestamp
        timestamp = self._extract_timestamp(entry)

        # Extract level
        level = self._extract_level(entry)

        # Extract message
        message = self._extract_message(entry)

        # Extract logger name
        logger = entry.get("logger") or entry.get("name") or entry.get("logger_name") or ""

        # Extract source/file
        source = entry.get("source") or entry.get("file") or entry.get("filename") or ""

        # Extract function
        function = entry.get("function") or entry.get("funcName") or entry.get("method") or ""

        # Extract line number
        line_number = entry.get("line") or entry.get("lineNumber") or entry.get("lineno")

        # Collect remaining fields as metadata
        known_fields = {
            "timestamp",
            "time",
            "datetime",
            "level",
            "severity",
            "message",
            "msg",
            "logger",
            "name",
            "logger_name",
            "source",
            "file",
            "filename",
            "function",
            "funcName",
            "method",
            "line",
            "lineNumber",
            "lineno",
            "ip",
            "source_ip",
            "client_ip",
        }
        metadata = {k: v for k, v in entry.items() if k not in known_fields}

        # Extract IP address
        ip_address = self._extract_ip(entry, message)
        latitude, longitude = None, None
        if ip_address:
            from src.geoip import get_geoip_location
            latitude, longitude = get_geoip_location(ip_address)

        return NormalizedLog(
            timestamp=timestamp,
            level=level,
            message=message,
            logger=logger,
            source=source,
            function=function,
            line_number=line_number,
            metadata=metadata,
            raw_line=raw_line,
            format="json",
            ip_address=ip_address,
            latitude=latitude,
            longitude=longitude,
        )

    def _extract_timestamp(self, entry: dict) -> datetime:
        """Extract timestamp from entry."""
        for field in ["timestamp", "time", "datetime", "@timestamp", "ts"]:
            if field in entry:
                value = entry[field]
                if isinstance(value, (int, float)):
                    # Unix timestamp
                    if value > 1e11:  # milliseconds
                        return datetime.fromtimestamp(value / 1000)
                    return datetime.fromtimestamp(value)
                if isinstance(value, str):
                    for fmt in ["%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S"]:
                        try:
                            return datetime.strptime(value, fmt)
                        except ValueError:
                            continue
                    try:
                        return datetime.fromisoformat(value.replace("Z", "+00:00"))
                    except ValueError:
                        pass
        return datetime.now()

    def _extract_level(self, entry: dict) -> LogLevel:
        """Extract log level from entry."""
        for field in ["level", "severity", "log_level", "loglevel"]:
            if field in entry:
                value = entry[field]
                if isinstance(value, str):
                    return LogLevel(value.upper())
                if isinstance(value, int):
                    # Common numeric levels: 10=DEBUG, 20=INFO, 30=WARNING, 40=ERROR, 50=CRITICAL
                    level_map = {10: LogLevel.DEBUG, 20: LogLevel.INFO, 30: LogLevel.WARNING, 40: LogLevel.ERROR, 50: LogLevel.CRITICAL}
                    return level_map.get(value, LogLevel.UNKNOWN)
        return LogLevel.UNKNOWN

    def _extract_message(self, entry: dict) -> str:
        """Extract message from entry."""
        for field in ["message", "msg", "text", "log"]:
            if field in entry:
                return str(entry[field])
        return str(entry)

    def _extract_ip(self, entry: dict, message: str) -> str | None:
        """Extract IP address from entry."""
        import re
        ip_pattern = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")

        # Check common IP fields
        for field in ["ip", "source_ip", "client_ip", "remote_ip", "host"]:
            if field in entry and isinstance(entry[field], str):
                match = ip_pattern.search(entry[field])
                if match:
                    ip_address = match.group(0)
                    if ip_address == "0.0.0.0" or ip_address.startswith("127."):
                        return None
                    return ip_address

        # Check message
        match = ip_pattern.search(message)
        if match:
            ip_address = match.group(0)
            if ip_address == "0.0.0.0" or ip_address.startswith("127."):
                return None
            return ip_address

        return None