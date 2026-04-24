"""Robust log parser that returns simple dict structures."""

import json
import logging
import re
from datetime import datetime
from typing import List

logger = logging.getLogger(__name__)


class RobustLogParser:
    """Robust parser for various log formats.

    Returns list of dicts with standardized fields:
    - timestamp: ISO string or empty
    - ip: extracted IP address or empty
    - event: main event/message
    - raw: original raw line
    """

    # IP address regex
    IP_PATTERN = re.compile(r"\b\d{1,3}(\.\d{1,3}){3}\b")

    # Timestamp patterns
    TIMESTAMP_PATTERNS = [
        # ISO format
        re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?"),
        # Simple date time
        re.compile(r"\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}"),
        # Month day time
        re.compile(r"\w{3} \d{1,2} \d{2}:\d{2}:\d{2}"),
    ]

    def parse_content(self, content: str) -> List[dict]:
        """Parse log content and return list of dicts.

        Args:
            content: Raw log content

        Returns:
            List of log dicts
        """
        if not content.strip():
            return []

        # Try JSON first
        if content.strip().startswith("{") or content.strip().startswith("["):
            try:
                return self._parse_json_content(content)
            except (json.JSONDecodeError, ValueError):
                pass  # Fall back to text parsing

        # Fall back to text parsing
        return self._parse_text_content(content)

    def _parse_json_content(self, content: str) -> List[dict]:
        """Parse JSON content."""
        try:
            data = json.loads(content)
            if isinstance(data, list):
                return [self._json_entry_to_dict(entry) for entry in data if entry]
            elif isinstance(data, dict):
                return [self._json_entry_to_dict(data)]
            else:
                # Single value, treat as raw
                return [{"timestamp": "", "ip": "", "event": str(data), "raw": content}]
        except json.JSONDecodeError:
            # Try line-by-line JSON
            lines = content.split("\n")
            entries = []
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    entries.append(self._json_entry_to_dict(data))
                except json.JSONDecodeError:
                    # Not JSON, parse as text
                    entries.extend(self._parse_text_line(line))
            return entries

    def _json_entry_to_dict(self, data: dict) -> dict:
        """Convert JSON entry to standardized dict."""
        # Extract timestamp
        timestamp = ""
        for key in ["timestamp", "time", "@timestamp", "date", "datetime"]:
            if key in data and data[key]:
                ts_str = str(data[key])
                # Try to parse as ISO
                try:
                    dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                    timestamp = dt.isoformat()
                    break
                except (ValueError, TypeError):
                    # Keep as string
                    timestamp = ts_str
                    break

        # Extract IP
        ip = ""
        for key in ["ip", "source_ip", "client_ip", "remote_ip"]:
            if key in data and data[key]:
                ip_match = self.IP_PATTERN.search(str(data[key]))
                if ip_match:
                    ip = ip_match.group(0)
                    break
        # If not found in specific fields, search entire entry
        if not ip:
            entry_str = json.dumps(data)
            ip_match = self.IP_PATTERN.search(entry_str)
            if ip_match:
                ip = ip_match.group(0)

        # Extract event/message
        event = ""
        for key in ["message", "event", "msg", "log", "text"]:
            if key in data and data[key]:
                event = str(data[key])
                break
        # If no specific field, use the whole thing except timestamp
        if not event:
            temp_data = data.copy()
            for key in ["timestamp", "time", "@timestamp", "date", "datetime", "ip", "source_ip"]:
                temp_data.pop(key, None)
            if temp_data:
                event = str(list(temp_data.values())[0]) if len(temp_data) == 1 else json.dumps(temp_data)

        raw = json.dumps(data)

        return {
            "timestamp": timestamp,
            "ip": ip,
            "event": event,
            "raw": raw
        }

    def _parse_text_content(self, content: str) -> List[dict]:
        """Parse plain text content."""
        lines = content.split("\n")
        entries = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            entries.extend(self._parse_text_line(line))
        return entries

    def _parse_text_line(self, line: str) -> List[dict]:
        """Parse a single text line."""
        # Extract timestamp
        timestamp = ""
        for pattern in self.TIMESTAMP_PATTERNS:
            match = pattern.search(line)
            if match:
                ts_str = match.group(0)
                # Try to standardize
                try:
                    # Handle various formats
                    if "T" in ts_str or "-" in ts_str:
                        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00").replace("/", "-"))
                    else:
                        # Assume current year for month day format
                        dt = datetime.strptime(f"{datetime.now().year} {ts_str}", "%Y %b %d %H:%M:%S")
                    timestamp = dt.isoformat()
                except (ValueError, TypeError):
                    timestamp = ts_str
                break

        # Extract IP
        ip_match = self.IP_PATTERN.search(line)
        ip = ip_match.group(0) if ip_match else ""

        # Event is the whole line
        event = line

        return [{
            "timestamp": timestamp,
            "ip": ip,
            "event": event,
            "raw": line
        }]


def parse_logs(content: str) -> List[dict]:
    """Parse log content and return standardized log dicts.

    This is the main entry point for parsing logs.
    """
    parser = RobustLogParser()
    return parser.parse_content(content)