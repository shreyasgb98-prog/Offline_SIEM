"""CSV log parser."""

import csv
import logging
from datetime import datetime
from io import StringIO
from typing import Iterator

from src.parsers.base import BaseParser
from src.schema import LogLevel, NormalizedLog


class CSVParser(BaseParser):
    """Parser for CSV-formatted logs."""

    # Common column mappings for log data
    TIMESTAMP_COLUMNS = ["timestamp", "time", "datetime", "date", "ts", "@timestamp"]
    LEVEL_COLUMNS = ["level", "severity", "log_level", "loglevel", "priority"]
    MESSAGE_COLUMNS = ["message", "msg", "text", "log", "description", "content"]
    LOGGER_COLUMNS = ["logger", "logger_name", "name", "source", "component"]
    SOURCE_COLUMNS = ["source", "file", "filename", "path"]
    FUNCTION_COLUMNS = ["function", "func", "funcName", "method"]
    LINE_COLUMNS = ["line", "line_number", "lineno", "lineNumber"]

    @property
    def name(self) -> str:
        return "csv"

    @property
    def supported_extensions(self) -> list[str]:
        return [".csv"]

    def parse(self, content: str) -> Iterator[NormalizedLog]:
        """Parse CSV log content."""
        reader = csv.DictReader(StringIO(content))

        for row in reader:
            if not row or not any(row.values()):
                continue

            yield self._parse_row(row, content)

    def _parse_row(self, row: dict, raw_line: str) -> NormalizedLog:
        """Parse a single CSV row."""
        # Find column mappings
        columns = {k.lower(): v for k, v in row.items()}

        # Extract timestamp
        timestamp = self._extract_timestamp(columns)

        # Extract level
        level = self._extract_level(columns)

        # Extract message
        message = self._extract_message(columns)

        # Extract logger
        logger = self._extract_column(columns, self.LOGGER_COLUMNS)

        # Extract source
        source = self._extract_column(columns, self.SOURCE_COLUMNS)

        # Extract function
        function = self._extract_column(columns, self.FUNCTION_COLUMNS)

        # Extract line number
        line_number = self._extract_line_number(columns)

        # Remaining columns as metadata
        known_columns = set(
            self.TIMESTAMP_COLUMNS
            + self.LEVEL_COLUMNS
            + self.MESSAGE_COLUMNS
            + self.LOGGER_COLUMNS
            + self.SOURCE_COLUMNS
            + self.FUNCTION_COLUMNS
            + self.LINE_COLUMNS
        )
        metadata = {k: v for k, v in row.items() if k.lower() not in known_columns and v}

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
            format="csv",
        )

    def _extract_timestamp(self, columns: dict) -> datetime:
        """Extract timestamp from columns."""
        for col in self.TIMESTAMP_COLUMNS:
            if col in columns and columns[col]:
                value = columns[col]
                return self._parse_timestamp_value(value)
        return datetime.now()

    def _parse_timestamp_value(self, value: str) -> datetime:
        """Parse a timestamp value."""
        # Try unix timestamp
        try:
            ts = float(value)
            if ts > 1e11:  # milliseconds
                return datetime.fromtimestamp(ts / 1000)
            return datetime.fromtimestamp(ts)
        except (ValueError, TypeError):
            pass

        # Try ISO formats
        for fmt in [
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y/%m/%d %H:%M:%S",
        ]:
            try:
                return datetime.strptime(value, fmt)
            except ValueError:
                continue

        # Try fromisoformat
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            pass

        return datetime.now()

    def _extract_level(self, columns: dict) -> LogLevel:
        """Extract log level from columns."""
        for col in self.LEVEL_COLUMNS:
            if col in columns and columns[col]:
                value = columns[col]
                if isinstance(value, str):
                    return LogLevel(value.upper())
                if isinstance(value, (int, float)):
                    level_map = {10: LogLevel.DEBUG, 20: LogLevel.INFO, 30: LogLevel.WARNING, 40: LogLevel.ERROR, 50: LogLevel.CRITICAL}
                    return level_map.get(int(value), LogLevel.UNKNOWN)
        return LogLevel.UNKNOWN

    def _extract_message(self, columns: dict) -> str:
        """Extract message from columns."""
        for col in self.MESSAGE_COLUMNS:
            if col in columns and columns[col]:
                return str(columns[col])
        # Fallback: join all non-empty values
        return " | ".join(v for v in columns.values() if v)

    def _extract_column(self, columns: dict, candidates: list[str]) -> str:
        """Extract a column value from candidates."""
        for col in candidates:
            if col in columns and columns[col]:
                return str(columns[col])
        return ""

    def _extract_line_number(self, columns: dict) -> int | None:
        """Extract line number from columns."""
        for col in self.LINE_COLUMNS:
            if col in columns and columns[col]:
                try:
                    return int(columns[col])
                except (ValueError, TypeError):
                    pass
        return None