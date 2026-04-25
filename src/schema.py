"""Common log schema for normalization."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class LogLevel(Enum):
    """Standard log levels."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


@dataclass
class NormalizedLog:
    """Normalized log entry schema.

    All parsers convert their input to this common format.
    The raw_line is preserved for traceability.
    """

    # Timestamp - normalized to ISO format
    timestamp: datetime

    # Log severity level
    level: LogLevel = LogLevel.UNKNOWN

    # Main log message
    message: str = ""

    # Source/logger name
    logger: str = ""

    # Optional: source file or component
    source: str = ""

    # Optional: function or method name
    function: str = ""

    # Optional: line number
    line_number: int | None = None

    # Optional: additional metadata
    metadata: dict[str, Any] = field(default_factory=dict)

    # Optional: extracted IP address
    ip_address: str | None = None

    # Optional: latitude from GeoIP
    latitude: float | None = None

    # Optional: longitude from GeoIP
    longitude: float | None = None

    # Raw log line for traceability
    raw_line: str = ""

    # Format of the log (e.g., 'text', 'json')
    format: str = ""

    # Original raw line for traceability
    raw_line: str = ""

    # Source format (json, syslog, text, csv)
    format: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "level": self.level.value,
            "message": self.message,
            "logger": self.logger,
            "source": self.source,
            "function": self.function,
            "line_number": self.line_number,
            "metadata": self.metadata,
            "raw_line": self.raw_line,
            "format": self.format,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "NormalizedLog":
        """Create from dictionary."""
        return cls(
            timestamp=datetime.fromisoformat(data["timestamp"]),
            level=LogLevel(data["level"]),
            message=data.get("message", ""),
            logger=data.get("logger", ""),
            source=data.get("source", ""),
            function=data.get("function", ""),
            line_number=data.get("line_number"),
            metadata=data.get("metadata", {}),
            raw_line=data.get("raw_line", ""),
            format=data.get("format", ""),
        )