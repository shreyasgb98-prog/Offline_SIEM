"""Alert schema for detection results."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class AlertSeverity(Enum):
    """Alert severity levels."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertType(Enum):
    """Types of security alerts."""

    BRUTE_FORCE = "BRUTE_FORCE"
    FAILED_LOGIN = "FAILED_LOGIN"
    SUSPICIOUS_KEYWORD = "SUSPICIOUS_KEYWORD"
    SUSPICIOUS_IP = "SUSPICIOUS_IP"
    ANOMALY = "ANOMALY"
    CUSTOM = "CUSTOM"


@dataclass
class Alert:
    """Structured security alert."""

    # Unique identifier
    id: str

    # Alert type
    alert_type: AlertType

    # Severity level
    severity: AlertSeverity

    # Human-readable reason
    reason: str

    # Detailed description
    description: str = ""

    # Timestamp of detection
    timestamp: datetime = field(default_factory=datetime.now)

    # Source log entries that triggered this alert
    source_logs: list[str] = field(default_factory=list)

    # Associated indicators (IPs, users, etc.)
    indicators: dict[str, Any] = field(default_factory=dict)

    # Raw matched pattern (if applicable)
    matched_pattern: str = ""

    # Confidence score (0.0 - 1.0)
    confidence: float = 1.0

    # Additional metadata
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "alert_type": self.alert_type.value,
            "severity": self.severity.value,
            "reason": self.reason,
            "description": self.description,
            "timestamp": self.timestamp.isoformat(),
            "source_logs": self.source_logs,
            "indicators": self.indicators,
            "matched_pattern": self.matched_pattern,
            "confidence": self.confidence,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Alert":
        """Create from dictionary."""
        return cls(
            id=data["id"],
            alert_type=AlertType(data["alert_type"]),
            severity=AlertSeverity(data["severity"]),
            reason=data["reason"],
            description=data.get("description", ""),
            timestamp=datetime.fromisoformat(data["timestamp"]),
            source_logs=data.get("source_logs", []),
            indicators=data.get("indicators", {}),
            matched_pattern=data.get("matched_pattern", ""),
            confidence=data.get("confidence", 1.0),
            metadata=data.get("metadata", {}),
        )