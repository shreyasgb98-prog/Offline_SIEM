"""Base detector interface."""

from abc import ABC, abstractmethod
from typing import Iterator

from src.detection.alert import Alert
from src.schema import NormalizedLog


class BaseDetector(ABC):
    """Abstract base class for detection engines."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Detector name."""
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        """Detector description."""
        ...

    @abstractmethod
    def detect(self, logs: Iterator[NormalizedLog]) -> Iterator[Alert]:
        """Analyze logs and yield alerts.

        Args:
            logs: Iterator of normalized log entries.

        Yields:
            Alert instances.
        """
        ...

    def _generate_alert_id(self, prefix: str, *parts: str) -> str:
        """Generate a unique alert ID."""
        import hashlib

        content = "-".join(parts)
        hash_suffix = hashlib.md5(content.encode()).hexdigest()[:8]
        return f"{prefix}-{hash_suffix}"