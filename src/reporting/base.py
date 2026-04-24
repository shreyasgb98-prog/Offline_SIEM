"""Report generation base classes."""

import hashlib
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ReportMetadata:
    """Report metadata."""

    title: str
    session_id: str
    generated_at: datetime = field(default_factory=datetime.now)
    generator: str = "Offline SIEM Analysis Engine"
    version: str = "1.0.0"


class BaseReport(ABC):
    """Abstract base class for reports."""

    def __init__(self, metadata: ReportMetadata):
        self.metadata = metadata

    @abstractmethod
    def generate(self) -> str:
        """Generate report content.

        Returns:
            Report content as string.
        """
        ...

    @abstractmethod
    def save(self, output_path: Path) -> Path:
        """Save report to file.

        Args:
            output_path: Path to save report.

        Returns:
            Path to saved file.
        """
        ...

    def compute_integrity_hash(self, content: str) -> str:
        """Compute SHA-256 hash of report content.

        Args:
            content: Report content.

        Returns:
            Hex digest of SHA-256 hash.
        """
        return hashlib.sha256(content.encode()).hexdigest()

    def _format_timestamp(self, dt: datetime) -> str:
        """Format timestamp for display."""
        return dt.strftime("%Y-%m-%d %H:%M:%S")