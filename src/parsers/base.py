"""Base parser interface."""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Iterator

from src.schema import NormalizedLog


class BaseParser(ABC):
    """Abstract base class for log parsers."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Parser identifier."""
        ...

    @property
    @abstractmethod
    def supported_extensions(self) -> list[str]:
        """File extensions this parser supports."""
        ...

    @abstractmethod
    def parse(self, content: str) -> Iterator[NormalizedLog]:
        """Parse log content into normalized entries.

        Args:
            content: Raw log content to parse.

        Yields:
            Normalized log entries.
        """
        ...

    def parse_line(self, line: str) -> NormalizedLog | None:
        """Parse a single log line. Default implementation wraps parse().

        Args:
            line: Single log line to parse.

        Returns:
            Normalized log entry or None if parsing fails.
        """
        try:
            entries = list(self.parse(line))
            return entries[0] if entries else None
        except Exception:
            return None

    def parse_file(self, file_path: Path) -> Iterator[NormalizedLog]:
        """Parse a log file.

        Args:
            file_path: Path to log file.

        Yields:
            Normalized log entries.
        """
        # Try UTF-8 first, fallback to other encodings
        content = None
        encodings = ["utf-8", "utf-8-sig", "latin-1", "cp1252"]
        for encoding in encodings:
            try:
                content = file_path.read_text(encoding=encoding)
                break
            except UnicodeDecodeError:
                continue
        
        if content is None:
            # Last resort: read as bytes and decode with errors='replace'
            content = file_path.read_bytes().decode("utf-8", errors="replace")
        
        yield from self.parse(content)

    def can_parse(self, file_path: Path) -> bool:
        """Check if this parser can handle the given file."""
        return file_path.suffix.lower() in self.supported_extensions