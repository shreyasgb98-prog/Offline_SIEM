"""Parser registry and factory."""

from pathlib import Path
from typing import Iterator, Type

from src.parsers.base import BaseParser
from src.parsers.csv_parser import CSVParser
from src.parsers.json_parser import JSONParser
from src.parsers.syslog_parser import SyslogParser
from src.parsers.text_parser import PlainTextParser
from src.schema import NormalizedLog


class ParserRegistry:
    """Registry for log parsers."""

    def __init__(self):
        self._parsers: list[BaseParser] = [
            JSONParser(),
            SyslogParser(),
            PlainTextParser(),
            CSVParser(),
        ]

    @property
    def parsers(self) -> list[BaseParser]:
        """Get all registered parsers."""
        return self._parsers

    def get_parser(self, name: str) -> BaseParser | None:
        """Get parser by name."""
        for parser in self._parsers:
            if parser.name == name:
                return parser
        return None

    def get_parser_for_file(self, file_path: Path) -> BaseParser | None:
        """Get appropriate parser for a file."""
        for parser in self._parsers:
            if parser.can_parse(file_path):
                return parser
        # Default to text parser
        return PlainTextParser()

    def parse_file(self, file_path: Path) -> Iterator[NormalizedLog]:
        """Parse a file using the appropriate parser."""
        parser = self.get_parser_for_file(file_path)
        if parser is None:
            return

        yield from parser.parse_file(file_path)

    def parse_content(self, content: str, format: str) -> Iterator[NormalizedLog]:
        """Parse content using specified format."""
        parser = self.get_parser(format)
        if parser is None:
            raise ValueError(f"Unknown format: {format}")

        yield from parser.parse(content)


# Global registry instance
registry = ParserRegistry()