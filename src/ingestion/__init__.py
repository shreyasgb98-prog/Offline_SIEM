"""Ingestion module for loading log files."""

import logging
from pathlib import Path
from typing import Iterator, Literal

from src.parsers import ParserRegistry
from src.schema import NormalizedLog

logger = logging.getLogger(__name__)


class LogIngestor:
    """Handles ingestion of log files from various sources."""

    def __init__(self, parser_registry: ParserRegistry | None = None):
        self.parser_registry = parser_registry or ParserRegistry()

    def ingest_content(
        self,
        content: str,
        format: str | None = None,
        filename: str | None = None,
    ) -> Iterator[NormalizedLog]:
        """Ingest log content directly.

        Args:
            content: Raw log content.
            format: Optional format override (json, syslog, text, csv).
            filename: Optional filename for format detection.

        Yields:
            Normalized log entries.
        """
        # Use specified format or auto-detect from filename
        if format:
            parser = self.parser_registry.get_parser(format)
            if parser is None:
                logger.error(f"Unknown format: {format}")
                return
        elif filename:
            # Create a dummy path for detection
            from pathlib import Path
            dummy_path = Path(filename)
            parser = self.parser_registry.get_parser_for_file(dummy_path)
        else:
            # Default to text parser
            parser = self.parser_registry.get_parser("text")

        if parser is None:
            logger.error("No suitable parser found")
            return

        # Parse content
        try:
            yield from parser.parse(content)
        except Exception as e:
            logger.error(f"Error parsing content: {e}")

    def ingest_file(
        self,
        file_path: str | Path,
        format: str | None = None,
    ) -> Iterator[NormalizedLog]:
        """Ingest a single log file.

        Args:
            file_path: Path to log file.
            format: Optional format override (json, syslog, text, csv).
                If not specified, auto-detected from extension.

        Yields:
            Normalized log entries.
        """
        file_path = Path(file_path)

        if not file_path.exists():
            logger.error(f"File not found: {file_path}")
            return

        logger.info(f"Ingesting file: {file_path}")

        # Use specified format or auto-detect
        if format:
            parser = self.parser_registry.get_parser(format)
            if parser is None:
                logger.error(f"Unknown format: {format}")
                return
        else:
            parser = self.parser_registry.get_parser_for_file(file_path)
            if parser is None:
                logger.warning(f"No parser found for: {file_path}")
                return

        # Parse file
        try:
            yield from parser.parse_file(file_path)
        except Exception as e:
            logger.error(f"Error parsing {file_path}: {e}")

    def ingest_file_streaming(
        self,
        file_path: str | Path,
        format: str | None = None,
        chunk_size: int = 8192,
    ) -> Iterator[NormalizedLog]:
        """Ingest a log file using streaming/chunked processing for memory efficiency.

        Args:
            file_path: Path to log file.
            format: Optional format override.
            chunk_size: Size of chunks to read (bytes).

        Yields:
            Normalized log entries.

        Time Complexity: O(n) where n is file size, but with bounded memory O(chunk_size)
        Space Complexity: O(chunk_size) instead of O(file_size)
        """
        file_path = Path(file_path)

        if not file_path.exists():
            logger.error(f"File not found: {file_path}")
            return

        logger.info(f"Streaming ingestion of file: {file_path}")

        # Use specified format or auto-detect
        if format:
            parser = self.parser_registry.get_parser(format)
            if parser is None:
                logger.error(f"Unknown format: {format}")
                return
        else:
            parser = self.parser_registry.get_parser_for_file(file_path)
            if parser is None:
                logger.warning(f"No parser found for: {file_path}")
                return

        # Stream file in chunks
        try:
            with open(file_path, 'rb') as f:
                buffer = b""
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break

                    buffer += chunk

                    # Process complete lines
                    lines = buffer.split(b'\n')
                    buffer = lines.pop()  # Keep incomplete line in buffer

                    # Decode and process complete lines
                    for line_bytes in lines:
                        try:
                            line = line_bytes.decode('utf-8').rstrip('\r\n')
                            if line:  # Skip empty lines
                                # Use streaming parse method if available
                                if hasattr(parser, 'parse_line'):
                                    entry = parser.parse_line(line)
                                    if entry:
                                        yield entry
                                else:
                                    # Fallback: parse single line as content
                                    entries = list(parser.parse(line))
                                    yield from entries
                        except UnicodeDecodeError:
                            # Skip lines that can't be decoded
                            continue

                # Process remaining buffer
                if buffer:
                    try:
                        line = buffer.decode('utf-8').rstrip('\r\n')
                        if line:
                            if hasattr(parser, 'parse_line'):
                                entry = parser.parse_line(line)
                                if entry:
                                    yield entry
                            else:
                                entries = list(parser.parse(line))
                                yield from entries
                    except UnicodeDecodeError:
                        pass

        except Exception as e:
            logger.error(f"Error streaming {file_path}: {e}")

    def ingest_incremental(
        self,
        file_path: str | Path,
        last_position: int = 0,
        format: str | None = None,
    ) -> tuple[Iterator[NormalizedLog], int]:
        """Ingest only new content from a file since last_position.

        Args:
            file_path: Path to log file.
            last_position: Byte position to start reading from.
            format: Optional format override.

        Returns:
            Tuple of (log entries iterator, new position).
        """
        file_path = Path(file_path)

        if not file_path.exists():
            logger.error(f"File not found: {file_path}")
            return iter([]), last_position

        # Use specified format or auto-detect
        if format:
            parser = self.parser_registry.get_parser(format)
        else:
            parser = self.parser_registry.get_parser_for_file(file_path)

        if parser is None:
            return iter([]), last_position

        try:
            with open(file_path, 'rb') as f:
                f.seek(last_position)
                buffer = b""
                new_position = last_position

                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break

                    buffer += chunk
                    new_position = f.tell()

                    # Process complete lines
                    lines = buffer.split(b'\n')
                    buffer = lines.pop()

                    for line_bytes in lines:
                        try:
                            line = line_bytes.decode('utf-8').rstrip('\r\n')
                            if line:
                                if hasattr(parser, 'parse_line'):
                                    entry = parser.parse_line(line)
                                    if entry:
                                        yield entry
                                else:
                                    entries = list(parser.parse(line))
                                    for entry in entries:
                                        yield entry
                        except UnicodeDecodeError:
                            continue

                # Process remaining buffer
                if buffer:
                    try:
                        line = buffer.decode('utf-8').rstrip('\r\n')
                        if line:
                            if hasattr(parser, 'parse_line'):
                                entry = parser.parse_line(line)
                                if entry:
                                    yield entry
                            else:
                                entries = list(parser.parse(line))
                                for entry in entries:
                                    yield entry
                    except UnicodeDecodeError:
                        pass

        except Exception as e:
            logger.error(f"Error in incremental ingestion {file_path}: {e}")

        return iter([]), new_position

    def ingest_directory(
        self,
        directory: str | Path,
        pattern: str = "*.log*",
        recursive: bool = False,
        streaming: bool = True,
    ) -> Iterator[NormalizedLog]:
        """Ingest all matching files in a directory.

        Args:
            directory: Directory path.
            pattern: Glob pattern for files to match.
            recursive: Whether to search recursively.
            streaming: Use chunked streaming (default True) to keep memory
                bounded regardless of individual file size.  Set False only
                when parsers do not support line-by-line mode.

        Yields:
            Normalized log entries from all matching files.

        Note:
            Always uses ingest_file_streaming() so that 5 GB+ directories
            do not exceed the configured max_memory_mb limit.
        """
        directory = Path(directory)

        if not directory.is_dir():
            logger.error(f"Directory not found: {directory}")
            return

        # Find matching files
        if recursive:
            files = directory.rglob(pattern)
        else:
            files = directory.glob(pattern)

        # Use streaming ingestion for each file to maintain bounded memory
        ingest_fn = self.ingest_file_streaming if streaming else self.ingest_file
        for file_path in sorted(files):
            if file_path.is_file():
                yield from ingest_fn(file_path)

    def ingest_multiple(
        self,
        file_paths: list[str | Path],
        streaming: bool = True,
    ) -> Iterator[NormalizedLog]:
        """Ingest multiple files.

        Args:
            file_paths: List of file paths.
            streaming: Use chunked streaming (default True).

        Yields:
            Normalized log entries from all files.
        """
        ingest_fn = self.ingest_file_streaming if streaming else self.ingest_file
        for file_path in file_paths:
            yield from ingest_fn(file_path)