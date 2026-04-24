"""Safe file handling utilities."""

import logging
import os
import shutil
from pathlib import Path
from typing import Any, Iterator

logger = logging.getLogger(__name__)


class SafeFileHandler:
    """Safe file operations with security checks."""

    # Base directory for allowed operations
    BASE_DIR = Path(__file__).parent.parent.parent.resolve()

    # Allowed extensions
    ALLOWED_EXTENSIONS = {
        ".log",
        ".txt",
        ".json",
        ".jsonl",
        ".csv",
        ".syslog",
        ".yaml",
        ".yml",
    }

    @classmethod
    def safe_read(cls, file_path: str | Path) -> str:
        """Safely read a file."""
        path = cls._validate_path(file_path)

        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")

        if not path.is_file():
            raise ValueError(f"Not a file: {path}")

        return path.read_text(encoding="utf-8")

    @classmethod
    def safe_write(cls, file_path: str | Path, content: str) -> None:
        """Safely write to a file."""
        path = cls._validate_path(file_path)

        # Create parent directories
        path.parent.mkdir(parents=True, exist_ok=True)

        # Write with atomic operation
        temp_path = path.with_suffix(path.suffix + ".tmp")
        try:
            temp_path.write_text(content, encoding="utf-8")
            temp_path.replace(path)
        except Exception:
            # Clean up temp file on error
            if temp_path.exists():
                temp_path.unlink()
            raise

    @classmethod
    def safe_copy(cls, src: str | Path, dst: str | Path) -> None:
        """Safely copy a file."""
        src_path = cls._validate_path(src)
        dst_path = cls._validate_path(dst)

        if not src_path.exists():
            raise FileNotFoundError(f"Source not found: {src_path}")

        # Create destination directory
        dst_path.parent.mkdir(parents=True, exist_ok=True)

        shutil.copy2(src_path, dst_path)

    @classmethod
    def safe_delete(cls, file_path: str | Path) -> bool:
        """Safely delete a file."""
        path = cls._validate_path(file_path)

        if not path.exists():
            return False

        if not path.is_file():
            raise ValueError(f"Not a file: {path}")

        path.unlink()
        return True

    @classmethod
    def safe_list_dir(cls, dir_path: str | Path, pattern: str = "*") -> list[Path]:
        """Safely list directory contents."""
        path = cls._validate_path(dir_path)

        if not path.is_dir():
            raise ValueError(f"Not a directory: {path}")

        return list(path.glob(pattern))

    @classmethod
    def _validate_path(cls, file_path: str | Path) -> Path:
        """Validate and resolve a file path."""
        path = Path(file_path).resolve()

        # Ensure path is within base directory
        try:
            path.relative_to(cls.BASE_DIR)
        except ValueError:
            # Path is outside base directory
            # Check if it's a new file in allowed location
            if not path.exists():
                # Allow if parent is within base
                if not path.parent.resolve().relative_to(cls.BASE_DIR):
                    raise ValueError(f"Path outside allowed directory: {path}")
            else:
                raise ValueError(f"Path outside allowed directory: {path}")

        # Check extension
        if path.suffix.lower() not in cls.ALLOWED_EXTENSIONS:
            if path.exists() and path.is_file():
                raise ValueError(f"Disallowed file extension: {path.suffix}")

        return path

    @classmethod
    def get_safe_path(cls, relative_path: str) -> Path:
        """Get a safe absolute path."""
        return cls.BASE_DIR / relative_path


# Global file handler instance
_file_handler: SafeFileHandler | None = None


def get_file_handler() -> SafeFileHandler:
    """Get global file handler instance."""
    global _file_handler
    if _file_handler is None:
        _file_handler = SafeFileHandler()
    return _file_handler