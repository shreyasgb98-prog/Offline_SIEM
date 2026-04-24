"""Source file tracking with hash verification."""

import hashlib
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from src.storage.database import Database, get_database

logger = logging.getLogger(__name__)


def compute_file_hash(file_path: Path, algorithm: str = "sha256") -> str:
    """Compute hash of a file.

    Args:
        file_path: Path to file.
        algorithm: Hash algorithm (md5, sha1, sha256).

    Returns:
        Hex digest of file hash.
    """
    hash_obj = hashlib.new(algorithm)

    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            hash_obj.update(chunk)

    return hash_obj.hexdigest()


class FileTracker:
    """Track source files and their integrity."""

    def __init__(self, db: Database | None = None):
        self.db = db or get_database()

    def track_file(
        self,
        session_id: str,
        file_path: str | Path,
        compute_hash: bool = True,
    ) -> int | None:
        """Track a source file.

        Args:
            session_id: Session ID.
            file_path: Path to file.
            compute_hash: Whether to compute file hash.

        Returns:
            File record ID or None on error.
        """
        file_path = Path(file_path)

        if not file_path.exists():
            logger.error(f"File not found: {file_path}")
            return None

        # Compute hash if requested
        file_hash = None
        file_size = None

        if compute_hash:
            try:
                file_hash = compute_file_hash(file_path)
                file_size = file_path.stat().st_size
            except Exception as e:
                logger.error(f"Error computing hash: {e}")

        # Determine format from extension
        format = self._detect_format(file_path)

        now = datetime.now().isoformat()

        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO source_files
                (session_id, file_path, file_hash, file_size, format, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (session_id, str(file_path), file_hash, file_size, format, now),
            )
            return cursor.lastrowid

    def _detect_format(self, file_path: Path) -> str:
        """Detect log format from file extension."""
        ext = file_path.suffix.lower()
        format_map = {
            ".json": "json",
            ".jsonl": "json",
            ".log": "text",
            ".txt": "text",
            ".syslog": "syslog",
            ".csv": "csv",
        }
        return format_map.get(ext, "unknown")

    def get_file(self, file_id: int) -> dict | None:
        """Get file details."""
        rows = self.db.execute(
            "SELECT * FROM source_files WHERE id = ?",
            (file_id,),
        )

        if not rows:
            return None

        return dict(rows[0])

    def verify_file_integrity(self, file_id: int) -> bool:
        """Verify file hash matches stored hash."""
        rows = self.db.execute(
            "SELECT file_path, file_hash FROM source_files WHERE id = ?",
            (file_id,),
        )

        if not rows or not rows[0]["file_hash"]:
            return True  # No hash to verify

        file_path = Path(rows[0]["file_path"])
        stored_hash = rows[0]["file_hash"]

        try:
            current_hash = compute_file_hash(file_path)
            return current_hash == stored_hash
        except Exception as e:
            logger.error(f"Hash verification error: {e}")
            return False

    def list_session_files(self, session_id: str) -> list[dict]:
        """List all files tracked in a session."""
        rows = self.db.execute(
            "SELECT * FROM source_files WHERE session_id = ? ORDER BY created_at",
            (session_id,),
        )

        return [dict(row) for row in rows]

    def delete_file(self, file_id: int) -> bool:
        """Delete file tracking record."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM source_files WHERE id = ?", (file_id,))
            return cursor.rowcount > 0