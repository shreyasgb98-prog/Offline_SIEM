"""Log storage operations."""

import json
import logging
from datetime import datetime
from typing import Any, Iterator

from src.schema import NormalizedLog
from src.storage.database import Database, get_database

logger = logging.getLogger(__name__)


class LogStorage:
    """Store and retrieve normalized logs."""

    def __init__(self, db: Database | None = None):
        self.db = db or get_database()

    def save_logs(
        self,
        session_id: str,
        logs: Iterator[NormalizedLog] | list[NormalizedLog],
    ) -> int:
        """Save normalized logs to database.

        Args:
            session_id: Session ID.
            logs: Iterator or list of NormalizedLog entries.

        Returns:
            Number of logs saved.
        """
        now = datetime.now().isoformat()
        count = 0

        # Convert iterator to list if needed
        log_list = list(logs) if hasattr(logs, "__iter__") else logs

        with self.db.get_connection() as conn:
            cursor = conn.cursor()

            for log in log_list:
                cursor.execute(
                    """
                    INSERT INTO logs (
                        session_id, timestamp, level, message, logger, source,
                        function, line_number, metadata, raw_line, format, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        session_id,
                        log.timestamp.isoformat(),
                        log.level.value,
                        log.message,
                        log.logger,
                        log.source,
                        log.function,
                        log.line_number,
                        json.dumps(log.metadata),
                        log.raw_line,
                        log.format,
                        now,
                    ),
                )
                count += 1

        logger.info(f"Saved {count} logs for session {session_id}")
        return count

    def get_logs(
        self,
        session_id: str,
        limit: int = 1000,
        offset: int = 0,
        level: str | None = None,
        start_time: str | None = None,
        end_time: str | None = None,
    ) -> list[NormalizedLog]:
        """Retrieve logs from database.

        Args:
            session_id: Session ID.
            limit: Maximum number of logs to return.
            offset: Number of logs to skip.
            level: Filter by log level.
            start_time: Filter by start timestamp (ISO format).
            end_time: Filter by end timestamp (ISO format).

        Returns:
            List of NormalizedLog entries.
        """
        query = "SELECT * FROM logs WHERE session_id = ?"
        params = [session_id]

        if level:
            query += " AND level = ?"
            params.append(level.upper())

        if start_time:
            query += " AND timestamp >= ?"
            params.append(start_time)

        if end_time:
            query += " AND timestamp <= ?"
            params.append(end_time)

        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        rows = self.db.execute(query, tuple(params))

        return [self._row_to_log(row) for row in rows]

    def _row_to_log(self, row: Any) -> NormalizedLog:
        """Convert database row to NormalizedLog."""
        from src.schema import LogLevel

        return NormalizedLog(
            timestamp=datetime.fromisoformat(row["timestamp"]),
            level=LogLevel(row["level"]),
            message=row["message"] or "",
            logger=row["logger"] or "",
            source=row["source"] or "",
            function=row["function"] or "",
            line_number=row["line_number"],
            metadata=json.loads(row["metadata"] or "{}"),
            raw_line=row["raw_line"] or "",
            format=row["format"] or "",
        )

    def count_logs(self, session_id: str) -> int:
        """Count logs in a session."""
        rows = self.db.execute(
            "SELECT COUNT(*) as count FROM logs WHERE session_id = ?",
            (session_id,),
        )
        return rows[0]["count"] if rows else 0

    def delete_logs(self, session_id: str) -> int:
        """Delete all logs for a session."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM logs WHERE session_id = ?", (session_id,))
            return cursor.rowcount