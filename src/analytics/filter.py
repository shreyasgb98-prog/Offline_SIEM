"""Filtering functionality."""

import logging
from datetime import datetime, timedelta
from typing import Any

from src.storage.database import Database, get_database

logger = logging.getLogger(__name__)


class FilterBuilder:
    """Build complex filters for logs and alerts."""

    def __init__(self, db: Database | None = None):
        self.db = db or get_database()

    def filter_by_time_range(
        self,
        session_id: str,
        start: datetime | str,
        end: datetime | str,
        table: str = "logs",
    ) -> list[dict]:
        """Filter entries by time range.

        Args:
            session_id: Session ID.
            start: Start time.
            end: End time.
            table: Table to query.

        Returns:
            Matching entries.
        """
        if isinstance(start, datetime):
            start = start.isoformat()
        if isinstance(end, datetime):
            end = end.isoformat()

        sql = f"SELECT * FROM {table} WHERE session_id = ? AND timestamp >= ? AND timestamp <= ? ORDER BY timestamp"
        rows = self.db.execute(sql, (session_id, start, end))
        return [dict(row) for row in rows]

    def filter_last_n_minutes(
        self,
        session_id: str,
        minutes: int,
        table: str = "logs",
    ) -> list[dict]:
        """Filter entries from last N minutes.

        Args:
            session_id: Session ID.
            minutes: Number of minutes to look back.
            table: Table to query.

        Returns:
            Recent entries.
        """
        end = datetime.now()
        start = end - timedelta(minutes=minutes)
        return self.filter_by_time_range(session_id, start, end, table)

    def filter_by_level(
        self,
        session_id: str,
        levels: list[str],
        table: str = "logs",
    ) -> list[dict]:
        """Filter by log levels.

        Args:
            session_id: Session ID.
            levels: List of levels (ERROR, WARNING, etc.).
            table: Table to query.

        Returns:
            Matching entries.
        """
        placeholders = ",".join(["?"] * len(levels))
        sql = f"SELECT * FROM {table} WHERE session_id = ? AND level IN ({placeholders}) ORDER BY timestamp"
        rows = self.db.execute(sql, (session_id,) + tuple(levels))
        return [dict(row) for row in rows]

    def filter_by_severity(
        self,
        session_id: str,
        severities: list[str],
    ) -> list[dict]:
        """Filter alerts by severity.

        Args:
            session_id: Session ID.
            severities: List of severities (HIGH, CRITICAL, etc.).

        Returns:
            Matching alerts.
        """
        return self.filter_by_level(session_id, severities, "alerts")

    def filter_errors_only(
        self,
        session_id: str,
        table: str = "logs",
    ) -> list[dict]:
        """Filter only error-level entries.

        Args:
            session_id: Session ID.
            table: Table to query.

        Returns:
            Error entries.
        """
        return self.filter_by_level(session_id, ["ERROR", "CRITICAL"], table)

    def filter_by_metadata(
        self,
        session_id: str,
        key: str,
        value: str,
        table: str = "logs",
    ) -> list[dict]:
        """Filter by metadata field.

        Args:
            session_id: Session ID.
            key: Metadata key.
            value: Value to match.
            table: Table to query.

        Returns:
            Matching entries.
        """
        # SQLite doesn't support JSON queries well, so we search in the metadata JSON string
        sql = f"SELECT * FROM {table} WHERE session_id = ? AND metadata LIKE ?"
        rows = self.db.execute(sql, (session_id, f'%"{key}":%{value}%'))
        return [dict(row) for row in rows]

    def get_time_range(
        self,
        session_id: str,
        table: str = "logs",
    ) -> dict:
        """Get min/max timestamps for a session.

        Args:
            session_id: Session ID.
            table: Table to query.

        Returns:
            Dict with min and max timestamps.
        """
        sql = f"SELECT MIN(timestamp) as min_time, MAX(timestamp) as max_time FROM {table} WHERE session_id = ?"
        rows = self.db.execute(sql, (session_id,))

        if rows and rows[0]:
            return {
                "min": rows[0]["min_time"],
                "max": rows[0]["max_time"],
            }
        return {"min": None, "max": None}