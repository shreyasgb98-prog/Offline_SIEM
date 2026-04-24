"""Search functionality for logs and alerts."""

import logging
import re
from typing import Any

from src.storage.database import Database, get_database

logger = logging.getLogger(__name__)


class SearchEngine:
    """Full-text and filtered search across logs and alerts."""

    def __init__(self, db: Database | None = None):
        self.db = db or get_database()

    def search_logs(
        self,
        session_id: str,
        query: str | None = None,
        level: str | None = None,
        logger: str | None = None,
        source: str | None = None,
        start_time: str | None = None,
        end_time: str | None = None,
        limit: int = 1000,
    ) -> list[dict]:
        """Search logs with multiple filters.

        Args:
            session_id: Session ID.
            query: Text search query.
            level: Filter by log level.
            logger: Filter by logger name.
            source: Filter by source.
            start_time: Start timestamp (ISO).
            end_time: End timestamp (ISO).
            limit: Max results.

        Returns:
            List of matching log entries.
        """
        where_clauses = ["session_id = ?"]
        params = [session_id]

        if query:
            where_clauses.append("(message LIKE ? OR raw_line LIKE ?)")
            params.extend([f"%{query}%", f"%{query}%"])

        if level:
            where_clauses.append("level = ?")
            params.append(level.upper())

        if logger:
            where_clauses.append("logger LIKE ?")
            params.append(f"%{logger}%")

        if source:
            where_clauses.append("source LIKE ?")
            params.append(f"%{source}%")

        if start_time:
            where_clauses.append("timestamp >= ?")
            params.append(start_time)

        if end_time:
            where_clauses.append("timestamp <= ?")
            params.append(end_time)

        query_sql = f"SELECT * FROM logs WHERE {' AND '.join(where_clauses)} ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        rows = self.db.execute(query_sql, tuple(params))
        return [dict(row) for row in rows]

    def search_alerts(
        self,
        session_id: str,
        query: str | None = None,
        severity: str | None = None,
        alert_type: str | None = None,
        start_time: str | None = None,
        end_time: str | None = None,
        limit: int = 1000,
    ) -> list[dict]:
        """Search alerts with multiple filters.

        Args:
            session_id: Session ID.
            query: Text search query.
            severity: Filter by severity.
            alert_type: Filter by alert type.
            start_time: Start timestamp.
            end_time: End timestamp.
            limit: Max results.

        Returns:
            List of matching alerts.
        """
        where_clauses = ["session_id = ?"]
        params = [session_id]

        if query:
            where_clauses.append("(reason LIKE ? OR description LIKE ? OR matched_pattern LIKE ?)")
            params.extend([f"%{query}%", f"%{query}%", f"%{query}%"])

        if severity:
            where_clauses.append("severity = ?")
            params.append(severity.upper())

        if alert_type:
            where_clauses.append("alert_type = ?")
            params.append(alert_type.upper())

        if start_time:
            where_clauses.append("timestamp >= ?")
            params.append(start_time)

        if end_time:
            where_clauses.append("timestamp <= ?")
            params.append(end_time)

        query_sql = f"SELECT * FROM alerts WHERE {' AND '.join(where_clauses)} ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        rows = self.db.execute(query_sql, tuple(params))
        return [dict(row) for row in rows]

    def search_raw(
        self,
        session_id: str,
        query: str,
        table: str = "logs",
        limit: int = 100,
    ) -> list[dict]:
        """Raw SQL search for advanced queries.

        Args:
            session_id: Session ID.
            query: SQL WHERE clause (without WHERE).
            table: Table to search (logs/alerts).
            limit: Max results.

        Returns:
            List of matching rows.
        """
        valid_tables = ["logs", "alerts"]
        if table not in valid_tables:
            raise ValueError(f"Invalid table: {table}")

        sql = f"SELECT * FROM {table} WHERE session_id = ? AND {query} LIMIT ?"
        rows = self.db.execute(sql, (session_id, limit))
        return [dict(row) for row in rows]

    def get_unique_values(
        self,
        session_id: str,
        field: str,
        table: str = "logs",
    ) -> list[str]:
        """Get unique values for a field.

        Args:
            session_id: Session ID.
            field: Field name.
            table: Table to query.

        Returns:
            List of unique values.
        """
        valid_fields = {
            "logs": ["level", "logger", "source", "format"],
            "alerts": ["severity", "alert_type"],
        }

        if table not in valid_fields or field not in valid_fields[table]:
            raise ValueError(f"Invalid field: {field} for table {table}")

        sql = f"SELECT DISTINCT {field} FROM {table} WHERE session_id = ? AND {field} IS NOT NULL ORDER BY {field}"
        rows = self.db.execute(sql, (session_id,))
        return [row[field] for row in rows if row[field]]