"""Grouping and aggregation functionality."""

import json
import logging
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any

from src.storage.database import Database, get_database

logger = logging.getLogger(__name__)


class GroupingEngine:
    """Group and aggregate log/alert data."""

    def __init__(self, db: Database | None = None):
        self.db = db or get_database()

    def group_by_ip(self, session_id: str) -> dict:
        """Group logs by source IP.

        Args:
            session_id: Session ID.

        Returns:
            Dict mapping IP to count and sample logs.
        """
        sql = """
            SELECT source, COUNT(*) as count, GROUP_CONCAT(raw_line, '|||') as samples
            FROM logs
            WHERE session_id = ? AND source IS NOT NULL AND source != ''
            GROUP BY source
            ORDER BY count DESC
        """
        rows = self.db.execute(sql, (session_id,))

        result = {}
        for row in rows:
            ip = row["source"]
            result[ip] = {
                "count": row["count"],
                "samples": row["samples"].split("|||")[:3] if row["samples"] else [],
            }
        return result

    def group_by_user(self, session_id: str) -> dict:
        """Group logs by username/logger.

        Args:
            session_id: Session ID.

        Returns:
            Dict mapping user to count and details.
        """
        sql = """
            SELECT logger, COUNT(*) as count
            FROM logs
            WHERE session_id = ? AND logger IS NOT NULL AND logger != ''
            GROUP BY logger
            ORDER BY count DESC
        """
        rows = self.db.execute(sql, (session_id,))

        return {
            row["logger"]: {"count": row["count"]}
            for row in rows
        }

    def group_by_severity(self, session_id: str) -> dict:
        """Group alerts by severity.

        Args:
            session_id: Session ID.

        Returns:
            Dict mapping severity to count and alerts.
        """
        sql = """
            SELECT severity, alert_type, COUNT(*) as count
            FROM alerts
            WHERE session_id = ?
            GROUP BY severity, alert_type
            ORDER BY severity, count DESC
        """
        rows = self.db.execute(sql, (session_id,))

        result = defaultdict(lambda: {"count": 0, "types": {}})
        for row in rows:
            severity = row["severity"]
            result[severity]["count"] += row["count"]
            result[severity]["types"][row["alert_type"]] = row["count"]

        return dict(result)

    def group_by_time(
        self,
        session_id: str,
        interval: str = "hour",
        table: str = "logs",
    ) -> dict:
        """Group entries by time interval.

        Args:
            session_id: Session ID.
            interval: Time interval (hour, day, minute).
            table: Table to query.

        Returns:
            Dict mapping time buckets to counts.
        """
        # Map interval to SQL date format
        format_map = {
            "minute": "%Y-%m-%d %H:%M",
            "hour": "%Y-%m-%d %H:00",
            "day": "%Y-%m-%d",
            "month": "%Y-%m",
        }

        sql_format = format_map.get(interval, "%Y-%m-%d %H:00")

        # SQLite strftime
        sql = f"""
            SELECT strftime('{sql_format}', timestamp) as time_bucket, COUNT(*) as count
            FROM {table}
            WHERE session_id = ?
            GROUP BY time_bucket
            ORDER BY time_bucket
        """
        rows = self.db.execute(sql, (session_id,))

        return {
            row["time_bucket"]: row["count"]
            for row in rows
        }

    def group_by_logger(self, session_id: str) -> dict:
        """Group logs by logger name.

        Args:
            session_id: Session ID.

        Returns:
            Dict mapping logger to count and level breakdown.
        """
        sql = """
            SELECT logger, level, COUNT(*) as count
            FROM logs
            WHERE session_id = ? AND logger IS NOT NULL
            GROUP BY logger, level
            ORDER BY logger, count DESC
        """
        rows = self.db.execute(sql, (session_id,))

        result = defaultdict(lambda: {"total": 0, "by_level": {}})
        for row in rows:
            logger = row["logger"]
            result[logger]["total"] += row["count"]
            result[logger]["by_level"][row["level"]] = row["count"]

        return dict(result)

    def get_top_values(
        self,
        session_id: str,
        field: str,
        table: str = "logs",
        limit: int = 10,
    ) -> list[dict]:
        """Get top N values for a field.

        Args:
            session_id: Session ID.
            field: Field to group by.
            table: Table to query.
            limit: Number of top values.

        Returns:
            List of {field, count} dicts.
        """
        valid_fields = {
            "logs": ["source", "logger", "level", "format"],
            "alerts": ["severity", "alert_type", "matched_pattern"],
        }

        if table not in valid_fields or field not in valid_fields[table]:
            return []

        sql = f"""
            SELECT {field}, COUNT(*) as count
            FROM {table}
            WHERE session_id = ? AND {field} IS NOT NULL
            GROUP BY {field}
            ORDER BY count DESC
            LIMIT ?
        """
        rows = self.db.execute(sql, (session_id, limit))

        return [
            {field: row[field], "count": row["count"]}
            for row in rows
        ]

    def get_level_distribution(self, session_id: str) -> dict:
        """Get distribution of log levels.

        Args:
            session_id: Session ID.

        Returns:
            Dict mapping level to count and percentage.
        """
        sql = """
            SELECT level, COUNT(*) as count
            FROM logs
            WHERE session_id = ?
            GROUP BY level
        """
        rows = self.db.execute(sql, (session_id,))

        total = sum(row["count"] for row in rows)
        result = {}

        for row in rows:
            level = row["level"]
            count = row["count"]
            result[level] = {
                "count": count,
                "percentage": round(count / total * 100, 2) if total > 0 else 0,
            }

        return result