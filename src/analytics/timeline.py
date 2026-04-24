"""Timeline data builder for UI visualization."""

import json
import logging
from collections import defaultdict
from datetime import datetime
from typing import Any

from src.storage.database import Database, get_database

logger = logging.getLogger(__name__)


class TimelineBuilder:
    """Build timeline data for UI visualization."""

    def __init__(self, db: Database | None = None):
        self.db = db or get_database()

    def build_log_timeline(
        self,
        session_id: str,
        bucket_minutes: int = 60,
        limit: int = 1000,
    ) -> dict:
        """Build timeline data for logs.

        Args:
            session_id: Session ID.
            bucket_minutes: Time bucket size in minutes.
            limit: Max number of buckets.

        Returns:
            Timeline data with buckets and counts.
        """
        sql = """
            SELECT timestamp, level, logger
            FROM logs
            WHERE session_id = ?
            ORDER BY timestamp
            LIMIT ?
        """
        rows = self.db.execute(sql, (session_id, limit))

        if not rows:
            return {"buckets": [], "levels": {}, "loggers": {}}

        # Group by time bucket
        buckets = defaultdict(lambda: {"count": 0, "by_level": defaultdict(int)})

        for row in rows:
            dt = datetime.fromisoformat(row["timestamp"])
            # Round to bucket
            bucket_key = dt.replace(
                minute=(dt.minute // bucket_minutes) * bucket_minutes, second=0, microsecond=0
            )
            key = bucket_key.isoformat()

            buckets[key]["count"] += 1
            buckets[key]["by_level"][row["level"]] += 1

        # Convert to list
        bucket_list = [
            {
                "time": k,
                "count": v["count"],
                "by_level": dict(v["by_level"]),
            }
            for k, v in sorted(buckets.items())
        ]

        # Aggregate level distribution
        levels = defaultdict(int)
        loggers = defaultdict(int)

        for row in rows:
            levels[row["level"]] += 1
            if row["logger"]:
                loggers[row["logger"]] += 1

        return {
            "buckets": bucket_list,
            "levels": dict(levels),
            "loggers": dict(loggers),
            "bucket_minutes": bucket_minutes,
        }

    def build_alert_timeline(
        self,
        session_id: str,
        bucket_minutes: int = 60,
    ) -> dict:
        """Build timeline data for alerts.

        Args:
            session_id: Session ID.
            bucket_minutes: Time bucket size.

        Returns:
            Timeline data with alert buckets.
        """
        sql = """
            SELECT timestamp, alert_type, severity
            FROM alerts
            WHERE session_id = ?
            ORDER BY timestamp
        """
        rows = self.db.execute(sql, (session_id,))

        if not rows:
            return {"buckets": [], "by_type": {}, "by_severity": {}}

        # Group by time bucket
        buckets = defaultdict(lambda: {"count": 0, "by_type": defaultdict(int), "by_severity": defaultdict(int)})

        for row in rows:
            dt = datetime.fromisoformat(row["timestamp"])
            bucket_key = dt.replace(
                minute=(dt.minute // bucket_minutes) * bucket_minutes, second=0, microsecond=0
            )
            key = bucket_key.isoformat()

            buckets[key]["count"] += 1
            buckets[key]["by_type"][row["alert_type"]] += 1
            buckets[key]["by_severity"][row["severity"]] += 1

        bucket_list = [
            {
                "time": k,
                "count": v["count"],
                "by_type": dict(v["by_type"]),
                "by_severity": dict(v["by_severity"]),
            }
            for k, v in sorted(buckets.items())
        ]

        # Aggregate
        by_type = defaultdict(int)
        by_severity = defaultdict(int)

        for row in rows:
            by_type[row["alert_type"]] += 1
            by_severity[row["severity"]] += 1

        return {
            "buckets": bucket_list,
            "by_type": dict(by_type),
            "by_severity": dict(by_severity),
            "bucket_minutes": bucket_minutes,
        }

    def build_combined_timeline(
        self,
        session_id: str,
        bucket_minutes: int = 60,
    ) -> dict:
        """Build combined timeline for logs and alerts.

        Args:
            session_id: Session ID.
            bucket_minutes: Time bucket size.

        Returns:
            Combined timeline data.
        """
        log_timeline = self.build_log_timeline(session_id, bucket_minutes)
        alert_timeline = self.build_alert_timeline(session_id, bucket_minutes)

        # Merge buckets
        all_times = set()
        for b in log_timeline["buckets"]:
            all_times.add(b["time"])
        for b in alert_timeline["buckets"]:
            all_times.add(b["time"])

        merged_buckets = []
        for time in sorted(all_times):
            log_bucket = next((b for b in log_timeline["buckets"] if b["time"] == time), None)
            alert_bucket = next((b for b in alert_timeline["buckets"] if b["time"] == time), None)

            merged_buckets.append({
                "time": time,
                "logs": log_bucket["count"] if log_bucket else 0,
                "log_levels": log_bucket["by_level"] if log_bucket else {},
                "alerts": alert_bucket["count"] if alert_bucket else 0,
                "alert_types": alert_bucket["by_type"] if alert_bucket else {},
                "alert_severities": alert_bucket["by_severity"] if alert_bucket else {},
            })

        return {
            "buckets": merged_buckets,
            "summary": {
                "total_logs": sum(b["logs"] for b in merged_buckets),
                "total_alerts": sum(b["alerts"] for b in merged_buckets),
            },
            "bucket_minutes": bucket_minutes,
        }

    def build_incident_timeline(
        self,
        session_id: str,
    ) -> dict:
        """Build timeline for incidents.

        Args:
            session_id: Session ID.

        Returns:
            Incident timeline data.
        """
        sql = """
            SELECT incident_id, title, severity, status, created_at, updated_at, resolved_at
            FROM incidents
            WHERE session_id = ?
            ORDER BY created_at
        """
        rows = self.db.execute(sql, (session_id,))

        incidents = []
        for row in rows:
            incidents.append({
                "id": row["incident_id"],
                "title": row["title"],
                "severity": row["severity"],
                "status": row["status"],
                "created": row["created_at"],
                "updated": row["updated_at"],
                "resolved": row["resolved_at"],
            })

        # Group by status
        by_status = defaultdict(list)
        for inc in incidents:
            by_status[inc["status"]].append(inc)

        return {
            "incidents": incidents,
            "by_status": dict(by_status),
            "total": len(incidents),
        }

    def get_dashboard_summary(
        self,
        session_id: str,
    ) -> dict:
        """Get summary data for dashboard.

        Args:
            session_id: Session ID.

        Returns:
            Dashboard summary data.
        """
        # Log counts
        log_sql = "SELECT COUNT(*) as count, level FROM logs WHERE session_id = ? GROUP BY level"
        log_rows = self.db.execute(log_sql, (session_id,))

        log_summary = {"total": 0, "by_level": {}}
        for row in log_rows:
            log_summary["by_level"][row["level"]] = row["count"]
            log_summary["total"] += row["count"]

        # Alert counts
        alert_sql = "SELECT COUNT(*) as count, severity FROM alerts WHERE session_id = ? GROUP BY severity"
        alert_rows = self.db.execute(alert_sql, (session_id,))

        alert_summary = {"total": 0, "by_severity": {}}
        for row in alert_rows:
            alert_summary["by_severity"][row["severity"]] = row["count"]
            alert_summary["total"] += row["count"]

        # Incident counts
        incident_sql = "SELECT COUNT(*) as count, status FROM incidents WHERE session_id = ? GROUP BY status"
        incident_rows = self.db.execute(incident_sql, (session_id,))

        incident_summary = {"total": 0, "by_status": {}}
        for row in incident_rows:
            incident_summary["by_status"][row["status"]] = row["count"]
            incident_summary["total"] += row["count"]

        # Time range
        time_sql = "SELECT MIN(timestamp) as min_time, MAX(timestamp) as max_time FROM logs WHERE session_id = ?"
        time_rows = self.db.execute(time_sql, (session_id,))
        time_range = {}
        if time_rows and time_rows[0]["min_time"]:
            time_range = {
                "start": time_rows[0]["min_time"],
                "end": time_rows[0]["max_time"],
            }

        return {
            "logs": log_summary,
            "alerts": alert_summary,
            "incidents": incident_summary,
            "time_range": time_range,
        }