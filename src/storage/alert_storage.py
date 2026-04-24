"""Alert storage operations."""

import json
import logging
from datetime import datetime
from typing import Any

from src.detection.alert import Alert, AlertSeverity, AlertType
from src.storage.database import Database, get_database

logger = logging.getLogger(__name__)


class AlertStorage:
    """Store and retrieve security alerts."""

    def __init__(self, db: Database | None = None):
        self.db = db or get_database()

    def save_alerts(
        self,
        session_id: str,
        alerts: list[Alert],
    ) -> int:
        """Save alerts to database.

        Args:
            session_id: Session ID.
            alerts: List of Alert objects.

        Returns:
            Number of alerts saved.
        """
        now = datetime.now().isoformat()
        count = 0

        with self.db.get_connection() as conn:
            cursor = conn.cursor()

            for alert in alerts:
                cursor.execute(
                    """
                    INSERT INTO alerts (
                        session_id, alert_id, alert_type, severity, reason,
                        description, timestamp, source_logs, indicators,
                        matched_pattern, confidence, metadata, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        session_id,
                        alert.id,
                        alert.alert_type.value,
                        alert.severity.value,
                        alert.reason,
                        alert.description,
                        alert.timestamp.isoformat(),
                        json.dumps(alert.source_logs),
                        json.dumps(alert.indicators),
                        alert.matched_pattern,
                        alert.confidence,
                        json.dumps(alert.metadata),
                        now,
                    ),
                )
                count += 1

        logger.info(f"Saved {count} alerts for session {session_id}")
        return count

    def get_alerts(
        self,
        session_id: str,
        severity: str | None = None,
        alert_type: str | None = None,
        limit: int = 1000,
    ) -> list[Alert]:
        """Retrieve alerts from database.

        Args:
            session_id: Session ID.
            severity: Filter by severity.
            alert_type: Filter by alert type.
            limit: Maximum number of alerts.

        Returns:
            List of Alert objects.
        """
        query = "SELECT * FROM alerts WHERE session_id = ?"
        params = [session_id]

        if severity:
            query += " AND severity = ?"
            params.append(severity.upper())

        if alert_type:
            query += " AND alert_type = ?"
            params.append(alert_type.upper())

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        rows = self.db.execute(query, tuple(params))

        return [self._row_to_alert(row) for row in rows]

    def _row_to_alert(self, row: Any) -> Alert:
        """Convert database row to Alert."""
        return Alert(
            id=row["alert_id"],
            alert_type=AlertType(row["alert_type"]),
            severity=AlertSeverity(row["severity"]),
            reason=row["reason"],
            description=row["description"] or "",
            timestamp=datetime.fromisoformat(row["timestamp"]),
            source_logs=json.loads(row["source_logs"] or "[]"),
            indicators=json.loads(row["indicators"] or "{}"),
            matched_pattern=row["matched_pattern"] or "",
            confidence=row["confidence"],
            metadata=json.loads(row["metadata"] or "{}"),
        )

    def count_alerts(self, session_id: str) -> dict:
        """Get alert counts by severity and type."""
        rows = self.db.execute(
            """
            SELECT severity, alert_type, COUNT(*) as count
            FROM alerts
            WHERE session_id = ?
            GROUP BY severity, alert_type
            """,
            (session_id,),
        )

        result = {"total": 0, "by_severity": {}, "by_type": {}}

        for row in rows:
            result["total"] += row["count"]
            result["by_severity"][row["severity"]] = row["count"]
            result["by_type"][row["alert_type"]] = row["count"]

        return result

    def delete_alerts(self, session_id: str) -> int:
        """Delete all alerts for a session."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM alerts WHERE session_id = ?", (session_id,))
            return cursor.rowcount