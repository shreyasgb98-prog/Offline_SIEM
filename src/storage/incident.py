"""Incident management."""

import json
import logging
import uuid
from datetime import datetime
from typing import Any

from src.detection.alert import AlertSeverity
from src.storage.database import Database, get_database

logger = logging.getLogger(__name__)


class IncidentStatus:
    """Incident status constants."""

    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    CLOSED = "closed"


class IncidentManager:
    """Manage security incidents."""

    def __init__(self, db: Database | None = None):
        self.db = db or get_database()

    def create_incident(
        self,
        session_id: str,
        title: str,
        description: str = "",
        severity: str = "MEDIUM",
        alert_ids: list[str] | None = None,
    ) -> str:
        """Create a new incident.

        Args:
            session_id: Session ID.
            title: Incident title.
            description: Incident description.
            severity: Initial severity.
            alert_ids: List of alert IDs to associate.

        Returns:
            Incident ID.
        """
        incident_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
        now = datetime.now().isoformat()

        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO incidents (
                    session_id, incident_id, title, description, severity,
                    status, alert_ids, created_at, updated_at, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    incident_id,
                    title,
                    description,
                    severity.upper(),
                    IncidentStatus.OPEN,
                    json.dumps(alert_ids or []),
                    now,
                    now,
                    json.dumps({}),
                ),
            )

        logger.info(f"Created incident: {incident_id}")
        return incident_id

    def get_incident(self, incident_id: str) -> dict | None:
        """Get incident details."""
        rows = self.db.execute(
            "SELECT * FROM incidents WHERE incident_id = ?",
            (incident_id,),
        )

        if not rows:
            return None

        return self._row_to_incident(rows[0])

    def update_incident(
        self,
        incident_id: str,
        title: str | None = None,
        description: str | None = None,
        severity: str | None = None,
        status: str | None = None,
    ) -> bool:
        """Update incident details."""
        updates = []
        params = []

        if title is not None:
            updates.append("title = ?")
            params.append(title)

        if description is not None:
            updates.append("description = ?")
            params.append(description)

        if severity is not None:
            updates.append("severity = ?")
            params.append(severity.upper())

        if status is not None:
            updates.append("status = ?")
            params.append(status)
            if status in (IncidentStatus.RESOLVED, IncidentStatus.CLOSED, IncidentStatus.FALSE_POSITIVE):
                updates.append("resolved_at = ?")
                params.append(datetime.now().isoformat())

        if not updates:
            return False

        updates.append("updated_at = ?")
        params.append(datetime.now().isoformat())
        params.append(incident_id)

        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                f"UPDATE incidents SET {', '.join(updates)} WHERE incident_id = ?",
                params,
            )
            return cursor.rowcount > 0

    def add_alert_to_incident(
        self,
        incident_id: str,
        alert_id: str,
    ) -> bool:
        """Add an alert to an incident."""
        rows = self.db.execute(
            "SELECT alert_ids FROM incidents WHERE incident_id = ?",
            (incident_id,),
        )

        if not rows:
            return False

        alert_ids = json.loads(rows[0]["alert_ids"] or "[]")
        if alert_id not in alert_ids:
            alert_ids.append(alert_id)

        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE incidents SET alert_ids = ?, updated_at = ? WHERE incident_id = ?",
                (json.dumps(alert_ids), datetime.now().isoformat(), incident_id),
            )
            return cursor.rowcount > 0

    def list_incidents(
        self,
        session_id: str,
        status: str | None = None,
        severity: str | None = None,
    ) -> list[dict]:
        """List incidents for a session."""
        query = "SELECT * FROM incidents WHERE session_id = ?"
        params = [session_id]

        if status:
            query += " AND status = ?"
            params.append(status)

        if severity:
            query += " AND severity = ?"
            params.append(severity.upper())

        query += " ORDER BY created_at DESC"

        rows = self.db.execute(query, tuple(params))
        return [self._row_to_incident(row) for row in rows]

    def _row_to_incident(self, row: Any) -> dict:
        """Convert database row to incident dict."""
        return {
            "incident_id": row["incident_id"],
            "title": row["title"],
            "description": row["description"],
            "severity": row["severity"],
            "status": row["status"],
            "alert_ids": json.loads(row["alert_ids"] or "[]"),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "resolved_at": row["resolved_at"],
            "metadata": json.loads(row["metadata"] or "{}"),
        }

    def delete_incident(self, incident_id: str) -> bool:
        """Delete an incident."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM incidents WHERE incident_id = ?", (incident_id,))
            return cursor.rowcount > 0