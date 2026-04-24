"""Audit event logging."""

import json
import logging
from datetime import datetime
from typing import Any

from src.storage.database import Database, get_database

logger = logging.getLogger(__name__)


class AuditEventType:
    """Audit event types."""

    SESSION = "SESSION"
    FILE = "FILE"
    LOG = "LOG"
    ALERT = "ALERT"
    INCIDENT = "INCIDENT"
    DETECTION = "DETECTION"
    EXPORT = "EXPORT"


class AuditAction:
    """Audit actions."""

    # Session actions
    SESSION_CREATE = "create"
    SESSION_UPDATE = "update"
    SESSION_DELETE = "delete"

    # File actions
    FILE_ADD = "add"
    FILE_VERIFY = "verify"
    FILE_DELETE = "delete"

    # Log actions
    LOG_IMPORT = "import"
    LOG_DELETE = "delete"

    # Alert actions
    ALERT_CREATE = "create"
    ALERT_VIEW = "view"
    ALERT_ACKNOWLEDGE = "acknowledge"

    # Incident actions
    INCIDENT_CREATE = "create"
    INCIDENT_UPDATE = "update"
    INCIDENT_RESOLVE = "resolve"

    # Detection actions
    DETECTION_RUN = "run"

    # Export actions
    EXPORT_CREATE = "create"


class AuditLogger:
    """Log audit events for traceability."""

    def __init__(self, db: Database | None = None):
        self.db = db or get_database()

    def log_event(
        self,
        session_id: str,
        event_type: str,
        event_action: str,
        actor: str | None = None,
        target: str | None = None,
        details: dict | None = None,
    ) -> int:
        """Log an audit event.

        Args:
            session_id: Session ID.
            event_type: Type of event (SESSION, FILE, LOG, etc.).
            event_action: Action performed.
            actor: User or system that performed the action.
            target: Target of the action.
            details: Additional details.

        Returns:
            Event ID.
        """
        now = datetime.now().isoformat()

        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO audit_events (
                    session_id, event_type, event_action, actor, target, details, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    event_type,
                    event_action,
                    actor,
                    target,
                    json.dumps(details or {}),
                    now,
                ),
            )
            return cursor.lastrowid

    def get_events(
        self,
        session_id: str,
        event_type: str | None = None,
        event_action: str | None = None,
        limit: int = 100,
    ) -> list[dict]:
        """Get audit events for a session.

        Args:
            session_id: Session ID.
            event_type: Filter by event type.
            event_action: Filter by action.
            limit: Maximum number of events.

        Returns:
            List of audit events.
        """
        query = "SELECT * FROM audit_events WHERE session_id = ?"
        params = [session_id]

        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)

        if event_action:
            query += " AND event_action = ?"
            params.append(event_action)

        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        rows = self.db.execute(query, tuple(params))
        return [self._row_to_event(row) for row in rows]

    def _row_to_event(self, row: Any) -> dict:
        """Convert database row to event dict."""
        return {
            "id": row["id"],
            "event_type": row["event_type"],
            "event_action": row["event_action"],
            "actor": row["actor"],
            "target": row["target"],
            "details": json.loads(row["details"] or "{}"),
            "created_at": row["created_at"],
        }

    def get_session_timeline(self, session_id: str) -> list[dict]:
        """Get chronological timeline of session events."""
        rows = self.db.execute(
            """
            SELECT * FROM audit_events
            WHERE session_id = ?
            ORDER BY created_at ASC
            """,
            (session_id,),
        )

        return [self._row_to_event(row) for row in rows]

    def delete_session_events(self, session_id: str) -> int:
        """Delete all audit events for a session."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM audit_events WHERE session_id = ?",
                (session_id,),
            )
            return cursor.rowcount