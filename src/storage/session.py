"""Session management."""

import json
import logging
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from src.storage.database import Database, get_database

logger = logging.getLogger(__name__)


class SessionManager:
    """Manage analysis sessions."""

    def __init__(self, db: Database | None = None):
        self.db = db or get_database()

    def create_session(
        self,
        name: str | None = None,
        description: str | None = None,
    ) -> str:
        """Create a new analysis session.

        Args:
            name: Optional session name.
            description: Optional session description.

        Returns:
            Session ID.
        """
        session_id = str(uuid.uuid4())
        now = datetime.now().isoformat()

        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO sessions (session_id, name, description, created_at, updated_at, metadata)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (session_id, name, description, now, now, json.dumps({})),
            )

        logger.info(f"Created session: {session_id}")
        return session_id

    def get_session(self, session_id: str) -> dict | None:
        """Get session details."""
        rows = self.db.execute(
            "SELECT * FROM sessions WHERE session_id = ?",
            (session_id,),
        )

        if not rows:
            return None

        row = rows[0]
        return {
            "session_id": row["session_id"],
            "name": row["name"],
            "description": row["description"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "metadata": json.loads(row["metadata"] or "{}"),
        }

    def update_session(
        self,
        session_id: str,
        name: str | None = None,
        description: str | None = None,
        metadata: dict | None = None,
    ) -> bool:
        """Update session details."""
        updates = []
        params = []

        if name is not None:
            updates.append("name = ?")
            params.append(name)

        if description is not None:
            updates.append("description = ?")
            params.append(description)

        if metadata is not None:
            updates.append("metadata = ?")
            params.append(json.dumps(metadata))

        if not updates:
            return False

        updates.append("updated_at = ?")
        params.append(datetime.now().isoformat())
        params.append(session_id)

        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                f"UPDATE sessions SET {', '.join(updates)} WHERE session_id = ?",
                params,
            )
            return cursor.rowcount > 0

    def list_sessions(self, limit: int = 100) -> list[dict]:
        """List all sessions."""
        rows = self.db.execute(
            "SELECT * FROM sessions ORDER BY created_at DESC LIMIT ?",
            (limit,),
        )

        return [
            {
                "session_id": row["session_id"],
                "name": row["name"],
                "description": row["description"],
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }
            for row in rows
        ]

    def delete_session(self, session_id: str) -> bool:
        """Delete a session and all related data."""
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            # Delete in order due to foreign keys
            cursor.execute("DELETE FROM audit_events WHERE session_id = ?", (session_id,))
            cursor.execute("DELETE FROM incidents WHERE session_id = ?", (session_id,))
            cursor.execute("DELETE FROM alerts WHERE session_id = ?", (session_id,))
            cursor.execute("DELETE FROM logs WHERE session_id = ?", (session_id,))
            cursor.execute("DELETE FROM source_files WHERE session_id = ?", (session_id,))
            cursor.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
            return cursor.rowcount > 0