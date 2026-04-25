"""Database connection and schema management."""

import logging
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator

logger = logging.getLogger(__name__)

# Default database path
DEFAULT_DB_PATH = Path(__file__).parent.parent.parent / "data" / "offline_siem.db"


class Database:
    """SQLite database manager with schema initialization."""

    def __init__(self, db_path: Path | None = None):
        """Initialize database.

        Args:
            db_path: Path to SQLite database file.
        """
        self.db_path = db_path or DEFAULT_DB_PATH
        self._ensure_directory()
        self._initialize_schema()

    def _ensure_directory(self) -> None:
        """Ensure database directory exists."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def get_connection(self) -> Iterator[sqlite3.Connection]:
        """Get database connection with context manager."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _initialize_schema(self) -> None:
        """Create all database tables."""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Sessions table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT UNIQUE NOT NULL,
                    name TEXT,
                    description TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    metadata TEXT
                )
            """)

            # Source files table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS source_files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    file_hash TEXT,
                    file_size INTEGER,
                    format TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
                )
            """)

            # Logs table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    level TEXT,
                    message TEXT,
                    logger TEXT,
                    source TEXT,
                    function TEXT,
                    line_number INTEGER,
                    metadata TEXT,
                    raw_line TEXT NOT NULL,
                    format TEXT,
                    source_ip TEXT DEFAULT '-',
                    ip_address TEXT,
                    latitude REAL,
                    longitude REAL,
                    log_source TEXT DEFAULT 'live',
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
                )
            """)

            # Add columns if they don't exist (for migration)
            for col_stmt in [
                "ALTER TABLE logs ADD COLUMN source_ip TEXT DEFAULT '-'",
                "ALTER TABLE logs ADD COLUMN ip_address TEXT",
                "ALTER TABLE logs ADD COLUMN latitude REAL",
                "ALTER TABLE logs ADD COLUMN longitude REAL",
                "ALTER TABLE logs ADD COLUMN log_source TEXT DEFAULT 'live'",
                "ALTER TABLE alerts ADD COLUMN source_ip TEXT DEFAULT '-'",
                "ALTER TABLE incidents ADD COLUMN source_ip TEXT DEFAULT '-'",
            ]:
                try:
                    cursor.execute(col_stmt)
                except sqlite3.OperationalError:
                    pass  # column already exists

            # Alerts table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    alert_id TEXT NOT NULL,
                    alert_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    description TEXT,
                    timestamp TEXT NOT NULL,
                    source_logs TEXT,
                    indicators TEXT,
                    matched_pattern TEXT,
                    confidence REAL,
                    metadata TEXT,
                    source_ip TEXT DEFAULT '-',
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
                )
            """)

            # Incidents table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    incident_id TEXT UNIQUE NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    severity TEXT NOT NULL,
                    status TEXT DEFAULT 'open',
                    alert_ids TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    resolved_at TEXT,
                    metadata TEXT,
                    source_ip TEXT DEFAULT '-',
                    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
                )
            """)

            # Audit events table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    event_action TEXT NOT NULL,
                    actor TEXT,
                    target TEXT,
                    details TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
                )
            """)

            # Create indexes
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_session ON logs(session_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_source ON logs(log_source)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_session ON alerts(session_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_session ON incidents(session_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_session ON audit_events(session_id)")

            logger.info(f"Database initialized at: {self.db_path}")

    def execute(self, query: str, params: tuple = ()) -> list[sqlite3.Row]:
        """Execute a query and return results."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            return cursor.fetchall()

    def execute_many(self, query: str, params_list: list[tuple]) -> None:
        """Execute a query with multiple parameter sets."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.executemany(query, params_list)


# Global database instance
_db: Database | None = None


def get_database(db_path: Path | None = None) -> Database:
    """Get or create global database instance."""
    global _db
    if _db is None:
        _db = Database(db_path)
    return _db


def reset_database(db_path: Path | None = None) -> Database:
    """Reset and reinitialize database."""
    global _db
    _db = Database(db_path)
    return _db