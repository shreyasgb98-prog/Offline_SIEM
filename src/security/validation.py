"""Input validation and sanitization."""

import logging
import re
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class InputValidator:
    """Validate and sanitize user inputs."""

    # Allowed file extensions for upload
    ALLOWED_EXTENSIONS = {".log", ".txt", ".json", ".jsonl", ".csv", ".syslog"}

    # Max file size (50MB)
    MAX_FILE_SIZE = 50 * 1024 * 1024

    # Dangerous patterns to sanitize
    DANGEROUS_PATTERNS = [
        r"<script[^>]*>.*?</script>",  # Script tags
        r"javascript:",  # JS protocol
        r"on\w+\s*=",  # Event handlers
        r"<!--.*?-->",  # HTML comments
    ]

    @classmethod
    def validate_session_id(cls, session_id: str) -> bool:
        """Validate session ID format."""
        if not session_id or not isinstance(session_id, str):
            return False
        # UUID format
        return bool(re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", session_id))

    @classmethod
    def validate_file_path(cls, file_path: str | Path) -> bool:
        """Validate file path for security."""
        path = Path(file_path).resolve()

        # Check extension
        if path.suffix.lower() not in cls.ALLOWED_EXTENSIONS:
            logger.warning(f"Invalid file extension: {path.suffix}")
            return False

        # Check size
        if path.exists() and path.is_file():
            if path.stat().st_size > cls.MAX_FILE_SIZE:
                logger.warning(f"File too large: {path.stat().st_size}")
                return False

        return True

    @classmethod
    def validate_alert_id(cls, alert_id: str) -> bool:
        """Validate alert ID format."""
        if not alert_id or not isinstance(alert_id, str):
            return False
        # Alphanumeric with hyphens
        return bool(re.match(r"^[A-Z0-9\-]+$", alert_id))

    @classmethod
    def validate_incident_id(cls, incident_id: str) -> bool:
        """Validate incident ID format."""
        if not incident_id or not isinstance(incident_id, str):
            return False
        # INC-XXXXXXXX format
        return bool(re.match(r"^INC-[A-F0-9]{8}$", incident_id))

    @classmethod
    def sanitize_search_query(cls, query: str) -> str:
        """Sanitize search query to prevent injection."""
        if not query:
            return ""

        # Remove leading/trailing whitespace
        query = query.strip()

        # Limit length
        query = query[:500]

        # Escape special SQL characters (for LIKE searches)
        # This is handled at the storage layer with parameterized queries

        return query

    @classmethod
    def sanitize_html(cls, content: str) -> str:
        """Sanitize HTML content."""
        if not content:
            return ""

        # Remove dangerous patterns
        for pattern in cls.DANGEROUS_PATTERNS:
            content = re.sub(pattern, "", content, flags=re.IGNORECASE | re.DOTALL)

        return content

    @classmethod
    def validate_timestamp(cls, timestamp: str) -> bool:
        """Validate ISO timestamp format."""
        if not timestamp:
            return False
        # ISO format pattern
        return bool(re.match(r"^\d{4}-\d{2}-\d{2}(T|\s)\d{2}:\d{2}:\d{2}", timestamp))

    @classmethod
    def validate_severity(cls, severity: str) -> bool:
        """Validate severity level."""
        valid = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        return severity.upper() in valid if severity else False

    @classmethod
    def validate_report_format(cls, format: str) -> bool:
        """Validate report format."""
        valid = {"html", "txt"}
        return format.lower() in valid if format else False