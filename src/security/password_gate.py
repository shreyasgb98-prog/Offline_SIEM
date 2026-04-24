"""Password gating for sensitive operations."""

import hashlib
import logging
import os
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class PasswordGate:
    """Password protection for sensitive operations."""

    def __init__(self, password_file: Path | None = None):
        self.password_file = password_file or self._get_default_password_file()
        self._hash = self._load_or_create_password()

    def _get_default_password_file(self) -> Path:
        """Get default password file location."""
        data_dir = Path(__file__).parent.parent.parent / "data"
        data_dir.mkdir(parents=True, exist_ok=True)
        return data_dir / ".password"

    def _load_or_create_password(self) -> str | None:
        """Load existing password or return None if not set."""
        if self.password_file.exists():
            return self.password_file.read_text().strip()
        return None

    def is_password_set(self) -> bool:
        """Check if a password has been set."""
        return self._hash is not None and len(self._hash) > 0

    def set_password(self, password: str) -> bool:
        """Set a new password."""
        if not password or len(password) < 4:
            logger.error("Password too short")
            return False

        # Hash the password
        self._hash = hashlib.sha256(password.encode()).hexdigest()

        # Save to file
        self.password_file.write_text(self._hash)
        logger.info("Password set successfully")
        return True

    def verify(self, password: str) -> bool:
        """Verify password."""
        if not self.is_password_set():
            return True  # No password set, allow access

        if not password:
            return False

        password_hash = hashlib.sha256(password.encode()).hexdigest()
        return password_hash == self._hash

    def check(self, password: str) -> bool:
        """Alias for verify."""
        return self.verify(password)

    def clear_password(self) -> bool:
        """Clear the password (disable gating)."""
        if self.password_file.exists():
            self.password_file.unlink()
        self._hash = None
        logger.info("Password cleared")
        return True


# Global password gate instance
_password_gate: Optional[PasswordGate] = None


def get_password_gate() -> PasswordGate:
    """Get global password gate instance."""
    global _password_gate
    if _password_gate is None:
        _password_gate = PasswordGate()
    return _password_gate