"""Cryptographic integrity verification using SHA-256."""

import hashlib
import hmac
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class IntegrityVerifier:
    """Cryptographic file and data integrity verification.

    Uses SHA-256 hashing for integrity verification:
    - SHA-256 provides 256-bit hash output
    - Collision resistant: 2^128 operations needed for collision
    - Preimage resistant: 2^256 operations needed to find preimage
    - Second preimage resistant: 2^256 operations needed

    Why SHA-256:
    - Standardized and widely implemented
    - No known practical attacks (as of 2024)
    - Suitable for integrity verification
    - Faster than SHA-3 for most use cases
    """

    # Hash algorithm configuration
    HASH_ALGORITHM = hashlib.sha256
    HASH_NAME = "SHA-256"
    HASH_LENGTH = 64  # Hex characters

    def __init__(self, secret_key: Optional[str] = None):
        """Initialize integrity verifier.

        Args:
            secret_key: Optional secret key for HMAC operations
        """
        self.secret_key = secret_key

    def generate_file_hash(self, file_path: Path) -> str:
        """Generate SHA-256 hash of file contents.

        Args:
            file_path: Path to file to hash

        Returns:
            Hex string of SHA-256 hash

        Process:
        1. Read file in 64KB chunks to handle large files
        2. Update hash incrementally
        3. Return hex digest

        Time Complexity: O(file_size)
        Space Complexity: O(1) - constant memory usage
        """
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        hash_obj = self.HASH_ALGORITHM()

        try:
            with open(file_path, 'rb') as f:
                # Read in chunks to handle large files efficiently
                chunk_size = 64 * 1024  # 64KB chunks
                while chunk := f.read(chunk_size):
                    hash_obj.update(chunk)

            hash_hex = hash_obj.hexdigest()
            logger.debug(f"Generated {self.HASH_NAME} hash for {file_path}: {hash_hex[:16]}...")
            return hash_hex

        except Exception as e:
            logger.error(f"Error generating hash for {file_path}: {e}")
            raise

    def verify_file_hash(self, file_path: Path, expected_hash: str) -> bool:
        """Verify file integrity against expected hash.

        Args:
            file_path: Path to file to verify
            expected_hash: Expected SHA-256 hash as hex string

        Returns:
            True if hash matches, False otherwise

        Verification Process:
        1. Generate current hash of file
        2. Compare with expected hash using constant-time comparison
        3. Log verification result
        """
        try:
            actual_hash = self.generate_file_hash(file_path)

            # Use constant-time comparison to prevent timing attacks
            is_valid = self._constant_time_compare(actual_hash, expected_hash)

            if is_valid:
                logger.info(f"✓ File integrity verified: {file_path}")
            else:
                logger.warning(f"✗ File integrity check FAILED: {file_path}")
                logger.warning(f"  Expected: {expected_hash}")
                logger.warning(f"  Actual:   {actual_hash}")

            return is_valid

        except Exception as e:
            logger.error(f"Error verifying hash for {file_path}: {e}")
            return False

    def generate_data_hash(self, data: str) -> str:
        """Generate SHA-256 hash of string data.

        Args:
            data: String data to hash

        Returns:
            Hex string of SHA-256 hash
        """
        hash_obj = self.HASH_ALGORITHM()
        hash_obj.update(data.encode('utf-8'))
        return hash_obj.hexdigest()

    def verify_data_hash(self, data: str, expected_hash: str) -> bool:
        """Verify string data integrity.

        Args:
            data: String data to verify
            expected_hash: Expected hash

        Returns:
            True if hash matches
        """
        actual_hash = self.generate_data_hash(data)
        return self._constant_time_compare(actual_hash, expected_hash)

    def generate_hmac(self, data: str) -> Optional[str]:
        """Generate HMAC-SHA256 if secret key is available.

        Args:
            data: Data to sign

        Returns:
            HMAC hex string or None if no secret key
        """
        if not self.secret_key:
            return None

        hmac_obj = hmac.new(
            self.secret_key.encode('utf-8'),
            data.encode('utf-8'),
            digestmod=self.HASH_ALGORITHM,
        )
        return hmac_obj.hexdigest()

    def verify_hmac(self, data: str, hmac_signature: str) -> bool:
        """Verify HMAC signature.

        Args:
            data: Original data
            hmac_signature: HMAC signature to verify

        Returns:
            True if signature is valid
        """
        if not self.secret_key:
            return False

        expected_hmac = self.generate_hmac(data)
        return expected_hmac is not None and hmac.compare_digest(expected_hmac, hmac_signature)

    def _constant_time_compare(self, a: str, b: str) -> bool:
        """Constant-time string comparison to prevent timing attacks.

        Args:
            a, b: Strings to compare

        Returns:
            True if strings are equal
        """
        if len(a) != len(b):
            return False
        return hmac.compare_digest(a, b)

    def get_hash_info(self) -> dict:
        """Get information about the hash algorithm being used."""
        return {
            "algorithm": self.HASH_NAME,
            "output_length_bits": self.HASH_ALGORITHM().digest_size * 8,
            "output_length_hex": self.HASH_LENGTH,
            "block_size": self.HASH_ALGORITHM().block_size,
            "description": "SHA-256 provides cryptographic integrity verification"
        }


# Convenience functions for easy usage
def generate_hash(file_path: Path) -> str:
    """Generate SHA-256 hash of file.

    Args:
        file_path: Path to file

    Returns:
        SHA-256 hash as hex string
    """
    verifier = IntegrityVerifier()
    return verifier.generate_file_hash(file_path)


def verify_hash(file_path: Path, expected_hash: str) -> bool:
    """Verify file hash.

    Args:
        file_path: Path to file
        expected_hash: Expected hash

    Returns:
        True if hash matches
    """
    verifier = IntegrityVerifier()
    return verifier.verify_file_hash(file_path, expected_hash)


# Legacy compatibility
class ReportSigner(IntegrityVerifier):
    """Legacy compatibility class for report signing."""

    def sign_content(self, content: str) -> str:
        """Create signature for content (HMAC if key available, else hash)."""
        if self.secret_key:
            hmac_sig = self.generate_hmac(content)
            return hmac_sig or self.generate_data_hash(content)
        else:
            return self.generate_data_hash(content)

    def verify_signature(self, content: str, signature: str) -> bool:
        """Verify content signature."""
        if self.secret_key:
            return self.verify_hmac(content, signature)
        else:
            return self.verify_data_hash(content, signature)

    def compute_content_hash(self, content: str) -> str:
        """Compute hash of content."""
        return self.generate_data_hash(content)

    def compute_file_hash(self, file_path: Path) -> str:
        """Compute SHA-256 hash of a file."""
        hash_obj = hashlib.sha256()

        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                hash_obj.update(chunk)

        return hash_obj.hexdigest()

    def create_report_signature(
        self,
        report_content: str,
        metadata: dict,
    ) -> dict:
        """Create a signed report with metadata."""
        content_hash = self.compute_content_hash(report_content)
        signature = self.sign_content(report_content)

        return {
            "content_hash": content_hash,
            "signature": signature,
            "signed_at": datetime.now().isoformat(),
            "metadata": metadata,
        }

    def verify_report(
        self,
        report_content: str,
        signature_data: dict,
    ) -> bool:
        """Verify a signed report."""
        # Verify content hash
        content_hash = self.compute_content_hash(report_content)
        if content_hash != signature_data.get("content_hash"):
            logger.warning("Content hash mismatch")
            return False

        # Verify signature
        signature = signature_data.get("signature", "")
        if not self.verify_signature(report_content, signature):
            logger.warning("Signature verification failed")
            return False

        return True


# Global signer instance
_signer: ReportSigner | None = None


def get_signer() -> ReportSigner:
    """Get global signer instance.

    Loads SIEM_SIGNING_KEY from the environment (or config.yaml) so that
    signatures are HMAC-SHA256 rather than a plain hash.  Without a key,
    sign_content() falls back to a bare SHA-256 hash which provides
    integrity checking but NOT authentication.
    """
    global _signer
    if _signer is None:
        import os
        secret_key: str | None = os.environ.get("SIEM_SIGNING_KEY")
        if secret_key is None:
            try:
                from src.config import load_config
                secret_key = load_config().get("security", {}).get("signing_key")
            except Exception:
                pass
        if secret_key is None:
            logger.warning(
                "No SIEM_SIGNING_KEY set — report signatures will be plain SHA-256 hashes, "
                "not HMAC. Set SIEM_SIGNING_KEY env var or security.signing_key in config.yaml "
                "to enable authenticated signatures."
            )
        _signer = ReportSigner(secret_key=secret_key)
    return _signer