"""Suspicious IP detection with offline threat intelligence updates."""

import hashlib
import json
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterator, Optional, Set, Tuple

from src.detection.alert import Alert, AlertSeverity, AlertType
from src.detection.base import BaseDetector
from src.schema import NormalizedLog

logger = logging.getLogger(__name__)


class ThreatIntelManager:
    """Manages offline threat intelligence updates.

    Supports:
    - Versioned threat intel files
    - Integrity verification via SHA-256
    - Manual import via USB/external files
    - Rollback capabilities
    """

    def __init__(self, intel_dir: Path = None):
        """Initialize threat intel manager.

        Args:
            intel_dir: Directory to store threat intel files
        """
        self.intel_dir = intel_dir or Path("data/threat_intel")
        self.intel_dir.mkdir(parents=True, exist_ok=True)

        # Current threat data
        self.suspicious_ips: Set[str] = set()
        self.current_version: Optional[str] = None
        self.last_updated: Optional[datetime] = None

        # Version history for rollback
        self.version_history: Dict[str, Dict] = {}

    def load_current_intel(self) -> bool:
        """Load the most recent threat intel file.

        Returns:
            True if loaded successfully, False otherwise
        """
        try:
            # Find latest version file
            version_files = list(self.intel_dir.glob("threat_intel_v*.json"))
            if not version_files:
                logger.warning("No threat intel files found")
                return False

            # Sort by version (assuming semantic versioning)
            latest_file = max(version_files, key=lambda x: x.stem)

            return self.load_intel_file(latest_file)

        except Exception as e:
            logger.error(f"Error loading current threat intel: {e}")
            return False

    def load_intel_file(self, file_path: Path) -> bool:
        """Load threat intel from a specific file with integrity check.

        Args:
            file_path: Path to threat intel JSON file

        Returns:
            True if loaded successfully
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            # Validate structure
            if not self._validate_intel_format(data):
                logger.error(f"Invalid threat intel format in {file_path}")
                return False

            # Verify integrity if hash is provided
            if 'expected_hash' in data:
                if not self._verify_file_integrity(file_path, data['expected_hash']):
                    logger.error(f"Integrity check failed for {file_path}")
                    return False

            # Load threat data
            self.suspicious_ips = set(data['threat_ips'])
            self.current_version = data.get('version', 'unknown')
            self.last_updated = datetime.fromisoformat(data['created_at'])

            # Store in version history
            self.version_history[self.current_version] = {
                'file_path': file_path,
                'loaded_at': datetime.now(),
                'ip_count': len(self.suspicious_ips)
            }

            logger.info(f"Loaded threat intel v{self.current_version} with {len(self.suspicious_ips)} IPs")
            return True

        except Exception as e:
            logger.error(f"Error loading threat intel file {file_path}: {e}")
            return False

    def import_external_intel(self, source_file: Path, version: str = None) -> bool:
        """Import threat intel from external source (USB, manual transfer).

        Args:
            source_file: Path to external threat intel file
            version: Version string for the import

        Returns:
            True if imported successfully
        """
        try:
            # Generate version if not provided
            if version is None:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                version = f"imported_{timestamp}"

            # Validate source file
            if not source_file.exists():
                logger.error(f"Source file does not exist: {source_file}")
                return False

            # Read and validate source
            with open(source_file, 'r', encoding='utf-8') as f:
                source_data = json.load(f)

            if not self._validate_intel_format(source_data):
                logger.error("Invalid format in source threat intel file")
                return False

            # Create new intel file
            intel_file = self.intel_dir / f"threat_intel_v{version}.json"

            # Add metadata
            intel_data = {
                "version": version,
                "created_at": datetime.now().isoformat(),
                "source": str(source_file),
                "threat_ips": source_data.get('threat_ips', []),
                "description": source_data.get('description', f"Imported from {source_file.name}"),
                "expected_hash": self._calculate_file_hash(source_file)
            }

            # Write to intel directory
            with open(intel_file, 'w', encoding='utf-8') as f:
                json.dump(intel_data, f, indent=2, ensure_ascii=False)

            logger.info(f"Imported threat intel v{version} to {intel_file}")

            # Load the new intel
            return self.load_intel_file(intel_file)

        except Exception as e:
            logger.error(f"Error importing external threat intel: {e}")
            return False

    def rollback_to_version(self, version: str) -> bool:
        """Rollback to a previous version of threat intel.

        Args:
            version: Version to rollback to

        Returns:
            True if rollback successful
        """
        if version not in self.version_history:
            logger.error(f"Version {version} not found in history")
            return False

        version_info = self.version_history[version]
        return self.load_intel_file(version_info['file_path'])

    def get_version_history(self) -> Dict[str, Dict]:
        """Get history of loaded threat intel versions."""
        return self.version_history.copy()

    def _validate_intel_format(self, data: Dict) -> bool:
        """Validate threat intel file format."""
        required_fields = ['threat_ips']
        if not all(field in data for field in required_fields):
            return False

        if not isinstance(data['threat_ips'], list):
            return False

        # Validate IP addresses
        ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$')
        for ip in data['threat_ips']:
            if not isinstance(ip, str) or not ip_pattern.match(ip):
                logger.warning(f"Invalid IP format: {ip}")
                # Continue validation but log warning

        return True

    def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA-256 hash of file for integrity verification."""
        hash_sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()

    def _verify_file_integrity(self, file_path: Path, expected_hash: str) -> bool:
        """Verify file integrity using SHA-256 hash."""
        actual_hash = self._calculate_file_hash(file_path)
        return actual_hash == expected_hash


class ThreatIntelDetector(BaseDetector):
    """Detect connections from known suspicious IPs with offline updates."""

    def __init__(
        self,
        intel_manager: ThreatIntelManager = None,
    ):
        """Initialize detector with threat intel manager.

        Args:
            intel_manager: Threat intel manager instance
        """
        self.intel_manager = intel_manager or ThreatIntelManager()

        # Load current threat intel
        if not self.intel_manager.load_current_intel():
            logger.warning("No threat intel loaded, using empty list")

    @property
    def name(self) -> str:
        return "ThreatIntelDetector"

    @property
    def description(self) -> str:
        return "Detects connections from known malicious IPs (offline updatable)"

    def detect(self, logs: Iterator[NormalizedLog]) -> Iterator[Alert]:
        """Detect suspicious IPs in logs."""
        for log in logs:
            yield from self._check_log(log)

    def _check_log(self, log: NormalizedLog) -> Iterator[Alert]:
        """Check a single log for suspicious IPs."""
        # Extract IP from various fields
        ips = self._extract_ips(log)

        for ip in ips:
            if self._is_suspicious(ip):
                yield self._create_alert(log, ip)

    def _extract_ips(self, log: NormalizedLog) -> list[str]:
        """Extract IP addresses from log entry."""
        ips = []

        # Check metadata
        if ip := log.metadata.get("ip") or log.metadata.get("source_ip") or log.metadata.get("client_ip"):
            ips.append(ip)

        # Check source
        if log.source:
            ips.append(log.source)

        # Try to extract from message
        ipv4_pattern = r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
        matches = re.findall(ipv4_pattern, log.message)
        ips.extend(matches)

        return ips

    def _is_suspicious(self, ip: str) -> bool:
        """Check if IP is in threat list."""
        # Exact match
        if ip in self.intel_manager.suspicious_ips:
            return True

        # Check CIDR patterns
        for threat in self.intel_manager.suspicious_ips:
            if "/" in threat:
                if self._ip_in_cidr(ip, threat):
                    return True

        return False

    def _ip_in_cidr(self, ip: str, cidr: str) -> bool:
        """Check if IP is in CIDR range."""
        import ipaddress

        try:
            return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr)
        except (ValueError, TypeError):
            return False

    def _create_alert(self, log: NormalizedLog, ip: str) -> Alert:
        """Create alert for suspicious IP."""
        version_info = f"v{self.intel_manager.current_version}" if self.intel_manager.current_version else "unknown"

        return Alert(
            id=self._generate_alert_id("IP", ip),
            alert_type=AlertType.SUSPICIOUS_IP,
            severity=AlertSeverity.HIGH,
            reason=f"Connection from known malicious IP: {ip}",
            description=f"Log contains connection from IP {ip} which is in threat intel {version_info}",
            source_logs=[log.raw_line],
            indicators={
                "ip": ip,
                "threat_intel_version": self.intel_manager.current_version,
                "last_updated": self.intel_manager.last_updated.isoformat() if self.intel_manager.last_updated else None
            },
            matched_pattern=ip,
            confidence=0.95,
            metadata={
                "threat_list_size": len(self.intel_manager.suspicious_ips),
                "intel_version": self.intel_manager.current_version,
            },
        )

    # Convenience methods for external management
    def import_threat_intel(self, file_path: Path, version: str = None) -> bool:
        """Import new threat intel file."""
        return self.intel_manager.import_external_intel(file_path, version)

    def get_intel_stats(self) -> Dict:
        """Get threat intel statistics."""
        return {
            "current_version": self.intel_manager.current_version,
            "threat_ip_count": len(self.intel_manager.suspicious_ips),
            "last_updated": self.intel_manager.last_updated.isoformat() if self.intel_manager.last_updated else None,
            "version_history": list(self.intel_manager.version_history.keys())
        }