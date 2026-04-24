"""Incident correlation functionality."""

import logging
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any

from src.storage.database import Database, get_database

logger = logging.getLogger(__name__)


class CorrelationEngine:
    """Correlate alerts to identify related incidents."""

    def __init__(self, db: Database | None = None):
        self.db = db or get_database()

    def correlate_by_ip(self, session_id: str) -> dict:
        """Correlate alerts by source IP.

        Args:
            session_id: Session ID.

        Returns:
            Dict mapping IP to list of related alerts.
        """
        sql = """
            SELECT alert_id, alert_type, severity, reason, timestamp, indicators
            FROM alerts
            WHERE session_id = ?
            ORDER BY timestamp
        """
        rows = self.db.execute(sql, (session_id,))

        # Group by IP from indicators
        ip_groups = defaultdict(list)

        for row in rows:
            indicators = row["indicators"]
            if isinstance(indicators, str):
                import json

                try:
                    indicators = json.loads(indicators)
                except json.JSONDecodeError:
                    indicators = {}

            # Extract IP from various indicator fields
            ip = (
                indicators.get("ip")
                or indicators.get("source")
                or indicators.get("src_ip")
            )

            if ip:
                ip_groups[ip].append(dict(row))

        return dict(ip_groups)

    def correlate_by_user(self, session_id: str) -> dict:
        """Correlate alerts by username.

        Args:
            session_id: Session ID.

        Returns:
            Dict mapping username to list of related alerts.
        """
        sql = """
            SELECT alert_id, alert_type, severity, reason, timestamp, indicators
            FROM alerts
            WHERE session_id = ?
            ORDER BY timestamp
        """
        rows = self.db.execute(sql, (session_id,))

        user_groups = defaultdict(list)

        for row in rows:
            indicators = row["indicators"]
            if isinstance(indicators, str):
                import json

                try:
                    indicators = json.loads(indicators)
                except json.JSONDecodeError:
                    indicators = {}

            username = indicators.get("username") or indicators.get("user")
            if username:
                user_groups[username].append(dict(row))

        return dict(user_groups)

    def correlate_by_time(
        self,
        session_id: str,
        window_minutes: int = 5,
    ) -> list[list[dict]]:
        """Correlate alerts that occur within a time window.

        Args:
            session_id: Session ID.
            window_minutes: Time window in minutes.

        Returns:
            List of alert groups (clusters).
        """
        sql = """
            SELECT alert_id, alert_type, severity, reason, timestamp
            FROM alerts
            WHERE session_id = ?
            ORDER BY timestamp
        """
        rows = self.db.execute(sql, (session_id,))

        if not rows:
            return []

        # Convert to dicts
        alerts = [dict(row) for row in rows]

        # Cluster by time
        clusters = []
        current_cluster = [alerts[0]]

        for i in range(1, len(alerts)):
            prev_time = datetime.fromisoformat(alerts[i - 1]["timestamp"])
            curr_time = datetime.fromisoformat(alerts[i]["timestamp"])

            if (curr_time - prev_time).total_seconds() <= window_minutes * 60:
                current_cluster.append(alerts[i])
            else:
                if len(current_cluster) > 1:
                    clusters.append(current_cluster)
                current_cluster = [alerts[i]]

        # Add last cluster
        if len(current_cluster) > 1:
            clusters.append(current_cluster)

        return clusters

    def find_related_alerts(
        self,
        session_id: str,
        alert_id: str,
    ) -> list[dict]:
        """Find alerts related to a given alert.

        Args:
            session_id: Session ID.
            alert_id: Alert ID to find relations for.

        Returns:
            List of related alerts.
        """
        # Get the reference alert
        sql = "SELECT * FROM alerts WHERE session_id = ? AND alert_id = ?"
        rows = self.db.execute(sql, (session_id, alert_id))

        if not rows:
            return []

        ref_alert = dict(rows[0])
        related = []

        # Find same alert type
        type_rows = self.db.execute(
            "SELECT * FROM alerts WHERE session_id = ? AND alert_type = ? AND alert_id != ?",
            (session_id, ref_alert["alert_type"], alert_id),
        )
        related.extend([dict(r) for r in type_rows[:5]])

        # Find same severity
        severity_rows = self.db.execute(
            "SELECT * FROM alerts WHERE session_id = ? AND severity = ? AND alert_id != ?",
            (session_id, ref_alert["severity"], alert_id),
        )
        related.extend([dict(r) for r in severity_rows[:3]])

        return related

    def get_attack_chain(self, session_id: str) -> list[dict]:
        """Reconstruct potential attack chains.

        Args:
            session_id: Session ID.

        Returns:
            List of attack chains with timeline.
        """
        # Get all alerts ordered by time
        sql = """
            SELECT alert_id, alert_type, severity, reason, timestamp, indicators
            FROM alerts
            WHERE session_id = ?
            ORDER BY timestamp
        """
        rows = self.db.execute(sql, (session_id,))

        alerts = [dict(row) for row in rows]

        # Build chains based on temporal proximity and related indicators
        chains = []
        current_chain = []

        for alert in alerts:
            if not current_chain:
                current_chain.append(alert)
                continue

            last_alert = current_chain[-1]
            time_diff = (
                datetime.fromisoformat(alert["timestamp"])
                - datetime.fromisoformat(last_alert["timestamp"])
            ).total_seconds()

            # Chain if within 1 hour and related type
            related_types = {
                "BRUTE_FORCE": ["FAILED_LOGIN", "SUSPICIOUS_IP"],
                "FAILED_LOGIN": ["BRUTE_FORCE", "SUSPICIOUS_KEYWORD"],
                "SUSPICIOUS_KEYWORD": ["ANOMALY"],
            }

            is_related = (
                time_diff <= 3600
                and alert["alert_type"] in related_types.get(last_alert["alert_type"], [])
            )

            if is_related:
                current_chain.append(alert)
            else:
                if len(current_chain) > 1:
                    severity_rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
                    chains.append(
                        {
                            "alerts": current_chain,
                            "start": current_chain[0]["timestamp"],
                            "end": current_chain[-1]["timestamp"],
                            "severity": max(
                                current_chain,
                                key=lambda a: severity_rank.get(a["severity"], 0)
                            )["severity"],
                        }
                    )
                current_chain = [alert]

        if len(current_chain) > 1:
            severity_rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
            chains.append(
                {
                    "alerts": current_chain,
                    "start": current_chain[0]["timestamp"],
                    "end": current_chain[-1]["timestamp"],
                    "severity": max(
                        current_chain,
                        key=lambda a: severity_rank.get(a["severity"], 0)
                    )["severity"],
                }
            )

        return chains

    def get_incident_correlation(
        self,
        session_id: str,
    ) -> dict:
        """Get correlation data for incidents.

        Args:
            session_id: Session ID.

        Returns:
            Dict with correlation metrics.
        """
        return {
            "by_ip": self.correlate_by_ip(session_id),
            "by_user": self.correlate_by_user(session_id),
            "time_clusters": self.correlate_by_time(session_id),
            "attack_chains": self.get_attack_chain(session_id),
        }