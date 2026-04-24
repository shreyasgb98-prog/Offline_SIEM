"""Report generator factory."""

import logging
from pathlib import Path
from typing import Any

from src.analytics import TimelineBuilder
from src.reporting.base import BaseReport, ReportMetadata
from src.reporting.html_report import HTMLReport
from src.reporting.text_report import TextReport
from src.storage import (
    AlertStorage,
    IncidentManager,
    LogStorage,
    SessionManager,
)

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generate various report formats."""

    def __init__(self, db=None):
        self.db = db
        self.session_mgr = SessionManager(db) if db else None
        self.log_storage = LogStorage(db) if db else None
        self.alert_storage = AlertStorage(db) if db else None
        self.incident_mgr = IncidentManager(db) if db else None
        self.timeline = TimelineBuilder(db) if db else None

    def generate_report(
        self,
        session_id: str,
        format: str = "html",
        output_path: Path | None = None,
    ) -> Path:
        """Generate a report for a session.

        Args:
            session_id: Session ID.
            format: Report format (html or txt).
            output_path: Output file path.

        Returns:
            Path to generated report.
        """
        # Gather data
        data = self._gather_report_data(session_id)

        # Create metadata
        session = self.session_mgr.get_session(session_id) if self.session_mgr else {}
        metadata = ReportMetadata(
            title=f"Offline SIEM Analysis Report - {session.get('name', 'Session')}",
            session_id=session_id,
        )

        # Generate report
        if format.lower() == "html":
            report = HTMLReport(metadata, data)
            ext = ".html"
        else:
            report = TextReport(metadata, data)
            ext = ".txt"

        # Determine output path
        if output_path is None:
            from datetime import datetime

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = Path(f"reports/report_{session_id[:8]}_{timestamp}{ext}")

        return report.save(output_path)

    def _gather_report_data(self, session_id: str) -> dict:
        """Gather all data needed for report."""
        data = {
            "session": {},
            "summary": {},
            "alerts": [],
            "incidents": [],
            "timeline": {},
        }

        # Session info
        if self.session_mgr:
            data["session"] = self.session_mgr.get_session(session_id) or {}

        # Dashboard summary
        if self.timeline:
            data["summary"] = self.timeline.get_dashboard_summary(session_id)

        # Alerts
        if self.alert_storage:
            alerts = self.alert_storage.get_alerts(session_id, limit=1000)
            data["alerts"] = [a.to_dict() for a in alerts]

        # Incidents
        if self.incident_mgr:
            incidents = self.incident_mgr.list_incidents(session_id)
            data["incidents"] = incidents

        # Timeline
        if self.timeline:
            data["timeline"] = self.timeline.build_combined_timeline(session_id)

        return data

    def generate_both(
        self,
        session_id: str,
        output_dir: Path | None = None,
    ) -> tuple[Path, Path]:
        """Generate both HTML and TXT reports.

        Args:
            session_id: Session ID.
            output_dir: Output directory.

        Returns:
            Tuple of (html_path, txt_path).
        """
        if output_dir is None:
            output_dir = Path("reports")
        output_dir.mkdir(parents=True, exist_ok=True)

        from datetime import datetime

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = f"report_{session_id[:8]}_{timestamp}"

        html_path = output_dir / f"{base_name}.html"
        txt_path = output_dir / f"{base_name}.txt"

        self.generate_report(session_id, "html", html_path)
        self.generate_report(session_id, "txt", txt_path)

        return html_path, txt_path