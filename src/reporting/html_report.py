"""HTML report generator."""

import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from src.analytics import TimelineBuilder
from src.detection import AlertSeverity
from src.reporting.base import BaseReport, ReportMetadata

logger = logging.getLogger(__name__)


class HTMLReport(BaseReport):
    """Generate HTML format reports."""

    def __init__(self, metadata: ReportMetadata, data: dict):
        super().__init__(metadata)
        self.data = data

    def generate(self) -> str:
        """Generate HTML report."""
        session = self.data.get("session", {})
        summary = self.data.get("summary", {})
        alerts = self.data.get("alerts", [])
        incidents = self.data.get("incidents", [])
        timeline = self.data.get("timeline", {})

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{self.metadata.title}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #333; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%); color: white; padding: 30px; border-radius: 8px; margin-bottom: 20px; }}
        .header h1 {{ font-size: 2em; margin-bottom: 10px; }}
        .header .meta {{ opacity: 0.8; font-size: 0.9em; }}
        .card {{ background: white; border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .card h2 {{ color: #1e3c72; border-bottom: 2px solid #1e3c72; padding-bottom: 10px; margin-bottom: 15px; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }}
        .stat-box {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; text-align: center; }}
        .stat-box.warning {{ background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); }}
        .stat-box.danger {{ background: linear-gradient(135deg, #fa709a 0%, #fee140 100%); }}
        .stat-box.success {{ background: linear-gradient(135deg, #43e97b 0%, #38f9d7 100%); }}
        .stat-box .number {{ font-size: 2.5em; font-weight: bold; }}
        .stat-box .label {{ opacity: 0.9; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #eee; }}
        th {{ background: #f8f9fa; font-weight: 600; }}
        .severity-LOW {{ color: #28a745; }}
        .severity-MEDIUM {{ color: #ffc107; }}
        .severity-HIGH {{ color: #fd7e14; }}
        .severity-CRITICAL {{ color: #dc3545; font-weight: bold; }}
        .badge {{ display: inline-block; padding: 4px 12px; border-radius: 12px; font-size: 0.85em; }}
        .badge-LOW {{ background: #d4edda; color: #155724; }}
        .badge-MEDIUM {{ background: #fff3cd; color: #856404; }}
        .badge-HIGH {{ background: #f8d7da; color: #721c24; }}
        .badge-CRITICAL {{ background: #f8d7da; color: #721c24; font-weight: bold; }}
        .timeline {{ position: relative; padding-left: 30px; }}
        .timeline::before {{ content: ''; position: absolute; left: 10px; top: 0; bottom: 0; width: 2px; background: #ddd; }}
        .timeline-item {{ position: relative; padding: 15px 0; }}
        .timeline-item::before {{ content: ''; position: absolute; left: -24px; top: 20px; width: 10px; height: 10px; border-radius: 50%; background: #1e3c72; }}
        .footer {{ text-align: center; padding: 20px; color: #666; font-size: 0.9em; border-top: 1px solid #eee; margin-top: 20px; }}
        .integrity {{ background: #f8f9fa; padding: 15px; border-radius: 8px; font-family: monospace; font-size: 0.85em; word-break: break-all; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{self.metadata.title}</h1>
            <div class="meta">
                <p>Session: {session.get('name', 'N/A')} ({self.metadata.session_id[:8]}...)</p>
                <p>Generated: {self._format_timestamp(self.metadata.generated_at)}</p>
                <p>Engine: {self.metadata.generator} v{self.metadata.version}</p>
            </div>
        </div>

        <div class="card">
            <h2>Summary Statistics</h2>
            <div class="stats">
                <div class="stat-box">
                    <div class="number">{summary.get('logs', {}).get('total', 0)}</div>
                    <div class="label">Total Logs</div>
                </div>
                <div class="stat-box warning">
                    <div class="number">{summary.get('alerts', {}).get('total', 0)}</div>
                    <div class="label">Total Alerts</div>
                </div>
                <div class="stat-box danger">
                    <div class="number">{summary.get('incidents', {}).get('total', 0)}</div>
                    <div class="label">Incidents</div>
                </div>
                <div class="stat-box success">
                    <div class="number">{len([a for a in alerts if a.get('severity') == 'CRITICAL'])}</div>
                    <div class="label">Critical</div>
                </div>
            </div>
        </div>

        <div class="card">
            <h2>Alert Breakdown</h2>
            <table>
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Type</th>
                        <th>Reason</th>
                        <th>Time</th>
                    </tr>
                </thead>
                <tbody>
{self._generate_alert_rows(alerts)}
                </tbody>
            </table>
        </div>

        <div class="card">
            <h2>Top Threats</h2>
            <table>
                <thead>
                    <tr>
                        <th>Rank</th>
                        <th>Threat</th>
                        <th>Count</th>
                        <th>Severity</th>
                    </tr>
                </thead>
                <tbody>
{self._generate_threat_rows(alerts)}
                </tbody>
            </table>
        </div>

        <div class="card">
            <h2>Incident Timeline</h2>
            <div class="timeline">
{self._generate_timeline(incidents)}
            </div>
        </div>

        <div class="card">
            <h2>Report Integrity</h2>
            <div class="integrity">
                <strong>SHA-256 Hash:</strong><br>
                {self.data.get('integrity_hash', 'N/A')}
            </div>
        </div>

        <div class="footer">
            <p>Generated by {self.metadata.generator} v{self.metadata.version}</p>
            <p>This report is for informational purposes only.</p>
        </div>
    </div>
</body>
</html>"""
        return html

    def _generate_alert_rows(self, alerts: list[dict]) -> str:
        """Generate table rows for alerts."""
        if not alerts:
            return "<tr><td colspan='4'>No alerts</td></tr>"

        rows = []
        for alert in alerts[:20]:  # Limit to 20
            severity = alert.get("severity", "UNKNOWN")
            rows.append(
                f"""                    <tr>
                        <td><span class="badge badge-{severity}">{severity}</span></td>
                        <td>{alert.get('alert_type', 'N/A')}</td>
                        <td>{alert.get('reason', 'N/A')}</td>
                        <td>{alert.get('timestamp', 'N/A')[:19]}</td>
                    </tr>"""
            )
        return "\n".join(rows)

    def _generate_threat_rows(self, alerts: list[dict]) -> str:
        """Generate rows for top threats."""
        from collections import Counter

        # Count by alert_type
        threat_counts = Counter(a.get("alert_type", "UNKNOWN") for a in alerts)
        top_threats = threat_counts.most_common(10)

        if not top_threats:
            return "<tr><td colspan='4'>No threats detected</td></tr>"

        rows = []
        for i, (threat, count) in enumerate(top_threats, 1):
            # Determine severity based on count
            if count > 10:
                severity = "CRITICAL"
            elif count > 5:
                severity = "HIGH"
            elif count > 2:
                severity = "MEDIUM"
            else:
                severity = "LOW"

            rows.append(
                f"""                    <tr>
                        <td>{i}</td>
                        <td>{threat}</td>
                        <td>{count}</td>
                        <td><span class="badge badge-{severity}">{severity}</span></td>
                    </tr>"""
            )
        return "\n".join(rows)

    def _generate_timeline(self, incidents: list[dict]) -> str:
        """Generate timeline items."""
        if not incidents:
            return '<div class="timeline-item">No incidents</div>'

        items = []
        for inc in incidents[:10]:  # Limit to 10
            status_badge = f"<span class='badge badge-{inc.get('severity', 'LOW')}'>{inc.get('status', 'open')}</span>"
            items.append(
                f"""                <div class="timeline-item">
                    <strong>{inc.get('title', 'N/A')}</strong> {status_badge}<br>
                    <small>{inc.get('created', 'N/A')[:19]}</small>
                </div>"""
            )
        return "\n".join(items)

    def save(self, output_path: Path) -> Path:
        """Save HTML report to file."""
        content = self.generate()

        # Compute integrity hash
        integrity_hash = self.compute_integrity_hash(content)
        self.data["integrity_hash"] = integrity_hash

        # Regenerate with hash
        content = self.generate()

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(content, encoding="utf-8")

        logger.info(f"HTML report saved to: {output_path}")
        return output_path