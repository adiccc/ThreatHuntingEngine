from datetime import datetime

from src.models.alert import Alert
from src.reporting.markdown_reporter import MarkdownReporter


def test_markdown_reporter_writes_file(tmp_path):
    alert = Alert(
        alert_id="a1",
        rule_id="RULE-001",
        rule_name="Test Rule",
        severity="high",
        title="Test Alert",
        description="Test description",
        first_seen=datetime.fromisoformat("2026-03-20T09:00:00"),
        last_seen=datetime.fromisoformat("2026-03-20T09:05:00"),
        host="host1",
        user="adi",
        source_ip="1.2.3.4",
        evidence_event_ids=["e1", "e2"],
        evidence_count=2,
        recommended_actions=["Investigate"],
    )

    output_file = tmp_path / "incident_report.md"
    MarkdownReporter.write([alert], str(output_file))

    content = output_file.read_text(encoding="utf-8")
    assert "# Threat Hunting Incident Report" in content
    assert "**Generated at:**" in content
    assert "## Table of Contents" in content
    assert "[Executive Summary](#executive-summary)" in content
    assert "## Executive Summary" in content
    assert "| Severity | Count |" in content
    assert "| Field | Value |" in content
    assert "| Event ID |" in content
    assert "HIGH Severity Alerts" in content
    assert "Test Alert" in content
