import json
from datetime import datetime

from src.models.alert import Alert
from src.reporting.json_reporter import JsonReporter


def test_json_reporter_writes_file(tmp_path):
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

    output_file = tmp_path / "alerts.json"
    JsonReporter.write([alert], str(output_file))

    content = json.loads(output_file.read_text(encoding="utf-8"))
    assert "report_metadata" in content
    assert "generated_at" in content["report_metadata"]
    assert content["summary"]["alert_count"] == 1
    assert content["summary"]["alerts_by_severity"]["HIGH"] == 1
    assert content["alerts"][0]["alert_id"] == "a1"