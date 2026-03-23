import json
from datetime import datetime
from pathlib import Path

from src.models.alert import Alert
from src.reporting.report_utils import (
    format_timestamp,
    sort_alerts,
    summarize_by_rule,
    summarize_by_severity,
)


class JsonReporter:
    @staticmethod
    def _serialize_alert(alert: Alert) -> dict:
        return {
            "alert_id": alert.alert_id,
            "rule_id": alert.rule_id,
            "rule_name": alert.rule_name,
            "severity": alert.severity,
            "title": alert.title,
            "description": alert.description,
            "first_seen": alert.first_seen.isoformat(),
            "last_seen": alert.last_seen.isoformat(),
            "first_seen_pretty": format_timestamp(alert.first_seen),
            "last_seen_pretty": format_timestamp(alert.last_seen),
            "host": alert.host,
            "user": alert.user,
            "source_ip": alert.source_ip,
            "evidence_event_ids": alert.evidence_event_ids,
            "evidence_count": alert.evidence_count,
            "recommended_actions": alert.recommended_actions,
        }

    @staticmethod
    def write(alerts: list[Alert], output_path: str) -> None:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        sorted_alerts = sort_alerts(alerts)
        generated_at = datetime.now()

        payload = {
            "report_metadata": {
                "generated_at": generated_at.isoformat(),
                "generated_at_pretty": format_timestamp(generated_at),
            },
            "summary": {
                "alert_count": len(sorted_alerts),
                "alerts_by_severity": summarize_by_severity(sorted_alerts),
                "alerts_by_rule": summarize_by_rule(sorted_alerts),
            },
            "alerts": [JsonReporter._serialize_alert(alert) for alert in sorted_alerts],
        }

        with path.open("w", encoding="utf-8") as file:
            json.dump(payload, file, indent=2)