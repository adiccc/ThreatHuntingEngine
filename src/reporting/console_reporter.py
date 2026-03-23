from src.models.alert import Alert
from src.reporting.report_utils import (
    sort_alerts,
    summarize_by_rule,
    summarize_by_severity,
)


class ConsoleReporter:
    @staticmethod
    def print_alerts(alerts: list[Alert]) -> None:
        sorted_alerts = sort_alerts(alerts)

        if not sorted_alerts:
            print("No alerts detected.")
            return

        severity_summary = summarize_by_severity(sorted_alerts)
        rule_summary = summarize_by_rule(sorted_alerts)

        print("\nDetected Alerts:")
        print("=" * 80)
        print(f"Total alerts: {len(sorted_alerts)}")
        print("Alerts by severity:")
        for severity, count in severity_summary.items():
            print(f"  - {severity}: {count}")

        print("Alerts by rule:")
        for rule_name, count in rule_summary.items():
            print(f"  - {rule_name}: {count}")

        print("=" * 80)

        for alert in sorted_alerts:
            print(f"[{alert.severity.upper()}] {alert.title}")
            print(f"Alert ID: {alert.alert_id}")
            print(f"Rule: {alert.rule_name} ({alert.rule_id})")
            print(f"User: {alert.user}")
            print(f"Host: {alert.host}")
            print(f"Source IP: {alert.source_ip}")
            print(f"First Seen: {alert.first_seen}")
            print(f"Last Seen: {alert.last_seen}")
            print(f"Evidence Count: {alert.evidence_count}")
            print(f"Description: {alert.description}")
            print("Recommended Actions:")
            for action in alert.recommended_actions:
                print(f"  - {action}")
            print("-" * 80)