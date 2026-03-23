from src.models.alert import Alert


class ConsoleReporter:
    @staticmethod
    def print_alerts(alerts: list[Alert]) -> None:
        if not alerts:
            print("No alerts detected.")
            return

        print("\nDetected Alerts:")
        print("=" * 80)

        for alert in alerts:
            print(f"[{alert.severity.upper()}] {alert.title}")
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