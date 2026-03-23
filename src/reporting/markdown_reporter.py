from collections import defaultdict
from datetime import datetime
from pathlib import Path

from src.models.alert import Alert
from src.reporting.report_utils import (
    format_timestamp,
    sort_alerts,
    summarize_by_rule,
    summarize_by_severity,
)


class MarkdownReporter:
    @staticmethod
    def _append_table(lines: list[str], headers: list[str], rows: list[list[str]]) -> None:
        lines.append(f"| {' | '.join(headers)} |")
        lines.append(f"| {' | '.join('---' for _ in headers)} |")
        for row in rows:
            lines.append(f"| {' | '.join(row)} |")
        lines.append("")

    @staticmethod
    def write(alerts: list[Alert], output_path: str) -> None:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        sorted_alerts = sort_alerts(alerts)
        severity_summary = summarize_by_severity(sorted_alerts)
        rule_summary = summarize_by_rule(sorted_alerts)
        generated_at = datetime.now()

        lines: list[str] = []

        lines.append("# Threat Hunting Incident Report")
        lines.append("")
        lines.append(f"**Generated at:** {format_timestamp(generated_at)}")
        lines.append("")

        lines.append("## Table of Contents")
        lines.append("")
        lines.append("- [Executive Summary](#executive-summary)")

        if any(alert.severity.lower() == "high" for alert in sorted_alerts):
            lines.append("- [HIGH Severity Alerts](#high-severity-alerts)")
        if any(alert.severity.lower() == "medium" for alert in sorted_alerts):
            lines.append("- [MEDIUM Severity Alerts](#medium-severity-alerts)")
        if any(alert.severity.lower() == "low" for alert in sorted_alerts):
            lines.append("- [LOW Severity Alerts](#low-severity-alerts)")

        lines.append("")

        lines.append("## Executive Summary")
        lines.append("")
        lines.append(f"**Total alerts detected:** {len(sorted_alerts)}")
        lines.append("")

        if severity_summary:
            lines.append("### Alerts by Severity")
            lines.append("")
            MarkdownReporter._append_table(
                lines,
                ["Severity", "Count"],
                [[severity, str(count)] for severity, count in severity_summary.items()],
            )

        if rule_summary:
            lines.append("### Alerts by Rule")
            lines.append("")
            MarkdownReporter._append_table(
                lines,
                ["Rule", "Count"],
                [[rule_name, str(count)] for rule_name, count in rule_summary.items()],
            )

        if not sorted_alerts:
            lines.append("No alerts were detected.")
        else:
            grouped_alerts: dict[str, list[Alert]] = defaultdict(list)
            for alert in sorted_alerts:
                grouped_alerts[alert.severity.upper()].append(alert)

            for severity in ["HIGH", "MEDIUM", "LOW"]:
                alerts_in_group = grouped_alerts.get(severity, [])
                if not alerts_in_group:
                    continue

                lines.append(f"## {severity} Severity Alerts")
                lines.append("")

                for index, alert in enumerate(alerts_in_group, start=1):
                    lines.append(f"### {index}. {alert.title}")
                    lines.append("")
                    MarkdownReporter._append_table(
                        lines,
                        ["Field", "Value"],
                        [
                            ["Alert ID", f"`{alert.alert_id}`"],
                            ["Rule", f"`{alert.rule_name}` (`{alert.rule_id}`)"],
                            ["Severity", f"`{alert.severity.upper()}`"],
                            ["User", f"`{alert.user or 'N/A'}`"],
                            ["Host", f"`{alert.host or 'N/A'}`"],
                            ["Source IP", f"`{alert.source_ip or 'N/A'}`"],
                            ["First Seen", f"`{format_timestamp(alert.first_seen)}`"],
                            ["Last Seen", f"`{format_timestamp(alert.last_seen)}`"],
                            ["Evidence Count", f"`{alert.evidence_count}`"],
                        ],
                    )
                    lines.append("#### Description")
                    lines.append(alert.description)
                    lines.append("")
                    lines.append("#### Recommended Actions")
                    for action in alert.recommended_actions:
                        lines.append(f"- {action}")
                    lines.append("")
                    lines.append("#### Evidence Event IDs")
                    MarkdownReporter._append_table(
                        lines,
                        ["Event ID"],
                        [[f"`{event_id}`"] for event_id in alert.evidence_event_ids],
                    )
                    lines.append("---")
                    lines.append("")

        with path.open("w", encoding="utf-8") as file:
            file.write("\n".join(lines))
