from uuid import uuid4

from src.models.alert import Alert
from src.models.event import Event


class SuspiciousProcessExecutionRule:
    rule_id = "RULE-002"
    rule_name = "Suspicious Process Execution"
    severity = "high"

    SUSPICIOUS_PROCESS_NAMES = {
        "powershell.exe",
        "cmd.exe",
        "bash",
    }

    SUSPICIOUS_COMMAND_INDICATORS = {
        "-enc",
        "base64",
        "whoami",
    }

    def detect(self, events: list[Event]) -> list[Alert]:
        process_events = [
            event
            for event in events
            if event.log_type == "process" and event.event_type == "process_start"
        ]

        alerts: list[Alert] = []

        for event in process_events:
            process_name = (event.process_name or "").lower()
            command_line = (event.command_line or "").lower()

            has_suspicious_name = process_name in self.SUSPICIOUS_PROCESS_NAMES
            matched_indicators = [
                indicator
                for indicator in self.SUSPICIOUS_COMMAND_INDICATORS
                if indicator in command_line
            ]

            if not has_suspicious_name or not matched_indicators:
                continue

            if process_name == "powershell.exe" and "-enc" in matched_indicators:
                severity = "high"
                title = "Suspicious encoded PowerShell execution detected"
            else:
                severity = "medium"
                title = "Suspicious process execution detected"

            description = (
                f"Detected suspicious process execution: process='{event.process_name}', "
                f"parent='{event.parent_process}', indicators={matched_indicators}."
            )

            alert = Alert(
                alert_id=str(uuid4()),
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=severity,
                title=title,
                description=description,
                first_seen=event.timestamp,
                last_seen=event.timestamp,
                host=event.host,
                user=event.user,
                source_ip=event.source_ip,
                evidence_event_ids=[event.event_id],
                evidence_count=1,
                recommended_actions=[
                    "Review the full command line and execution context.",
                    "Inspect the parent process and child process chain.",
                    "Check whether the command was expected for this user and host.",
                    "Investigate related authentication and network activity around this time.",
                ],
            )
            alerts.append(alert)

        return alerts