from datetime import timedelta
from uuid import uuid4

from src.models.alert import Alert
from src.models.event import Event


class BruteForceFollowedBySuccessRule:
    rule_id = "RULE-001"
    rule_name = "Brute Force Followed by Success"
    severity = "high"

    def __init__(self, failure_threshold: int = 5, window_minutes: int = 5):
        self.failure_threshold = failure_threshold
        self.window = timedelta(minutes=window_minutes)

    def detect(self, events: list[Event]) -> list[Alert]:
        auth_events = [
            event
            for event in events
            if event.log_type == "authentication" and event.event_type == "login"
        ]

        grouped: dict[tuple[str | None, str | None, str | None], list[Event]] = {}

        for event in auth_events:
            key = (event.user, event.source_ip, event.host)
            grouped.setdefault(key, []).append(event)

        alerts: list[Alert] = []

        for (user, source_ip, host), group_events in grouped.items():
            group_events.sort(key=lambda event: event.timestamp)

            for index, event in enumerate(group_events):
                if event.status != "success":
                    continue

                success_time = event.timestamp
                failures_before_success = [
                    candidate
                    for candidate in group_events[:index]
                    if candidate.status == "failure"
                    and success_time - candidate.timestamp <= self.window
                ]

                if len(failures_before_success) >= self.failure_threshold:
                    evidence_events = failures_before_success + [event]

                    alert = Alert(
                        alert_id=str(uuid4()),
                        rule_id=self.rule_id,
                        rule_name=self.rule_name,
                        severity=self.severity,
                        title="Possible brute force attack followed by successful login",
                        description=(
                            f"Detected {len(failures_before_success)} failed login attempts "
                            f"followed by a successful login within "
                            f"{int(self.window.total_seconds() // 60)} minutes."
                        ),
                        first_seen=evidence_events[0].timestamp,
                        last_seen=evidence_events[-1].timestamp,
                        host=host,
                        user=user,
                        source_ip=source_ip,
                        evidence_event_ids=[e.event_id for e in evidence_events],
                        evidence_count=len(evidence_events),
                        recommended_actions=[
                            "Review the source IP for suspicious activity.",
                            "Validate whether this login was expected.",
                            "Check for additional suspicious activity on the host.",
                            "Consider resetting the affected user's credentials.",
                        ],
                    )
                    alerts.append(alert)

                    break

        return alerts