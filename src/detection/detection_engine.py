from src.models.alert import Alert
from src.models.event import Event


class DetectionEngine:
    def __init__(self, rules: list):
        self.rules = rules

    def run(self, events: list[Event]) -> list[Alert]:
        alerts: list[Alert] = []

        for rule in self.rules:
            rule_alerts = rule.detect(events)
            alerts.extend(rule_alerts)

        return alerts