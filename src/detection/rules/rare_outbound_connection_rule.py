import ipaddress
from uuid import uuid4

from src.models.alert import Alert
from src.models.event import Event


class RareOutboundConnectionRule:
    rule_id = "RULE-003"
    rule_name = "Rare Outbound Connection"
    severity = "medium"

    COMMON_PORTS = {53, 80, 123, 443}

    @staticmethod
    def _is_external_ip(ip_address: str | None) -> bool:
        if not ip_address:
            return False

        try:
            ip_obj = ipaddress.ip_address(ip_address)
            return not ip_obj.is_private
        except ValueError:
            return False

    def detect(self, events: list[Event]) -> list[Alert]:
        network_events = [
            event
            for event in events
            if event.log_type == "network" and event.event_type == "network_connection"
        ]

        alerts: list[Alert] = []

        for event in network_events:
            is_external = self._is_external_ip(event.destination_ip)
            destination_port = event.destination_port

            if not is_external:
                continue

            if destination_port in self.COMMON_PORTS:
                continue

            alert = Alert(
                alert_id=str(uuid4()),
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                title="Rare outbound network connection detected",
                description=(
                    f"Detected outbound connection from host '{event.host}' "
                    f"to external IP '{event.destination_ip}' on uncommon port "
                    f"'{destination_port}/{event.protocol}'."
                ),
                first_seen=event.timestamp,
                last_seen=event.timestamp,
                host=event.host,
                user=event.user,
                source_ip=event.source_ip,
                evidence_event_ids=[event.event_id],
                evidence_count=1,
                recommended_actions=[
                    "Review the destination IP and port for known malicious activity.",
                    "Inspect processes running on the source host around this time.",
                    "Check whether this outbound connection is expected for the host.",
                    "Correlate this event with recent authentication or process alerts.",
                ],
            )
            alerts.append(alert)

        return alerts