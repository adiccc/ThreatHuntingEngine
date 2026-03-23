from src.detection.rules.rare_outbound_connection_rule import (
    RareOutboundConnectionRule,
)
from src.normalization.event_normalizer import EventNormalizer


def test_rare_outbound_connection_detects_external_uncommon_port():
    network_records = [
        {
            "timestamp": "2026-03-20T09:05:00",
            "host": "host1",
            "source_ip": "10.0.0.5",
            "destination_ip": "185.99.88.77",
            "destination_port": 4444,
            "protocol": "TCP",
        }
    ]

    events = EventNormalizer.normalize_all(
        auth_records=[],
        process_records=[],
        network_records=network_records,
    )

    rule = RareOutboundConnectionRule()
    alerts = rule.detect(events)

    assert len(alerts) == 1
    assert alerts[0].host == "host1"
    assert alerts[0].source_ip == "10.0.0.5"
    assert alerts[0].severity == "medium"
    assert "outbound" in alerts[0].title.lower()


def test_rare_outbound_connection_ignores_common_port():
    network_records = [
        {
            "timestamp": "2026-03-20T08:06:00",
            "host": "host1",
            "source_ip": "10.0.0.5",
            "destination_ip": "52.97.162.34",
            "destination_port": 443,
            "protocol": "TCP",
        }
    ]

    events = EventNormalizer.normalize_all(
        auth_records=[],
        process_records=[],
        network_records=network_records,
    )

    rule = RareOutboundConnectionRule()
    alerts = rule.detect(events)

    assert len(alerts) == 0