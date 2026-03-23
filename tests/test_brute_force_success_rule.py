from src.detection.rules.brute_force_success_rule import (
    BruteForceFollowedBySuccessRule,
)
from src.normalization.event_normalizer import EventNormalizer


def test_brute_force_followed_by_success_detects_alert():
    auth_records = [
        {
            "timestamp": "2026-03-20T09:00:00",
            "username": "adi",
            "source_ip": "185.24.10.8",
            "host": "host1",
            "event_type": "login",
            "status": "failure",
        },
        {
            "timestamp": "2026-03-20T09:00:30",
            "username": "adi",
            "source_ip": "185.24.10.8",
            "host": "host1",
            "event_type": "login",
            "status": "failure",
        },
        {
            "timestamp": "2026-03-20T09:01:00",
            "username": "adi",
            "source_ip": "185.24.10.8",
            "host": "host1",
            "event_type": "login",
            "status": "failure",
        },
        {
            "timestamp": "2026-03-20T09:01:30",
            "username": "adi",
            "source_ip": "185.24.10.8",
            "host": "host1",
            "event_type": "login",
            "status": "failure",
        },
        {
            "timestamp": "2026-03-20T09:02:00",
            "username": "adi",
            "source_ip": "185.24.10.8",
            "host": "host1",
            "event_type": "login",
            "status": "failure",
        },
        {
            "timestamp": "2026-03-20T09:02:30",
            "username": "adi",
            "source_ip": "185.24.10.8",
            "host": "host1",
            "event_type": "login",
            "status": "success",
        },
    ]

    events = EventNormalizer.normalize_all(
        auth_records=auth_records,
        process_records=[],
        network_records=[],
    )

    rule = BruteForceFollowedBySuccessRule(failure_threshold=5, window_minutes=5)
    alerts = rule.detect(events)

    assert len(alerts) == 1
    assert alerts[0].user == "adi"
    assert alerts[0].source_ip == "185.24.10.8"
    assert alerts[0].severity == "high"