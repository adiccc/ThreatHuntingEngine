from src.normalization.event_normalizer import EventNormalizer


def test_normalize_all_sorts_events_by_timestamp():
    auth_records = [
        {
            "timestamp": "2026-03-20T09:00:00",
            "username": "adi",
            "source_ip": "1.1.1.1",
            "host": "host1",
            "event_type": "login",
            "status": "success",
        }
    ]

    process_records = [
        {
            "timestamp": "2026-03-20T08:00:00",
            "host": "host1",
            "username": "adi",
            "process_name": "chrome.exe",
            "parent_process": "explorer.exe",
            "command_line": "chrome.exe",
        }
    ]

    network_records = [
        {
            "timestamp": "2026-03-20T10:00:00",
            "host": "host1",
            "source_ip": "10.0.0.5",
            "destination_ip": "8.8.8.8",
            "destination_port": 53,
            "protocol": "UDP",
        }
    ]

    events = EventNormalizer.normalize_all(
        auth_records=auth_records,
        process_records=process_records,
        network_records=network_records,
    )

    assert len(events) == 3
    assert events[0].log_type == "process"
    assert events[1].log_type == "authentication"
    assert events[2].log_type == "network"