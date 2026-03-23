from src.detection.rules.suspicious_process_rule import (
    SuspiciousProcessExecutionRule,
)
from src.normalization.event_normalizer import EventNormalizer


def test_suspicious_process_execution_detects_encoded_powershell():
    process_records = [
        {
            "timestamp": "2026-03-20T09:03:00",
            "host": "host1",
            "username": "adi",
            "process_name": "powershell.exe",
            "parent_process": "explorer.exe",
            "command_line": "powershell.exe -enc SQBFAFgA",
        }
    ]

    events = EventNormalizer.normalize_all(
        auth_records=[],
        process_records=process_records,
        network_records=[],
    )

    rule = SuspiciousProcessExecutionRule()
    alerts = rule.detect(events)

    assert len(alerts) == 1
    assert alerts[0].user == "adi"
    assert alerts[0].host == "host1"
    assert alerts[0].severity == "high"
    assert "powershell" in alerts[0].title.lower()