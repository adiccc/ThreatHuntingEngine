from collections import Counter
from src.models.alert import Alert


SEVERITY_ORDER = {
    "high": 0,
    "medium": 1,
    "low": 2,
}


def sort_alerts(alerts: list[Alert]) -> list[Alert]:
    return sorted(
        alerts,
        key=lambda alert: (
            SEVERITY_ORDER.get(alert.severity.lower(), 99),
            alert.first_seen,
        ),
    )


def summarize_by_severity(alerts: list[Alert]) -> dict[str, int]:
    counter = Counter(alert.severity.upper() for alert in alerts)
    return dict(counter)


def summarize_by_rule(alerts: list[Alert]) -> dict[str, int]:
    counter = Counter(alert.rule_name for alert in alerts)
    return dict(counter)


def format_timestamp(dt) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S")