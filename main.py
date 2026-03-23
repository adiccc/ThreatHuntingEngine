from collections import Counter

from src.detection.detection_engine import DetectionEngine
from src.detection.rules.brute_force_success_rule import (
    BruteForceFollowedBySuccessRule,
)
from src.detection.rules.suspicious_process_rule import (
    SuspiciousProcessExecutionRule,
)
from src.detection.rules.rare_outbound_connection_rule import (
    RareOutboundConnectionRule,
)
from src.ingestion.log_loader import LogLoader
from src.normalization.event_normalizer import EventNormalizer
from src.parsers.auth_parser import AuthenticationLogParser
from src.parsers.network_parser import NetworkLogParser
from src.parsers.process_parser import ProcessLogParser
from src.reporting.console_reporter import ConsoleReporter


def main():
    auth_df = LogLoader.load_csv("data/sample_logs/auth_logs.csv")
    process_df = LogLoader.load_csv("data/sample_logs/process_logs.csv")
    network_df = LogLoader.load_csv("data/sample_logs/network_logs.csv")

    auth_records = AuthenticationLogParser.parse(auth_df)
    process_records = ProcessLogParser.parse(process_df)
    network_records = NetworkLogParser.parse(network_df)

    all_events = EventNormalizer.normalize_all(
        auth_records=auth_records,
        process_records=process_records,
        network_records=network_records,
    )

    print(f"Total normalized events: {len(all_events)}")
    print("-" * 80)

    log_type_counts = Counter(event.log_type for event in all_events)
    print("Event counts by log type:")
    for log_type, count in log_type_counts.items():
        print(f"{log_type}: {count}")

    rules = [
        BruteForceFollowedBySuccessRule(failure_threshold=5, window_minutes=5),
        SuspiciousProcessExecutionRule(),
        RareOutboundConnectionRule(),
    ]

    detection_engine = DetectionEngine(rules=rules)
    alerts = detection_engine.run(all_events)

    ConsoleReporter.print_alerts(alerts)


if __name__ == "__main__":
    main()