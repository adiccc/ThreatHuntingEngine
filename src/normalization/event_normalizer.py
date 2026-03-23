from datetime import datetime
from uuid import uuid4

from src.models.event import Event


class EventNormalizer:
    @staticmethod
    def _parse_timestamp(timestamp: str) -> datetime:
        return datetime.fromisoformat(timestamp)

    @staticmethod
    def normalize_auth_records(records: list[dict]) -> list[Event]:
        events: list[Event] = []

        for record in records:
            event = Event(
                event_id=str(uuid4()),
                timestamp=EventNormalizer._parse_timestamp(record["timestamp"]),
                log_type="authentication",
                event_type=record["event_type"],
                host=record.get("host"),
                user=record.get("username"),
                source_ip=record.get("source_ip"),
                status=record.get("status"),
                raw=record,
            )
            events.append(event)

        return events

    @staticmethod
    def normalize_process_records(records: list[dict]) -> list[Event]:
        events: list[Event] = []

        for record in records:
            event = Event(
                event_id=str(uuid4()),
                timestamp=EventNormalizer._parse_timestamp(record["timestamp"]),
                log_type="process",
                event_type="process_start",
                host=record.get("host"),
                user=record.get("username"),
                process_name=record.get("process_name"),
                parent_process=record.get("parent_process"),
                command_line=record.get("command_line"),
                raw=record,
            )
            events.append(event)

        return events

    @staticmethod
    def normalize_network_records(records: list[dict]) -> list[Event]:
        events: list[Event] = []

        for record in records:
            event = Event(
                event_id=str(uuid4()),
                timestamp=EventNormalizer._parse_timestamp(record["timestamp"]),
                log_type="network",
                event_type="network_connection",
                host=record.get("host"),
                source_ip=record.get("source_ip"),
                destination_ip=record.get("destination_ip"),
                destination_port=int(record["destination_port"]),
                protocol=record.get("protocol"),
                raw=record,
            )
            events.append(event)

        return events

    @staticmethod
    def normalize_all(
        auth_records: list[dict],
        process_records: list[dict],
        network_records: list[dict],
    ) -> list[Event]:
        all_events: list[Event] = []

        all_events.extend(EventNormalizer.normalize_auth_records(auth_records))
        all_events.extend(EventNormalizer.normalize_process_records(process_records))
        all_events.extend(EventNormalizer.normalize_network_records(network_records))

        all_events.sort(key=lambda event: event.timestamp)
        return all_events