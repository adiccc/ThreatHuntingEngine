from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class Alert:
    alert_id: str
    rule_id: str
    rule_name: str
    severity: str
    title: str
    description: str
    first_seen: datetime
    last_seen: datetime
    host: Optional[str] = None
    user: Optional[str] = None
    source_ip: Optional[str] = None
    evidence_event_ids: list[str] = field(default_factory=list)
    evidence_count: int = 0
    recommended_actions: list[str] = field(default_factory=list)