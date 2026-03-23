from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional


@dataclass
class Event:
    event_id: str
    timestamp: datetime
    log_type: str
    event_type: str
    host: Optional[str] = None
    user: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    process_name: Optional[str] = None
    parent_process: Optional[str] = None
    command_line: Optional[str] = None
    status: Optional[str] = None
    protocol: Optional[str] = None
    raw: dict[str, Any] = field(default_factory=dict)