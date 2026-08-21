from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

class EventType(StrEnum):
    "Events that can be logged by the bastion"
    AUTH_FAILURE = "auth_failure"
    AUTH_SUCCESS = "auth_success"
    INVALID_USER = "invalid_user"
    CONNECTION = "connection"
    UNKOWN = "unknown"

class ServiceType(StrEnum):
    "Services that can be logged by the bastion"
    SSH = "ssh"
    HTTP = "http"
    FTP = "ftp"
    UNKNOWN = "unknown"

@dataclass(frozen=True, slots=True)
class SecurityEvent:
    timestamp: datetime
    source_ip: str
    service: ServiceType
    event_type: EventType
    username: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.timestamp.tzinfo is None:
            raise ValueError("timestamp must be timezone-aware")
        if not self.source_ip:
            raise ValueError("source_ip must be a non-empty string")

@classmethod
def now(
    cls,
    *,
    source_ip: str,
    service: ServiceType,
    event_type: EventType,
    username: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> SecurityEvent:
    
    return cls(
        timestamp=datetime.now(timezone.utc),
        source_ip=source_ip,
        service=service,
        event_type=event_type,
        username=username,
        metadata=metadata or {},
    )