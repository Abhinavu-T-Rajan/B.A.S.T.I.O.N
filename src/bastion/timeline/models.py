from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Optional


class TimelineEntryType(StrEnum):
    """Category of chronological timeline evidence."""

    EVENT = "event"
    DETECTION = "detection"
    IOC_MATCH = "ioc_match"
    RISK_CHANGE = "risk_change"
    ACTOR_STATE = "actor_state"
    INCIDENT_UPDATE = "incident_update"
    RESPONSE_ACTION = "response_action"


@dataclass
class TimelineEntry:
    """Individual chronological event record in an investigation timeline."""

    timestamp: datetime
    entry_type: TimelineEntryType
    source: str
    summary: str
    details: dict[str, Any] = field(default_factory=dict)
    entry_id: str = field(default_factory=lambda: f"tle-{uuid.uuid4().hex[:10]}")
    incident_id: Optional[str] = None
    actor_id: Optional[str] = None

    def __post_init__(self) -> None:
        if isinstance(self.entry_type, str) and not isinstance(self.entry_type, TimelineEntryType):
            self.entry_type = TimelineEntryType(self.entry_type.lower())
        if self.timestamp.tzinfo is None:
            self.timestamp = self.timestamp.replace(tzinfo=timezone.utc)

    def to_dict(self) -> dict[str, Any]:
        """Convert entry to dictionary."""
        return {
            "entry_id": self.entry_id,
            "timestamp": self.timestamp.isoformat(),
            "entry_type": self.entry_type.value,
            "source": self.source,
            "summary": self.summary,
            "details": self.details,
            "incident_id": self.incident_id,
            "actor_id": self.actor_id,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TimelineEntry:
        """Construct a TimelineEntry from a dictionary."""
        ts_val = data["timestamp"]
        ts_dt = (
            datetime.fromisoformat(ts_val)
            if isinstance(ts_val, str)
            else (ts_val or datetime.now(timezone.utc))
        )
        if ts_dt.tzinfo is None:
            ts_dt = ts_dt.replace(tzinfo=timezone.utc)

        details = data.get("details", {})
        if isinstance(details, str):
            try:
                details = json.loads(details)
            except Exception:
                details = {}

        return cls(
            entry_id=data.get("entry_id", f"tle-{uuid.uuid4().hex[:10]}"),
            timestamp=ts_dt,
            entry_type=TimelineEntryType(data["entry_type"].lower()),
            source=data.get("source", "system"),
            summary=data["summary"],
            details=details,
            incident_id=data.get("incident_id"),
            actor_id=data.get("actor_id"),
        )
