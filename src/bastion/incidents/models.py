from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from bastion.models.actors import Severity


class IncidentStatus(StrEnum):
    """Lifecycle states of a security incident."""

    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RESOLVED = "resolved"
    CLOSED = "closed"


@dataclass
class Incident:
    """Security Incident representing an aggregated attack cluster or investigation."""

    title: str
    incident_id: str = field(
        default_factory=lambda: f"inc-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:6]}"
    )
    status: IncidentStatus = IncidentStatus.OPEN
    severity: Severity = Severity.LOW
    risk_score: int = 0
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    related_events: list[int] = field(default_factory=list)
    related_actors: list[str] = field(default_factory=list)
    related_iocs: list[str] = field(default_factory=list)
    attack_techniques: list[str] = field(default_factory=list)
    summary: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if isinstance(self.status, str) and not isinstance(self.status, IncidentStatus):
            self.status = IncidentStatus(self.status.lower())
        if isinstance(self.severity, str) and not isinstance(self.severity, Severity):
            self.severity = Severity(self.severity.upper())
        self.risk_score = max(0, min(100, int(self.risk_score)))

    def to_dict(self) -> dict[str, Any]:
        """Serialize incident to dictionary."""
        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "status": self.status.value,
            "severity": self.severity.value,
            "risk_score": self.risk_score,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "related_events": self.related_events,
            "related_actors": self.related_actors,
            "related_iocs": self.related_iocs,
            "attack_techniques": self.attack_techniques,
            "summary": self.summary,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Incident:
        """Construct an Incident from a dictionary."""
        first_seen = data.get("first_seen")
        last_seen = data.get("last_seen")
        created_at = data.get("created_at")
        updated_at = data.get("updated_at")

        first_seen_dt = (
            datetime.fromisoformat(first_seen)
            if isinstance(first_seen, str)
            else (first_seen or datetime.now(timezone.utc))
        )
        last_seen_dt = (
            datetime.fromisoformat(last_seen)
            if isinstance(last_seen, str)
            else (last_seen or datetime.now(timezone.utc))
        )
        created_at_dt = (
            datetime.fromisoformat(created_at)
            if isinstance(created_at, str)
            else (created_at or datetime.now(timezone.utc))
        )
        updated_at_dt = (
            datetime.fromisoformat(updated_at)
            if isinstance(updated_at, str)
            else (updated_at or datetime.now(timezone.utc))
        )

        attack_techs = data.get("attack_techniques", [])
        if isinstance(attack_techs, str):
            try:
                attack_techs = json.loads(attack_techs)
            except Exception:
                attack_techs = [t.strip() for t in attack_techs.split(",") if t.strip()]

        metadata = data.get("metadata", {})
        if isinstance(metadata, str):
            try:
                metadata = json.loads(metadata)
            except Exception:
                metadata = {}

        return cls(
            incident_id=data.get("incident_id", f"inc-{uuid.uuid4().hex[:8]}"),
            title=data.get("title", "Security Incident"),
            status=IncidentStatus(data.get("status", "open").lower()),
            severity=Severity(data.get("severity", "LOW").upper()),
            risk_score=int(data.get("risk_score", 0)),
            first_seen=first_seen_dt,
            last_seen=last_seen_dt,
            related_events=data.get("related_events", []),
            related_actors=data.get("related_actors", []),
            related_iocs=data.get("related_iocs", []),
            attack_techniques=attack_techs,
            summary=data.get("summary", ""),
            created_at=created_at_dt,
            updated_at=updated_at_dt,
            metadata=metadata,
        )
