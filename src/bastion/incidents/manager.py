from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, List, Optional

from bastion.incidents.models import Incident, IncidentStatus
from bastion.models.actors import Severity

if TYPE_CHECKING:
    from bastion.storage.sqlite import SQLiteStorage


class IncidentManager:
    """Manages creation, aggregation, and lifecycle tracking of security incidents."""

    def __init__(self, storage: SQLiteStorage) -> None:
        self.storage = storage

    def create_incident(
        self,
        title: str,
        severity: Severity = Severity.LOW,
        risk_score: int = 0,
        summary: str = "",
        actors: Optional[List[str]] = None,
        events: Optional[List[int]] = None,
        iocs: Optional[List[str]] = None,
        techniques: Optional[List[str]] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> Incident:
        """Create and persist a new security incident."""
        now = datetime.now(timezone.utc)
        incident = Incident(
            title=title,
            status=IncidentStatus.OPEN,
            severity=severity,
            risk_score=risk_score,
            first_seen=now,
            last_seen=now,
            related_events=events or [],
            related_actors=actors or [],
            related_iocs=iocs or [],
            attack_techniques=techniques or [],
            summary=summary,
            created_at=now,
            updated_at=now,
            metadata=metadata or {},
        )
        self.storage.save_incident(incident)
        return incident

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        """Retrieve an incident by its ID."""
        return self.storage.get_incident(incident_id)

    def update_incident(self, incident: Incident) -> None:
        """Persist updates to an existing incident."""
        incident.updated_at = datetime.now(timezone.utc)
        self.storage.save_incident(incident)

    def update_status(
        self,
        incident_id: str,
        status: IncidentStatus | str,
        notes: str = "",
    ) -> Optional[Incident]:
        """Update incident status and append notes."""
        incident = self.get_incident(incident_id)
        if not incident:
            return None

        status_enum = IncidentStatus(status.lower()) if isinstance(status, str) else status
        incident.status = status_enum
        if notes:
            incident.summary = f"{incident.summary}\n[{datetime.now(timezone.utc).isoformat()}] Status changed to {status_enum.value}: {notes}".strip()
        incident.updated_at = datetime.now(timezone.utc)
        self.storage.save_incident(incident)
        return incident

    def list_incidents(
        self,
        status: Optional[IncidentStatus | str] = None,
        limit: int = 50,
    ) -> List[Incident]:
        """List incidents with optional status filter."""
        status_enum = IncidentStatus(status.lower()) if isinstance(status, str) else status
        return self.storage.list_incidents(status=status_enum, limit=limit)

    def find_active_incident_for_actor(self, actor_id: str) -> Optional[Incident]:
        """Find the most recent open or investigating incident involving an actor."""
        return self.storage.find_active_incident_for_actor(actor_id)
