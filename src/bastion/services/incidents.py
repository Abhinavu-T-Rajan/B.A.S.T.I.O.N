from __future__ import annotations

from typing import Any

from bastion.core.contracts.storage import StorageProvider
from bastion.incidents.manager import IncidentManager
from bastion.incidents.models import Incident, IncidentSeverity, IncidentStatus
from bastion.timeline.generator import TimelineGenerator
from bastion.timeline.models import TimelineEntry


class IncidentAppService:
    """Application service for incident lifecycle and forensic investigation timelines."""

    def __init__(self, storage: StorageProvider) -> None:
        self.storage = storage
        self.incident_manager = IncidentManager(storage=self.storage)
        self.timeline_gen = TimelineGenerator(storage=self.storage)

    def list_incidents(
        self,
        status: str | None = None,
        limit: int = 100,
    ) -> list[Incident]:
        """List incidents filtered by status."""
        status_enum = IncidentStatus(status.lower()) if status else None
        return self.incident_manager.list_incidents(status=status_enum, limit=limit)

    def get_incident(self, incident_id: str) -> Incident | None:
        """Fetch incident by unique identifier."""
        return self.incident_manager.get_incident(incident_id)

    def create_incident(
        self,
        title: str,
        severity: str = "medium",
        description: str = "",
        actor_ips: list[str] | None = None,
    ) -> Incident:
        """Create a new manual incident."""
        sev_enum = IncidentSeverity(severity.lower())
        return self.incident_manager.create_incident(
            title=title,
            severity=sev_enum,
            summary=description,
            actors=actor_ips,
        )

    def update_status(
        self,
        incident_id: str,
        status: str,
        resolution_notes: str | None = None,
    ) -> tuple[bool, str]:
        """Update lifecycle status of an incident."""
        try:
            status_enum = IncidentStatus(status.lower())
        except ValueError as exc:
            return False, f"Invalid status: {exc}"

        updated = self.incident_manager.update_status(
            incident_id=incident_id,
            status=status_enum,
            notes=resolution_notes or "",
        )
        if updated:
            return True, f"Incident {incident_id} updated to {status_enum.value.upper()}"
        return False, f"Incident {incident_id} not found"

    def generate_timeline(self, source_ip: str) -> list[TimelineEntry]:
        """Generate chronologically ordered forensic timeline for an IP address."""
        return self.timeline_gen.generate_for_ip(source_ip)
