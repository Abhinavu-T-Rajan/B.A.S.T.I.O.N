from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from bastion.incidents.models import Incident, IncidentStatus
from bastion.intelligence.models import Indicator
from bastion.models.actors import ThreatActorProfile
from bastion.models.events import SecurityEvent
from bastion.response.models import BanRecord


class StorageProvider(ABC):
    """Abstract interface for B.A.S.T.I.O.N. persistent storage engines."""

    @abstractmethod
    def save_event(self, event: SecurityEvent) -> None:
        """Persist a normalized SecurityEvent."""
        ...

    @abstractmethod
    def get_events(
        self,
        *,
        limit: int = 100,
        source_ip: str | None = None,
    ) -> list[SecurityEvent]:
        """Query security events by filter."""
        ...

    @abstractmethod
    def upsert_threat_actor(self, profile: ThreatActorProfile) -> None:
        """Insert or update a threat actor profile."""
        ...

    @abstractmethod
    def get_threat_actor(self, source_ip: str) -> ThreatActorProfile | None:
        """Fetch threat actor profile by IP."""
        ...

    @abstractmethod
    def list_threat_actors(
        self,
        *,
        min_score: int = 0,
        limit: int = 100,
    ) -> list[ThreatActorProfile]:
        """List threat actors filtered by minimum score threshold."""
        ...

    @abstractmethod
    def save_ban(self, ban: BanRecord) -> None:
        """Persist a ban record."""
        ...

    @abstractmethod
    def get_ban(self, ban_id: str) -> BanRecord | None:
        """Fetch ban record by ID."""
        ...

    @abstractmethod
    def get_ban_by_ip(self, source_ip: str) -> BanRecord | None:
        """Fetch active or recent ban record for an IP."""
        ...

    @abstractmethod
    def list_bans(
        self,
        *,
        active_only: bool = True,
        limit: int = 100,
    ) -> list[BanRecord]:
        """List active or historical ban records."""
        ...

    @abstractmethod
    def save_ioc(self, ioc: Indicator) -> None:
        """Persist a threat indicator (IOC)."""
        ...

    @abstractmethod
    def get_ioc(self, value: str) -> Indicator | None:
        """Fetch indicator by value."""
        ...

    @abstractmethod
    def list_iocs(
        self,
        *,
        active_only: bool = True,
        limit: int = 100,
    ) -> list[Indicator]:
        """List indicators."""
        ...

    @abstractmethod
    def delete_ioc(self, value: str) -> bool:
        """Delete an indicator by value."""
        ...

    @abstractmethod
    def save_incident(self, incident: Incident) -> None:
        """Persist a security incident."""
        ...

    @abstractmethod
    def get_incident(self, incident_id: str) -> Incident | None:
        """Fetch incident by ID."""
        ...

    @abstractmethod
    def list_incidents(
        self,
        *,
        status: IncidentStatus | None = None,
        limit: int = 100,
    ) -> list[Incident]:
        """List incidents filtered by status."""
        ...

    @abstractmethod
    def get_stats(self) -> dict[str, int]:
        """Return aggregate telemetry and entity statistics."""
        ...

    @abstractmethod
    def close(self) -> None:
        """Safely close storage connections and flush pending writes."""
        ...
