from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from bastion.intelligence.models import IOCRecord, IOCStatus, IOCType, Provenance
from bastion.intelligence.validator import IOCValidator
from bastion.models.events import SecurityEvent

if TYPE_CHECKING:
    from bastion.storage.sqlite import SQLiteStorage


class IOCManager:
    """Manager for Indicators of Compromise (IOCs) and threat correlation."""

    def __init__(self, storage: SQLiteStorage) -> None:
        self.storage = storage

    def add_ioc(
        self,
        ioc_type: IOCType | str,
        value: str,
        confidence: int = 50,
        source: str = "local",
        status: IOCStatus | str = IOCStatus.ACTIVE,
        provenance: Provenance | str = Provenance.CONFIGURED,
        tags: list[str] | None = None,
        notes: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> IOCRecord:
        """Validate and add an IOC record to persistent storage."""
        if isinstance(ioc_type, str):
            ioc_type = IOCType(ioc_type.lower())
        if isinstance(status, str):
            status = IOCStatus(status.lower())
        if isinstance(provenance, str):
            provenance = Provenance(provenance.lower())

        is_valid, normalized_or_err = IOCValidator.validate(ioc_type, value)
        if not is_valid:
            raise ValueError(f"Invalid IOC value: {normalized_or_err}")

        # Check if identical active IOC already exists for this value & type
        existing = self.storage.get_ioc_by_type_value(ioc_type, normalized_or_err)
        if existing:
            # Update last_seen, confidence, tags
            existing.last_seen = datetime.now(timezone.utc)
            existing.confidence = max(existing.confidence, confidence)
            if tags:
                merged_tags = list(set(existing.tags + tags))
                existing.tags = merged_tags
            if notes:
                existing.notes = f"{existing.notes}\n{notes}".strip()
            self.storage.save_ioc(existing)
            return existing

        ioc = IOCRecord(
            ioc_type=ioc_type,
            value=normalized_or_err,
            confidence=confidence,
            source=source,
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
            status=status,
            provenance=provenance,
            tags=tags or [],
            notes=notes,
            metadata=metadata or {},
        )
        self.storage.save_ioc(ioc)
        return ioc

    def get_ioc(self, ioc_id: str) -> IOCRecord | None:
        """Retrieve an IOC record by ID."""
        return self.storage.get_ioc(ioc_id)

    def delete_ioc(self, ioc_id: str) -> bool:
        """Delete an IOC record by ID."""
        return self.storage.delete_ioc(ioc_id)

    def list_iocs(
        self,
        ioc_type: IOCType | str | None = None,
        status: IOCStatus | str | None = None,
        limit: int = 100,
    ) -> list[IOCRecord]:
        """List IOC records with optional filtering."""
        type_enum = IOCType(ioc_type.lower()) if isinstance(ioc_type, str) else ioc_type
        status_enum = IOCStatus(status.lower()) if isinstance(status, str) else status
        return self.storage.list_iocs(ioc_type=type_enum, status=status_enum, limit=limit)

    def search(self, query: str, limit: int = 50) -> list[IOCRecord]:
        """Search IOC records by value, tag, or notes substring."""
        return self.storage.search_iocs(query=query, limit=limit)

    def match_event(self, event: SecurityEvent) -> list[IOCRecord]:
        """
        Correlate a SecurityEvent against active IOCs.

        Checks event source_ip against IP IOCs and event username against USERNAME IOCs.
        """
        matches: list[IOCRecord] = []

        # Match IP
        if event.source_ip:
            ip_iocs = self.storage.lookup_active_iocs(IOCType.IP, event.source_ip)
            matches.extend(ip_iocs)

        # Match Username
        if event.username:
            user_iocs = self.storage.lookup_active_iocs(IOCType.USERNAME, event.username)
            matches.extend(user_iocs)

        return matches
