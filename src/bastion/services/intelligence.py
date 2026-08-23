from __future__ import annotations

from typing import Any

from bastion.attack.registry import AttackRegistry
from bastion.core.contracts.storage import StorageProvider
from bastion.intelligence.manager import IOCManager
from bastion.intelligence.models import IOCRecord, IOCType
from bastion.intelligence.validator import IOCValidator
from bastion.models.actors import Severity


class IntelligenceAppService:
    """Application service for threat intelligence, IOC operations, and MITRE ATT&CK mappings."""

    def __init__(self, storage: StorageProvider) -> None:
        self.storage = storage
        self.ioc_manager = IOCManager(storage=self.storage)
        self.attack_registry = AttackRegistry.load_default()

    def add_ioc(
        self,
        ioc_type: str,
        value: str,
        description: str = "",
        confidence: int = 80,
        severity: str = "medium",
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> tuple[bool, str, IOCRecord | None]:
        """Validate and add a threat indicator."""
        t_str = ioc_type.lower().strip()
        try:
            if t_str in {"ip", "ipv4", "ipv6"}:
                type_enum = IOCType.IP
            else:
                type_enum = IOCType(t_str)
        except ValueError as exc:
            return False, f"Invalid IOC type: {exc}", None

        valid, err = IOCValidator.validate(type_enum, value)
        if not valid:
            return False, f"Validation failed: {err}", None

        try:
            record = self.ioc_manager.add_ioc(
                ioc_type=type_enum,
                value=value.strip(),
                confidence=confidence,
                notes=description,
                tags=tags or [],
                metadata=metadata or {},
            )
            return True, f"Successfully registered IOC '{value}' [{type_enum.value}]", record
        except Exception as exc:
            return False, f"Failed to add IOC: {exc}", None

    def list_iocs(self, active_only: bool = True, limit: int = 100) -> list[IOCRecord]:
        """List threat indicators."""
        status = "active" if active_only else None
        return self.ioc_manager.list_iocs(status=status, limit=limit)

    def search_iocs(self, query: str) -> list[IOCRecord]:
        """Search threat indicators by substring value or description."""
        return self.ioc_manager.search_iocs(query=query)

    def delete_ioc(self, identifier_or_value: str) -> tuple[bool, str]:
        """Delete an indicator by ID or value."""
        if self.storage.delete_ioc(identifier_or_value):
            return True, f"Deleted IOC '{identifier_or_value}'"
        iocs = self.storage.search_iocs(identifier_or_value)
        for ioc in iocs:
            if ioc.value == identifier_or_value:
                if self.storage.delete_ioc(ioc.ioc_id):
                    return True, f"Deleted IOC '{identifier_or_value}'"
        return False, f"IOC '{identifier_or_value}' not found"

    def get_attack_catalog(self) -> list[dict[str, Any]]:
        """Return full catalog of mapped MITRE ATT&CK techniques."""
        return [
            {
                "technique_id": t.technique_id,
                "name": t.name,
                "tactic": t.tactic.value if hasattr(t.tactic, "value") else str(t.tactic),
                "description": t.description,
                "url": t.url,
            }
            for t in self.attack_registry.list_techniques()
        ]

    def inspect_technique(self, technique_id: str) -> dict[str, Any] | None:
        """Inspect a specific MITRE ATT&CK technique by ID."""
        tech = self.attack_registry.get_technique(technique_id)
        if tech is None:
            return None
        return {
            "technique_id": tech.technique_id,
            "name": tech.name,
            "tactic": tech.tactic.value if hasattr(tech.tactic, "value") else str(tech.tactic),
            "description": tech.description,
            "url": tech.url,
            "mitre_url": tech.url,
        }
