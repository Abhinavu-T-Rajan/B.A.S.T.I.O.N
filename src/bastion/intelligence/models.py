from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any


class IOCType(StrEnum):
    """Supported Indicator of Compromise (IOC) types."""

    IP = "ip"
    DOMAIN = "domain"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    USERNAME = "username"


class IOCStatus(StrEnum):
    """Lifecycle status for IOC records."""

    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


class Provenance(StrEnum):
    """Data origin and trustworthiness classification."""

    OBSERVED = "observed"
    INFERRED = "inferred"
    CONFIGURED = "configured"
    CONFIRMED = "confirmed"
    UNKNOWN = "unknown"


@dataclass
class IOCRecord:
    """Indicator of Compromise (IOC) record."""

    ioc_type: IOCType
    value: str
    ioc_id: str = field(default_factory=lambda: f"ioc-{uuid.uuid4().hex[:12]}")
    confidence: int = 50  # 0 to 100
    source: str = "local"
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    status: IOCStatus = IOCStatus.ACTIVE
    provenance: Provenance = Provenance.OBSERVED
    tags: list[str] = field(default_factory=list)
    notes: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if isinstance(self.ioc_type, str) and not isinstance(self.ioc_type, IOCType):
            self.ioc_type = IOCType(self.ioc_type.lower())
        if isinstance(self.status, str) and not isinstance(self.status, IOCStatus):
            self.status = IOCStatus(self.status.lower())
        if isinstance(self.provenance, str) and not isinstance(self.provenance, Provenance):
            self.provenance = Provenance(self.provenance.lower())
        self.confidence = max(0, min(100, int(self.confidence)))

    def to_dict(self) -> dict[str, Any]:
        """Convert IOC record to dictionary."""
        return {
            "ioc_id": self.ioc_id,
            "ioc_type": self.ioc_type.value,
            "value": self.value,
            "confidence": self.confidence,
            "source": self.source,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "status": self.status.value,
            "provenance": self.provenance.value,
            "tags": self.tags,
            "notes": self.notes,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> IOCRecord:
        """Construct IOC record from dictionary or database row mapping."""
        first_seen = data.get("first_seen")
        if isinstance(first_seen, str):
            first_seen_dt = datetime.fromisoformat(first_seen.replace("Z", "+00:00"))
        else:
            first_seen_dt = first_seen or datetime.now(timezone.utc)

        last_seen = data.get("last_seen")
        if isinstance(last_seen, str):
            last_seen_dt = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
        else:
            last_seen_dt = last_seen or datetime.now(timezone.utc)

        tags = data.get("tags", [])
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",") if t.strip()]

        metadata = data.get("metadata", {})
        if isinstance(metadata, str):
            try:
                metadata = json.loads(metadata)
            except Exception:
                metadata = {}

        return cls(
            ioc_id=data.get("ioc_id", f"ioc-{uuid.uuid4().hex[:12]}"),
            ioc_type=IOCType(data["ioc_type"].lower()),
            value=data["value"].strip(),
            confidence=int(data.get("confidence", 50)),
            source=data.get("source", "local"),
            first_seen=first_seen_dt,
            last_seen=last_seen_dt,
            status=IOCStatus(data.get("status", "active").lower()),
            provenance=Provenance(data.get("provenance", "observed").lower()),
            tags=tags,
            notes=data.get("notes", ""),
            metadata=metadata,
        )


# Domain alias
Indicator = IOCRecord
