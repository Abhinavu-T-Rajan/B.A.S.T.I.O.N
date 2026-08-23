from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any


class ResponseMode(StrEnum):
    """Execution mode for the response engine."""

    DRY_RUN = "dry_run"
    MANUAL_APPROVAL = "manual"
    AUTOMATIC = "automatic"
    DISABLED = "disabled"


class ResponseAction(StrEnum):
    """Enforceable defensive actions."""

    NONE = "none"
    MONITOR = "monitor"
    RATE_LIMIT = "rate_limit"
    TEMPORARY_ISOLATION = "temporary_isolation"
    PERMANENT_BAN = "permanent_ban"


class BanStatus(StrEnum):
    """Lifecycle status of a ban record."""

    ACTIVE = "active"
    EXPIRED = "expired"
    UNBANNED = "unbanned"
    PENDING_APPROVAL = "pending_approval"
    DRY_RUN = "dry_run"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class ResponseDecision:
    """A policy evaluation decision determining what response action to take."""

    source_ip: str
    action: ResponseAction
    threat_score: int
    reason: str
    duration_seconds: int | None = None
    is_allowlisted: bool = False
    mode: ResponseMode = ResponseMode.DRY_RUN
    executed: bool = False
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class BanRecord:
    """A persistent record representing an active, expired, or simulated ban."""

    ban_id: str
    source_ip: str
    reason: str
    threat_score: int
    created_at: datetime
    expires_at: datetime | None = None
    action: ResponseAction = ResponseAction.TEMPORARY_ISOLATION
    status: BanStatus = BanStatus.ACTIVE
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.created_at.tzinfo is None:
            self.created_at = self.created_at.replace(tzinfo=timezone.utc)
        if self.expires_at is not None and self.expires_at.tzinfo is None:
            self.expires_at = self.expires_at.replace(tzinfo=timezone.utc)

    @property
    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) >= self.expires_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "ban_id": self.ban_id,
            "source_ip": self.source_ip,
            "reason": self.reason,
            "threat_score": self.threat_score,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "action": self.action.value,
            "status": self.status.value,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BanRecord:
        created_at = datetime.fromisoformat(data["created_at"])
        expires_at = (
            datetime.fromisoformat(data["expires_at"])
            if data.get("expires_at")
            else None
        )
        return cls(
            ban_id=data["ban_id"],
            source_ip=data["source_ip"],
            reason=data["reason"],
            threat_score=int(data.get("threat_score", 0)),
            created_at=created_at,
            expires_at=expires_at,
            action=ResponseAction(data.get("action", ResponseAction.TEMPORARY_ISOLATION.value)),
            status=BanStatus(data.get("status", BanStatus.ACTIVE.value)),
            metadata=data.get("metadata", {}),
        )
