from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional


@dataclass
class ResponseAuditRecord:
    """Audit log record for any executed or simulated defensive response action."""

    action: str
    target: str
    executed_by: str
    dry_run: bool
    success: bool
    audit_id: str = field(default_factory=lambda: f"aud-{uuid.uuid4().hex[:12]}")
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    actor_id: Optional[str] = None
    incident_id: Optional[str] = None
    details: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.timestamp.tzinfo is None:
            self.timestamp = self.timestamp.replace(tzinfo=timezone.utc)

    def to_dict(self) -> dict[str, Any]:
        """Convert audit record to dictionary."""
        return {
            "audit_id": self.audit_id,
            "timestamp": self.timestamp.isoformat(),
            "action": self.action,
            "target": self.target,
            "actor_id": self.actor_id,
            "incident_id": self.incident_id,
            "executed_by": self.executed_by,
            "dry_run": self.dry_run,
            "success": self.success,
            "details": self.details,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ResponseAuditRecord:
        """Construct audit record from dictionary."""
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
            audit_id=data.get("audit_id", f"aud-{uuid.uuid4().hex[:12]}"),
            timestamp=ts_dt,
            action=data["action"],
            target=data["target"],
            actor_id=data.get("actor_id"),
            incident_id=data.get("incident_id"),
            executed_by=data["executed_by"],
            dry_run=bool(data["dry_run"]),
            success=bool(data["success"]),
            details=details,
        )


@dataclass
class ResponseResult:
    """Structured outcome of an experimental response invocation."""

    success: bool
    action: str
    target: str
    dry_run: bool
    message: str
    audit_id: str
    details: dict[str, Any] = field(default_factory=dict)
