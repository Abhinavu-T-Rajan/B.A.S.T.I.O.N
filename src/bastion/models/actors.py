from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    """Threat severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_score(cls, score: int) -> Severity:
        """Derive severity classification from a 0-100 threat score."""
        if score >= 85:
            return cls.CRITICAL
        if score >= 70:
            return cls.HIGH
        if score >= 40:
            return cls.MEDIUM
        return cls.LOW


class ActorState(StrEnum):
    """Operational lifecycle state of a threat actor."""

    TRUSTED = "trusted"
    NEUTRAL = "neutral"
    PROBING = "probing"
    SUSPICIOUS = "suspicious"
    ACTIVE_THREAT = "active_threat"
    ISOLATED = "isolated"
    EXPIRED = "expired"
    RELEASED = "released"


class RecommendedAction(StrEnum):
    """Defensive advisory action recommended by the risk engine."""

    NONE = "none"
    MONITOR = "monitor"
    RATE_LIMIT = "rate_limit"
    TEMPORARY_ISOLATION = "temporary_isolation"
    PERMANENT_BAN = "permanent_ban"


@dataclass(frozen=True, slots=True)
class ScoreFactor:
    """An explainable contributing factor to a threat score."""

    name: str
    score_delta: int
    description: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "score_delta": self.score_delta,
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScoreFactor:
        return cls(
            name=data["name"],
            score_delta=int(data["score_delta"]),
            description=data["description"],
        )


@dataclass(slots=True)
class ThreatActorProfile:
    """Comprehensive behavioral and forensic profile of an IP address."""

    source_ip: str
    first_seen: datetime
    last_seen: datetime
    total_events: int = 0
    auth_failures: int = 0
    auth_successes: int = 0
    usernames_targeted: set[str] = field(default_factory=set)
    services_targeted: set[str] = field(default_factory=set)
    threat_score: int = 0
    severity: Severity = Severity.LOW
    state: ActorState = ActorState.NEUTRAL
    factors: list[ScoreFactor] = field(default_factory=list)
    recommended_action: RecommendedAction = RecommendedAction.NONE

    def __post_init__(self) -> None:
        if self.first_seen.tzinfo is None:
            self.first_seen = self.first_seen.replace(tzinfo=timezone.utc)
        if self.last_seen.tzinfo is None:
            self.last_seen = self.last_seen.replace(tzinfo=timezone.utc)
        self.threat_score = max(0, min(100, self.threat_score))
        if self.severity == Severity.LOW and self.threat_score > 0:
            self.severity = Severity.from_score(self.threat_score)

    def to_dict(self) -> dict[str, Any]:
        """Serialize profile to a JSON-compatible dictionary."""
        return {
            "source_ip": self.source_ip,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "total_events": self.total_events,
            "auth_failures": self.auth_failures,
            "auth_successes": self.auth_successes,
            "usernames_targeted": sorted(self.usernames_targeted),
            "services_targeted": sorted(self.services_targeted),
            "threat_score": self.threat_score,
            "severity": self.severity.value,
            "state": self.state.value,
            "factors": [f.to_dict() for f in self.factors],
            "recommended_action": self.recommended_action.value,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ThreatActorProfile:
        """Deserialize profile from a dictionary."""
        first_seen = datetime.fromisoformat(data["first_seen"])
        last_seen = datetime.fromisoformat(data["last_seen"])
        if first_seen.tzinfo is None:
            first_seen = first_seen.replace(tzinfo=timezone.utc)
        if last_seen.tzinfo is None:
            last_seen = last_seen.replace(tzinfo=timezone.utc)

        factors = [ScoreFactor.from_dict(f) for f in data.get("factors", [])]

        return cls(
            source_ip=data["source_ip"],
            first_seen=first_seen,
            last_seen=last_seen,
            total_events=int(data.get("total_events", 0)),
            auth_failures=int(data.get("auth_failures", 0)),
            auth_successes=int(data.get("auth_successes", 0)),
            usernames_targeted=set(data.get("usernames_targeted", [])),
            services_targeted=set(data.get("services_targeted", [])),
            threat_score=int(data.get("threat_score", 0)),
            severity=Severity(data.get("severity", Severity.LOW.value)),
            state=ActorState(data.get("state", ActorState.NEUTRAL.value)),
            factors=factors,
            recommended_action=RecommendedAction(
                data.get("recommended_action", RecommendedAction.NONE.value)
            ),
        )
