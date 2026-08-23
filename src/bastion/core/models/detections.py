from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class DetectorType(str, Enum):
    """Enumeration of standard behavioral detector identifiers."""

    BRUTE_FORCE = "brute_force"
    PASSWORD_SPRAY = "password_spray"
    USERNAME_ENUMERATION = "username_enumeration"
    BURST_VELOCITY = "burst_velocity"
    CUSTOM = "custom"


@dataclass(frozen=True, slots=True)
class DetectionResult:
    """Result of evaluating a security event against a behavioral threat detector."""

    detected: bool
    source_ip: str
    event_count: int
    threshold: int
    window_seconds: int
    reason: str | None = None
    detector_name: str = "brute_force"
    metadata: dict[str, Any] = field(default_factory=dict)
