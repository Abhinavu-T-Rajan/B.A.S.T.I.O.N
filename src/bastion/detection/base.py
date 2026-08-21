from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class DetectionResult:
    """Result of evaluating a security event against a behavioral detector."""

    detected: bool
    source_ip: str
    event_count: int
    threshold: int
    window_seconds: int
    reason: str | None = None
    detector_name: str = "brute_force"
    metadata: dict[str, Any] = field(default_factory=dict)
