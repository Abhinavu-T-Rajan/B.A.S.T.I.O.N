from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Protocol, runtime_checkable

from bastion.core.models.detections import DetectionResult, DetectorType
from bastion.models.events import SecurityEvent


@runtime_checkable
class DetectorProvider(Protocol):
    """Protocol for behavioral threat detector providers."""

    name: str
    description: str
    enabled: bool

    def evaluate(self, event: SecurityEvent) -> DetectionResult | None:
        """Evaluate an incoming security event and return a DetectionResult if triggered."""
        ...

    def reset(self) -> None:
        """Reset internal state, sliding windows, or counters."""
        ...


class Detector(ABC):
    """Abstract base class for stateful or heuristic behavioral threat detectors."""

    def __init__(self, *, name: str, description: str, enabled: bool = True) -> None:
        self.name = name
        self.description = description
        self.enabled = enabled

    @abstractmethod
    def evaluate(self, event: SecurityEvent) -> DetectionResult | None:
        """Process a normalized SecurityEvent and return DetectionResult if threshold met."""
        ...

    def reset(self) -> None:
        """Reset state or clear sliding tracking windows."""
        ...
