from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from typing import Protocol, runtime_checkable

from bastion.core.models.telemetry import RawTelemetry
from bastion.models.events import SecurityEvent


@runtime_checkable
class CollectorProvider(Protocol):
    """Abstract protocol for raw telemetry ingestion providers (journald, stdin, file)."""

    name: str

    def is_available(self) -> bool:
        """Check if provider dependencies and binaries are available."""
        ...

    def stream(self) -> Iterator[RawTelemetry]:
        """Continuously stream raw telemetry records in real-time."""
        ...

    def read(self, limit: int = 50) -> Iterator[RawTelemetry]:
        """Read a bounded batch of recent raw telemetry records."""
        ...

    def stop(self) -> None:
        """Cleanly terminate background collector workers or subprocesses."""
        ...


@runtime_checkable
class TelemetryAdapter(Protocol):
    """Protocol for specialized source normalizers (e.g. OpenSSH, Web Server)."""

    name: str

    def can_handle(self, telemetry: RawTelemetry) -> bool:
        """Return True if this adapter can normalize the given telemetry record."""
        ...

    def normalize(self, telemetry: RawTelemetry) -> SecurityEvent | None:
        """Parse raw telemetry record into a standardized domain SecurityEvent."""
        ...


class EventNormalizer(ABC):
    """Abstract pipeline gateway for converting raw telemetry into domain events."""

    @abstractmethod
    def register_adapter(self, adapter: TelemetryAdapter) -> None:
        """Register a source-specific telemetry adapter."""
        ...

    @abstractmethod
    def normalize(self, telemetry: RawTelemetry) -> SecurityEvent | None:
        """Route raw telemetry through registered adapters to produce a SecurityEvent."""
        ...
