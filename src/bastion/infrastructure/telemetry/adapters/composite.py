from __future__ import annotations

from collections.abc import Sequence

from bastion.core.contracts.collector import EventNormalizer, TelemetryAdapter
from bastion.core.models.telemetry import RawTelemetry
from bastion.infrastructure.telemetry.adapters.ssh import SSHLogAdapter
from bastion.models.events import SecurityEvent


class CompositeEventNormalizer(EventNormalizer):
    """Orchestrates telemetry adapters to normalize RawTelemetry records into SecurityEvents."""

    def __init__(self, adapters: Sequence[TelemetryAdapter] | None = None) -> None:
        if adapters is not None:
            self._adapters: list[TelemetryAdapter] = list(adapters)
        else:
            self._adapters = [SSHLogAdapter()]

    @property
    def adapters(self) -> list[TelemetryAdapter]:
        return list(self._adapters)

    def register_adapter(self, adapter: TelemetryAdapter) -> None:
        """Register a source-specific telemetry adapter."""
        self._adapters.append(adapter)

    def normalize(self, telemetry: RawTelemetry | str) -> SecurityEvent | None:
        """Route raw telemetry record through adapters and return normalized SecurityEvent."""
        if isinstance(telemetry, str):
            telemetry = RawTelemetry(raw_message=telemetry, source="string_input")

        for adapter in self._adapters:
            if adapter.can_handle(telemetry):
                event = adapter.normalize(telemetry)
                if event is not None:
                    return event
        return None
