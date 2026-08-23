from __future__ import annotations

import sys
from collections.abc import Iterable, Iterator
from datetime import datetime, timezone

from bastion.core.contracts.collector import CollectorProvider
from bastion.core.models.telemetry import RawTelemetry


class StdinCollector(CollectorProvider):
    """Streams lines from standard input into RawTelemetry records."""

    def __init__(self, stream_source: Iterable[str] | None = None) -> None:
        self.name = "stdin"
        self._stream_source = stream_source
        self._stopped = False

    def is_available(self) -> bool:
        return True

    def stream(self) -> Iterator[RawTelemetry]:
        source = self._stream_source if self._stream_source is not None else sys.stdin
        for raw_line in source:
            if self._stopped:
                break
            cleaned = raw_line.strip() if isinstance(raw_line, str) else str(raw_line).strip()
            if cleaned:
                yield RawTelemetry(
                    raw_message=cleaned,
                    source="stdin",
                    timestamp=datetime.now(timezone.utc),
                    transport="pipe",
                )

    def read(self, limit: int = 50) -> Iterator[RawTelemetry]:
        count = 0
        for item in self.stream():
            yield item
            count += 1
            if count >= limit:
                break

    def stop(self) -> None:
        self._stopped = True
