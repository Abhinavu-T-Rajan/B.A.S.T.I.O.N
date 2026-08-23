from __future__ import annotations

import os
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path

from bastion.core.contracts.collector import CollectorProvider
from bastion.core.models.telemetry import RawTelemetry


class FileCollector(CollectorProvider):
    """Streams lines from a log file into RawTelemetry records."""

    def __init__(self, file_path: str | Path) -> None:
        self.name = "file"
        self.file_path = Path(os.path.expanduser(str(file_path))).resolve()
        self._stopped = False

    def is_available(self) -> bool:
        return self.file_path.exists() and os.access(self.file_path, os.R_OK)

    def stream(self) -> Iterator[RawTelemetry]:
        if not self.is_available():
            return

        with open(self.file_path, "r", encoding="utf-8", errors="replace") as f:
            for raw_line in f:
                if self._stopped:
                    break
                cleaned = raw_line.strip()
                if cleaned:
                    yield RawTelemetry(
                        raw_message=cleaned,
                        source="file",
                        timestamp=datetime.now(timezone.utc),
                        transport="file_io",
                        metadata={"file_path": str(self.file_path)},
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
