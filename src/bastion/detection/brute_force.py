from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Any

from bastion.core.contracts.detector import Detector
from bastion.detection.base import DetectionResult
from bastion.models.events import EventType, SecurityEvent


class BruteForceDetector(Detector):
    """Detect repeated authentication failures from a source IP within a sliding window."""

    def __init__(
        self,
        *,
        threshold: int = 10,
        window_seconds: int = 60,
        name: str = "brute_force",
        description: str = "Detect repeated authentication failures from a source IP",
        enabled: bool = True,
    ) -> None:
        super().__init__(name=name, description=description, enabled=enabled)
        if threshold <= 0:
            raise ValueError("threshold must be greater than zero")

        if window_seconds <= 0:
            raise ValueError("window_seconds must be greater than zero")

        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)
        self._failures: dict[str, deque[datetime]] = defaultdict(deque)

    def evaluate(self, event: SecurityEvent) -> DetectionResult:
        """Evaluate one security event."""
        if not self.enabled:
            return DetectionResult(
                detected=False,
                source_ip=event.source_ip,
                event_count=0,
                threshold=self.threshold,
                window_seconds=int(self.window.total_seconds()),
                detector_name=self.name,
            )

        if event.event_type not in {
            EventType.AUTH_FAILURE,
            EventType.INVALID_USER,
        }:
            return DetectionResult(
                detected=False,
                source_ip=event.source_ip,
                event_count=self._count_active(event.source_ip, event.timestamp),
                threshold=self.threshold,
                window_seconds=int(self.window.total_seconds()),
                detector_name=self.name,
            )

        timestamps = self._failures[event.source_ip]
        timestamps.append(event.timestamp)

        self._expire_old_events(
            timestamps=timestamps,
            current_time=event.timestamp,
        )

        count = len(timestamps)

        if count >= self.threshold:
            return DetectionResult(
                detected=True,
                source_ip=event.source_ip,
                event_count=count,
                threshold=self.threshold,
                window_seconds=int(self.window.total_seconds()),
                reason="repeated authentication failures",
                detector_name=self.name,
            )

        return DetectionResult(
            detected=False,
            source_ip=event.source_ip,
            event_count=count,
            threshold=self.threshold,
            window_seconds=int(self.window.total_seconds()),
            detector_name=self.name,
        )

    def reset(self) -> None:
        """Reset internal failures map."""
        self._failures.clear()

    def _count_active(
        self,
        source_ip: str,
        current_time: datetime,
    ) -> int:
        """Return active failure count for a source."""
        timestamps = self._failures[source_ip]

        self._expire_old_events(
            timestamps=timestamps,
            current_time=current_time,
        )

        return len(timestamps)

    def _expire_old_events(
        self,
        *,
        timestamps: deque[datetime],
        current_time: datetime,
    ) -> None:
        """Remove timestamps outside the detection window."""
        cutoff = current_time - self.window

        while timestamps and timestamps[0] < cutoff:
            timestamps.popleft()