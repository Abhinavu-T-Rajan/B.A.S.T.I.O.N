from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timedelta

from bastion.detection.brute_force import DetectionResult
from bastion.models.events import EventType, SecurityEvent


class BurstDetector:
    """Detects sudden high-velocity authentication bursts in short time windows."""

    def __init__(
        self,
        *,
        threshold: int = 5,
        window_seconds: int = 5,
    ) -> None:
        if threshold <= 0:
            raise ValueError("threshold must be greater than zero")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be greater than zero")

        self.threshold = threshold
        self.window = timedelta(seconds=window_seconds)
        self._history: dict[str, deque[datetime]] = defaultdict(deque)

    def evaluate(self, event: SecurityEvent) -> DetectionResult:
        """Evaluate event for high-frequency burst patterns."""
        if event.event_type not in {EventType.AUTH_FAILURE, EventType.INVALID_USER}:
            active_count = self._count_active(event.source_ip, event.timestamp)
            return DetectionResult(
                detected=False,
                source_ip=event.source_ip,
                event_count=active_count,
                threshold=self.threshold,
                window_seconds=int(self.window.total_seconds()),
                detector_name="burst_velocity",
            )

        timestamps = self._history[event.source_ip]
        timestamps.append(event.timestamp)
        self._expire_old(timestamps, event.timestamp)

        count = len(timestamps)
        detected = count >= self.threshold

        return DetectionResult(
            detected=detected,
            source_ip=event.source_ip,
            event_count=count,
            threshold=self.threshold,
            window_seconds=int(self.window.total_seconds()),
            reason=f"attack burst velocity detected ({count} attempts in {int(self.window.total_seconds())}s)"
            if detected
            else None,
            detector_name="burst_velocity",
        )

    def _count_active(self, source_ip: str, current_time: datetime) -> int:
        timestamps = self._history[source_ip]
        self._expire_old(timestamps, current_time)
        return len(timestamps)

    def _expire_old(self, timestamps: deque[datetime], current_time: datetime) -> None:
        cutoff = current_time - self.window
        while timestamps and timestamps[0] < cutoff:
            timestamps.popleft()
