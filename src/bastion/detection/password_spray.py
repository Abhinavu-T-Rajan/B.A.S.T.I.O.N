from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timedelta

from bastion.core.contracts.detector import Detector
from bastion.detection.base import DetectionResult
from bastion.models.events import EventType, SecurityEvent


class PasswordSprayDetector(Detector):
    """Detects password spraying: single IP targeting multiple distinct accounts with low attempt counts."""

    def __init__(
        self,
        *,
        min_usernames: int = 3,
        max_attempts_per_user: int = 3,
        window_seconds: int = 120,
        name: str = "password_spray",
        description: str = "Detect horizontal password spraying across multiple usernames",
        enabled: bool = True,
    ) -> None:
        super().__init__(name=name, description=description, enabled=enabled)
        if min_usernames <= 1:
            raise ValueError("min_usernames must be greater than 1")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be greater than zero")

        self.min_usernames = min_usernames
        self.max_attempts_per_user = max_attempts_per_user
        self.window = timedelta(seconds=window_seconds)
        self._history: dict[str, deque[tuple[datetime, str]]] = defaultdict(deque)

    def evaluate(self, event: SecurityEvent) -> DetectionResult:
        """Evaluate event for password spraying behavior."""
        if not self.enabled:
            return DetectionResult(
                detected=False,
                source_ip=event.source_ip,
                event_count=0,
                threshold=self.min_usernames,
                window_seconds=int(self.window.total_seconds()),
                detector_name=self.name,
            )

        if event.event_type not in {EventType.AUTH_FAILURE, EventType.INVALID_USER} or not event.username:
            active_users = self._get_active_users(event.source_ip, event.timestamp)
            return DetectionResult(
                detected=False,
                source_ip=event.source_ip,
                event_count=len(active_users),
                threshold=self.min_usernames,
                window_seconds=int(self.window.total_seconds()),
                detector_name=self.name,
            )

        events_deque = self._history[event.source_ip]
        events_deque.append((event.timestamp, event.username))
        self._expire_old_events(events_deque, event.timestamp)

        # Count distinct usernames and max attempts per user
        user_counts: dict[str, int] = defaultdict(int)
        for _, u in events_deque:
            user_counts[u] += 1

        distinct_users = len(user_counts)
        max_attempts = max(user_counts.values()) if user_counts else 0

        is_spray = (distinct_users >= self.min_usernames) and (max_attempts <= self.max_attempts_per_user)

        return DetectionResult(
            detected=is_spray,
            source_ip=event.source_ip,
            event_count=distinct_users,
            threshold=self.min_usernames,
            window_seconds=int(self.window.total_seconds()),
            reason=f"targeted {distinct_users} distinct accounts within window" if is_spray else None,
            detector_name=self.name,
            metadata={"distinct_users": list(user_counts.keys()), "attempts_per_user": dict(user_counts)},
        )

    def reset(self) -> None:
        """Reset internal history map."""
        self._history.clear()

    def _get_active_users(self, source_ip: str, current_time: datetime) -> set[str]:
        events_deque = self._history[source_ip]
        self._expire_old_events(events_deque, current_time)
        return {u for _, u in events_deque}

    def _expire_old_events(self, events_deque: deque[tuple[datetime, str]], current_time: datetime) -> None:
        cutoff = current_time - self.window
        while events_deque and events_deque[0][0] < cutoff:
            events_deque.popleft()
