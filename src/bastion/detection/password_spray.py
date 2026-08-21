from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timedelta

from bastion.detection.brute_force import DetectionResult
from bastion.models.events import EventType, SecurityEvent


class PasswordSprayDetector:
    """Detects password spraying: single IP targeting multiple distinct accounts with low attempt counts."""

    def __init__(
        self,
        *,
        min_usernames: int = 3,
        max_attempts_per_user: int = 3,
        window_seconds: int = 120,
    ) -> None:
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
        if event.event_type not in {EventType.AUTH_FAILURE, EventType.INVALID_USER} or not event.username:
            active_users = self._get_active_users(event.source_ip, event.timestamp)
            return DetectionResult(
                detected=False,
                source_ip=event.source_ip,
                event_count=len(active_users),
                threshold=self.min_usernames,
                window_seconds=int(self.window.total_seconds()),
                detector_name="password_spray",
            )

        entries = self._history[event.source_ip]
        entries.append((event.timestamp, event.username))
        self._expire_old(entries, event.timestamp)

        user_counts: dict[str, int] = defaultdict(int)
        for _, u in entries:
            user_counts[u] += 1

        unique_count = len(user_counts)
        total_attempts = len(entries)
        avg_attempts = total_attempts / unique_count if unique_count else 0

        is_spray = (
            unique_count >= self.min_usernames
            and avg_attempts <= self.max_attempts_per_user
        )

        return DetectionResult(
            detected=is_spray,
            source_ip=event.source_ip,
            event_count=unique_count,
            threshold=self.min_usernames,
            window_seconds=int(self.window.total_seconds()),
            reason=f"password spraying across {unique_count} distinct usernames" if is_spray else None,
            detector_name="password_spray",
            metadata={
                "unique_usernames": sorted(user_counts.keys()),
                "total_attempts": total_attempts,
            },
        )

    def _get_active_users(self, source_ip: str, current_time: datetime) -> set[str]:
        entries = self._history[source_ip]
        self._expire_old(entries, current_time)
        return {u for _, u in entries}

    def _expire_old(
        self, entries: deque[tuple[datetime, str]], current_time: datetime
    ) -> None:
        cutoff = current_time - self.window
        while entries and entries[0][0] < cutoff:
            entries.popleft()
