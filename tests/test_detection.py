"""Tests for B.A.S.T.I.O.N. detection logic."""

from datetime import datetime, timedelta, timezone

from bastion.detection.brute_force import BruteForceDetector
from bastion.models.events import EventType, SecurityEvent, ServiceType


def make_event(
    *,
    source_ip: str = "192.0.2.10",
    seconds: int = 0,
    event_type: EventType = EventType.AUTH_FAILURE,
) -> SecurityEvent:
    """Create a deterministic test event."""
    timestamp = datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(
        seconds=seconds,
    )

    return SecurityEvent(
        timestamp=timestamp,
        source_ip=source_ip,
        service=ServiceType.SSH,
        event_type=event_type,
    )


def test_brute_force_detects_after_threshold() -> None:
    """Ten failures inside the window should trigger detection."""
    detector = BruteForceDetector(
        threshold=10,
        window_seconds=60,
    )

    result = None

    for _ in range(10):
        result = detector.evaluate(make_event())

    assert result is not None
    assert result.detected is True
    assert result.event_count == 10


def test_brute_force_does_not_detect_below_threshold() -> None:
    """Events below the threshold should not trigger detection."""
    detector = BruteForceDetector(
        threshold=10,
        window_seconds=60,
    )

    for _ in range(9):
        result = detector.evaluate(make_event())

    assert result.detected is False
    assert result.event_count == 9


def test_old_events_expire() -> None:
    """Failures outside the sliding window should expire."""
    detector = BruteForceDetector(
        threshold=3,
        window_seconds=60,
    )

    detector.evaluate(make_event(seconds=0))
    detector.evaluate(make_event(seconds=1))

    result = detector.evaluate(make_event(seconds=62))

    assert result.detected is False
    assert result.event_count == 1


def test_success_event_does_not_increase_failure_count() -> None:
    """Successful authentication must not increase the failure counter."""
    detector = BruteForceDetector(
        threshold=3,
        window_seconds=60,
    )

    detector.evaluate(make_event(seconds=0))
    detector.evaluate(
        make_event(
            seconds=1,
            event_type=EventType.AUTH_SUCCESS,
        )
    )

    result = detector.evaluate(make_event(seconds=2))

    assert result.detected is False
    assert result.event_count == 2