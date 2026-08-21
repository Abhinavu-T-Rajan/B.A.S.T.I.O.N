"""Unit tests for B.A.S.T.I.O.N. behavioral detectors."""

from datetime import datetime, timedelta, timezone

from bastion.detection.brute_force import BruteForceDetector
from bastion.detection.burst import BurstDetector
from bastion.detection.engine import DetectionEngine
from bastion.detection.enumeration import UsernameEnumerationDetector
from bastion.detection.password_spray import PasswordSprayDetector
from bastion.models.events import EventType, SecurityEvent, ServiceType


def make_event(
    *,
    source_ip: str = "192.0.2.100",
    username: str = "root",
    seconds_offset: int = 0,
    event_type: EventType = EventType.AUTH_FAILURE,
    invalid_user: bool = False,
) -> SecurityEvent:
    base_ts = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    return SecurityEvent(
        timestamp=base_ts + timedelta(seconds=seconds_offset),
        source_ip=source_ip,
        service=ServiceType.SSH,
        event_type=event_type,
        username=username,
        metadata={"invalid_user": invalid_user},
    )


def test_password_spray_detector() -> None:
    detector = PasswordSprayDetector(
        min_usernames=3,
        max_attempts_per_user=2,
        window_seconds=60,
    )

    # 1st attempt: admin
    res1 = detector.evaluate(make_event(username="admin", seconds_offset=0))
    assert res1.detected is False

    # 2nd attempt: test
    res2 = detector.evaluate(make_event(username="test", seconds_offset=2))
    assert res2.detected is False

    # 3rd attempt: deploy -> 3 distinct usernames!
    res3 = detector.evaluate(make_event(username="deploy", seconds_offset=4))
    assert res3.detected is True
    assert res3.detector_name == "password_spray"
    assert res3.event_count == 3


def test_password_spray_ignores_single_user_brute_force() -> None:
    detector = PasswordSprayDetector(
        min_usernames=3,
        max_attempts_per_user=2,
        window_seconds=60,
    )

    # 10 attempts on root only
    for i in range(10):
        res = detector.evaluate(make_event(username="root", seconds_offset=i))

    assert res.detected is False
    assert res.event_count == 1


def test_username_enumeration_detector() -> None:
    detector = UsernameEnumerationDetector(
        threshold=3,
        window_seconds=60,
    )

    detector.evaluate(make_event(username="invalid1", invalid_user=True, seconds_offset=0))
    detector.evaluate(make_event(username="invalid2", invalid_user=True, seconds_offset=1))
    res = detector.evaluate(make_event(username="invalid3", invalid_user=True, seconds_offset=2))

    assert res.detected is True
    assert res.detector_name == "username_enumeration"
    assert res.event_count == 3


def test_username_enumeration_ignores_valid_users() -> None:
    detector = UsernameEnumerationDetector(threshold=3, window_seconds=60)

    for i in range(5):
        res = detector.evaluate(make_event(username="valid_user", invalid_user=False, seconds_offset=i))

    assert res.detected is False
    assert res.event_count == 0


def test_burst_detector() -> None:
    detector = BurstDetector(threshold=5, window_seconds=5)

    for i in range(4):
        res = detector.evaluate(make_event(seconds_offset=i))
        assert res.detected is False

    # 5th attempt in 4 seconds -> burst triggered
    res5 = detector.evaluate(make_event(seconds_offset=4))
    assert res5.detected is True
    assert res5.detector_name == "burst_velocity"
    assert res5.event_count == 5


def test_burst_detector_expires_spaced_events() -> None:
    detector = BurstDetector(threshold=5, window_seconds=5)

    # Attempts spaced 2 seconds apart
    detector.evaluate(make_event(seconds_offset=0))
    detector.evaluate(make_event(seconds_offset=2))
    detector.evaluate(make_event(seconds_offset=4))
    detector.evaluate(make_event(seconds_offset=6))
    detector.evaluate(make_event(seconds_offset=8))
    res = detector.evaluate(make_event(seconds_offset=10))

    assert res.detected is False


def test_detection_engine_aggregates_all() -> None:
    engine = DetectionEngine()
    event = make_event(username="root", invalid_user=True)

    results = engine.evaluate(event)
    assert len(results) == 4
    names = {r.detector_name for r in results}
    assert names == {"brute_force", "password_spray", "username_enumeration", "burst_velocity"}
