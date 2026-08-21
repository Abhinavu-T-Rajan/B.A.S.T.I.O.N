"""Unit tests for the B.A.S.T.I.O.N. Risk Scoring Engine."""

from datetime import datetime, timezone

import pytest

from bastion.detection.brute_force import DetectionResult
from bastion.models.actors import (
    ActorState,
    RecommendedAction,
    ScoreFactor,
    Severity,
    ThreatActorProfile,
)
from bastion.models.events import EventType, SecurityEvent, ServiceType
from bastion.risk.scorer import RiskEngine, RiskScoringConfig


def make_event(
    *,
    source_ip: str = "198.51.100.23",
    event_type: EventType = EventType.AUTH_FAILURE,
    username: str | None = "admin",
    metadata: dict | None = None,
) -> SecurityEvent:
    return SecurityEvent(
        timestamp=datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        source_ip=source_ip,
        service=ServiceType.SSH,
        event_type=event_type,
        username=username,
        metadata=metadata or {},
    )


def test_single_failure_scoring() -> None:
    engine = RiskEngine()
    event = make_event()
    profile = engine.evaluate(event)

    assert profile.source_ip == "198.51.100.23"
    assert profile.auth_failures == 1
    assert profile.threat_score == 5
    assert profile.severity == Severity.LOW
    assert profile.state == ActorState.PROBING
    assert profile.recommended_action == RecommendedAction.MONITOR
    assert any(f.name == "auth_failures" for f in profile.factors)


def test_invalid_user_scoring_bonus() -> None:
    engine = RiskEngine()
    event = make_event(
        event_type=EventType.INVALID_USER,
        metadata={"invalid_user": True},
    )
    profile = engine.evaluate(event)

    # 5 (auth_failures) + 10 (invalid_user) = 15
    assert profile.threat_score == 15
    assert any(f.name == "invalid_user" for f in profile.factors)


def test_detector_signals_and_burst_scoring() -> None:
    engine = RiskEngine()
    event = make_event(metadata={"invalid_user": True})

    detections = [
        DetectionResult(
            detected=True,
            source_ip=event.source_ip,
            event_count=10,
            threshold=10,
            window_seconds=60,
            detector_name="brute_force",
            reason="brute force",
        ),
        DetectionResult(
            detected=True,
            source_ip=event.source_ip,
            event_count=5,
            threshold=5,
            window_seconds=5,
            detector_name="burst_velocity",
            reason="burst",
        ),
    ]

    profile = engine.evaluate(event, detections=detections)

    # 5 (failures) + 10 (invalid_user) + 20 (brute_force) + 25 (burst) = 60
    assert profile.threat_score == 60
    assert profile.severity == Severity.MEDIUM
    assert profile.state == ActorState.SUSPICIOUS
    assert profile.recommended_action == RecommendedAction.RATE_LIMIT


def test_critical_threshold_and_isolation_action() -> None:
    engine = RiskEngine()
    event = make_event(metadata={"reason": "max_auth_attempts_exceeded", "invalid_user": True})

    detections = [
        DetectionResult(
            detected=True,
            source_ip=event.source_ip,
            event_count=10,
            threshold=10,
            window_seconds=60,
            detector_name="brute_force",
        ),
        DetectionResult(
            detected=True,
            source_ip=event.source_ip,
            event_count=4,
            threshold=3,
            window_seconds=120,
            detector_name="password_spray",
        ),
        DetectionResult(
            detected=True,
            source_ip=event.source_ip,
            event_count=5,
            threshold=5,
            window_seconds=5,
            detector_name="burst_velocity",
        ),
    ]

    profile = engine.evaluate(event, detections=detections)

    # 5 + 10 + 20 (max_attempts) + 20 (bf) + 20 (spray) + 25 (burst) = 100 (clamped)
    assert profile.threat_score >= 85
    assert profile.severity == Severity.CRITICAL
    assert profile.state == ActorState.ACTIVE_THREAT
    assert profile.recommended_action == RecommendedAction.TEMPORARY_ISOLATION


def test_trusted_ip_allowlist() -> None:
    engine = RiskEngine()
    event = make_event(source_ip="127.0.0.1", event_type=EventType.AUTH_FAILURE)
    profile = engine.evaluate(event)

    assert profile.threat_score == 0
    assert profile.severity == Severity.LOW
    assert profile.state == ActorState.TRUSTED
    assert profile.recommended_action == RecommendedAction.NONE
    assert profile.factors[0].name == "trusted_source"


def test_auth_success_reduces_score() -> None:
    engine = RiskEngine()
    existing = ThreatActorProfile(
        source_ip="198.51.100.5",
        first_seen=datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc),
        last_seen=datetime(2026, 1, 1, 11, 0, tzinfo=timezone.utc),
        total_events=3,
        auth_failures=2,
        threat_score=10,
        severity=Severity.LOW,
    )

    event = make_event(source_ip="198.51.100.5", event_type=EventType.AUTH_SUCCESS)
    updated = engine.evaluate(event, existing_profile=existing)

    assert updated.auth_successes == 1
    assert any(f.name == "auth_success" for f in updated.factors)
