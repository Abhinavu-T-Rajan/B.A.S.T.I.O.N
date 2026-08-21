"""Unit tests for SQLiteStorage layer."""

from datetime import datetime, timezone
from pathlib import Path

import pytest

from bastion.models.actors import (
    ActorState,
    RecommendedAction,
    ScoreFactor,
    Severity,
    ThreatActorProfile,
)
from bastion.models.events import EventType, SecurityEvent, ServiceType
from bastion.storage.sqlite import SQLiteStorage


@pytest.fixture
def storage() -> SQLiteStorage:
    s = SQLiteStorage(":memory:")
    yield s
    s.close()


def test_save_and_get_events(storage: SQLiteStorage) -> None:
    now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    ev1 = SecurityEvent(
        timestamp=now,
        source_ip="192.168.1.10",
        service=ServiceType.SSH,
        event_type=EventType.AUTH_FAILURE,
        username="root",
    )
    ev2 = SecurityEvent(
        timestamp=now,
        source_ip="10.0.0.1",
        service=ServiceType.SSH,
        event_type=EventType.AUTH_SUCCESS,
        username="deploy",
    )

    id1 = storage.save_event(ev1)
    id2 = storage.save_event(ev2)

    assert id1 > 0
    assert id2 > id1

    all_events = storage.get_events()
    assert len(all_events) == 2

    filtered = storage.get_events(source_ip="192.168.1.10")
    assert len(filtered) == 1
    assert filtered[0].source_ip == "192.168.1.10"
    assert filtered[0].username == "root"


def test_upsert_and_get_threat_actor(storage: SQLiteStorage) -> None:
    now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    profile = ThreatActorProfile(
        source_ip="198.51.100.23",
        first_seen=now,
        last_seen=now,
        total_events=12,
        auth_failures=10,
        auth_successes=0,
        usernames_targeted={"admin", "root"},
        services_targeted={"ssh"},
        threat_score=85,
        severity=Severity.CRITICAL,
        state=ActorState.ACTIVE_THREAT,
        factors=[ScoreFactor("brute_force", 20, "brute-force threshold crossed")],
        recommended_action=RecommendedAction.TEMPORARY_ISOLATION,
    )

    storage.upsert_threat_actor(profile)
    retrieved = storage.get_threat_actor("198.51.100.23")

    assert retrieved is not None
    assert retrieved.source_ip == "198.51.100.23"
    assert retrieved.threat_score == 85
    assert retrieved.severity == Severity.CRITICAL
    assert retrieved.state == ActorState.ACTIVE_THREAT
    assert retrieved.usernames_targeted == {"admin", "root"}
    assert retrieved.recommended_action == RecommendedAction.TEMPORARY_ISOLATION
    assert len(retrieved.factors) == 1


def test_list_threat_actors(storage: SQLiteStorage) -> None:
    now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    p1 = ThreatActorProfile(
        source_ip="1.1.1.1",
        first_seen=now,
        last_seen=now,
        threat_score=30,
        severity=Severity.LOW,
    )
    p2 = ThreatActorProfile(
        source_ip="2.2.2.2",
        first_seen=now,
        last_seen=now,
        threat_score=90,
        severity=Severity.CRITICAL,
    )

    storage.upsert_threat_actor(p1)
    storage.upsert_threat_actor(p2)

    top = storage.list_threat_actors(min_score=50)
    assert len(top) == 1
    assert top[0].source_ip == "2.2.2.2"


def test_get_stats(storage: SQLiteStorage) -> None:
    now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    storage.save_event(
        SecurityEvent(
            timestamp=now,
            source_ip="192.168.1.1",
            service=ServiceType.SSH,
            event_type=EventType.AUTH_FAILURE,
            username="admin",
        )
    )
    storage.upsert_threat_actor(
        ThreatActorProfile(
            source_ip="192.168.1.1",
            first_seen=now,
            last_seen=now,
            total_events=1,
            auth_failures=1,
            threat_score=75,
            severity=Severity.HIGH,
        )
    )

    stats = storage.get_stats()
    assert stats["total_events"] == 1
    assert stats["total_actors"] == 1
    assert stats["active_threats"] == 1
    assert len(stats["top_threats"]) == 1


def test_file_based_storage(tmp_path: Path) -> None:
    db_file = tmp_path / "subdir" / "test.db"
    s = SQLiteStorage(str(db_file))
    ev = SecurityEvent(
        timestamp=datetime.now(timezone.utc),
        source_ip="1.2.3.4",
        service=ServiceType.SSH,
        event_type=EventType.CONNECTION,
    )
    s.save_event(ev)
    s.close()

    assert db_file.exists()
