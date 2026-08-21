"""Unit and integration tests for the Sentinel/Aegis Pipeline."""

from bastion.collector.ssh import SSHLogParser
from bastion.detection.brute_force import BruteForceDetector, DetectionResult
from bastion.detection.engine import DetectionEngine
from bastion.models.actors import ThreatActorProfile
from bastion.models.events import EventType, SecurityEvent
from bastion.pipeline import SentinelPipeline, format_explainable_alert
from bastion.risk.scorer import RiskEngine
from bastion.storage.sqlite import SQLiteStorage


def test_pipeline_multi_detection_risk_and_storage() -> None:
    events_received: list[SecurityEvent] = []
    alerts_received: list[tuple[SecurityEvent, ThreatActorProfile, list[DetectionResult]]] = []

    def on_event(e: SecurityEvent) -> None:
        events_received.append(e)

    def on_alert(
        e: SecurityEvent,
        p: ThreatActorProfile,
        d: list[DetectionResult],
    ) -> None:
        alerts_received.append((e, p, d))

    storage = SQLiteStorage(":memory:")
    detection_engine = DetectionEngine(
        brute_force=BruteForceDetector(threshold=3, window_seconds=60),
    )
    risk_engine = RiskEngine()

    pipeline = SentinelPipeline(
        parser=SSHLogParser(),
        engine=detection_engine,
        risk_engine=risk_engine,
        storage=storage,
        on_event=on_event,
        on_alert=on_alert,
        alert_min_score=40,
    )

    log_stream = [
        "Failed password for root from 192.0.2.10 port 5001 ssh2",
        "Invalid user admin from 192.0.2.10 port 5002",
        "Server listening on 0.0.0.0 port 22.",
        "Failed password for invalid user admin from 192.0.2.10 port 5003 ssh2",
    ]

    results = list(pipeline.process(log_stream))

    assert len(results) == 4
    # Event 1
    assert results[0].event is not None
    assert results[0].profile is not None
    assert results[0].profile.threat_score == 5

    # Event 2
    assert results[1].event is not None
    assert results[1].profile is not None
    # 10 (failures) + 10 (invalid_user) = 20
    assert results[1].profile.threat_score == 20

    # Event 3: Non-security log line
    assert results[2].event is None
    assert results[2].profile is None

    # Event 4: Hits brute force threshold
    assert results[3].event is not None
    assert results[3].profile is not None
    # 15 (failures) + 10 (invalid_user) + 20 (brute_force) = 45 -> score >= 40 triggers alert!
    assert results[3].profile.threat_score == 45
    assert results[3].is_alert is True
    assert results[3].alert_message is not None
    assert "🚨 THREAT DETECTED" in results[3].alert_message
    assert "192.0.2.10" in results[3].alert_message

    assert len(events_received) == 3
    assert len(alerts_received) == 1

    # Verify storage persisted events and actor
    stored_events = storage.get_events()
    assert len(stored_events) == 3

    actor = storage.get_threat_actor("192.0.2.10")
    assert actor is not None
    assert actor.threat_score == 45
    assert "admin" in actor.usernames_targeted

    storage.close()


def test_format_explainable_alert() -> None:
    event = SecurityEvent.now(
        source_ip="198.51.100.23",
        service=EventType.AUTH_FAILURE,
        event_type=EventType.AUTH_FAILURE,
    )
    profile = ThreatActorProfile(
        source_ip="198.51.100.23",
        first_seen=event.timestamp,
        last_seen=event.timestamp,
        threat_score=87,
        usernames_targeted={"admin", "root"},
    )
    alert = format_explainable_alert(event, profile, [])
    assert "🚨 THREAT DETECTED" in alert
    assert "198.51.100.23" in alert
    assert "87 / 100" in alert
    assert "Targeted Users: admin, root" in alert
