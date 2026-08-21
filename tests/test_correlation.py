"""Unit tests for the Threat Correlation Engine."""

from datetime import datetime, timezone

from bastion.correlation.engine import CorrelationEngine
from bastion.detection.base import DetectionResult
from bastion.incidents.manager import IncidentManager
from bastion.intelligence.manager import IOCManager
from bastion.intelligence.models import IOCType
from bastion.models.actors import ActorState, RecommendedAction, Severity, ThreatActorProfile
from bastion.models.events import EventType, SecurityEvent, ServiceType
from bastion.storage.sqlite import SQLiteStorage


def test_correlation_engine_ioc_and_technique_enrichment() -> None:
    storage = SQLiteStorage(":memory:")
    ioc_mgr = IOCManager(storage)
    inc_mgr = IncidentManager(storage)
    engine = CorrelationEngine(storage=storage, ioc_manager=ioc_mgr, incident_manager=inc_mgr)

    # Pre-add IOC
    ioc_mgr.add_ioc(
        ioc_type=IOCType.IP,
        value="198.51.100.23",
        confidence=90,
    )

    ev = SecurityEvent(
        timestamp=datetime.now(timezone.utc),
        source_ip="198.51.100.23",
        service=ServiceType.SSH,
        event_type=EventType.AUTH_FAILURE,
        username="admin",
    )
    detections = [
        DetectionResult(
            detected=True,
            source_ip="198.51.100.23",
            event_count=5,
            threshold=3,
            window_seconds=60,
            detector_name="password_spray",
            reason="Spray detected across accounts",
        )
    ]
    actor = ThreatActorProfile(
        source_ip="198.51.100.23",
        first_seen=ev.timestamp,
        last_seen=ev.timestamp,
        threat_score=85,
        severity=Severity.CRITICAL,
    )

    ctx = engine.correlate(event=ev, detections=detections, actor=actor, event_id=1)

    assert len(ctx.matched_iocs) == 1
    assert ctx.matched_iocs[0].value == "198.51.100.23"
    assert len(ctx.attack_techniques) == 1
    assert ctx.attack_techniques[0].technique_id == "T1110.003"
    assert ctx.incident is not None
    assert ctx.incident.risk_score == 85
    assert "198.51.100.23" in ctx.incident.related_actors


def test_correlation_engine_alert_deduplication() -> None:
    storage = SQLiteStorage(":memory:")
    ioc_mgr = IOCManager(storage)
    inc_mgr = IncidentManager(storage)
    engine = CorrelationEngine(storage=storage, ioc_manager=ioc_mgr, incident_manager=inc_mgr, dedup_window_seconds=10)

    ev = SecurityEvent(
        timestamp=datetime.now(timezone.utc),
        source_ip="192.0.2.55",
        service=ServiceType.SSH,
        event_type=EventType.AUTH_FAILURE,
    )
    detections = [
        DetectionResult(
            detected=True,
            source_ip="192.0.2.55",
            event_count=5,
            threshold=3,
            window_seconds=60,
            detector_name="brute_force",
        )
    ]
    actor = ThreatActorProfile(
        source_ip="192.0.2.55",
        first_seen=ev.timestamp,
        last_seen=ev.timestamp,
        threat_score=50,
        severity=Severity.MEDIUM,
    )

    # First correlation -> not duplicate
    ctx1 = engine.correlate(event=ev, detections=detections, actor=actor)
    assert ctx1.is_duplicate_alert is False

    # Immediate second correlation -> duplicate
    ctx2 = engine.correlate(event=ev, detections=detections, actor=actor)
    assert ctx2.is_duplicate_alert is True
