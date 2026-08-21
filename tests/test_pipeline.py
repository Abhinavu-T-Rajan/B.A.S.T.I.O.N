"""Unit and integration tests for the Sentinel/Guardian Pipeline."""

from bastion.collector.ssh import SSHLogParser
from bastion.detection.brute_force import BruteForceDetector, DetectionResult
from bastion.detection.engine import DetectionEngine
from bastion.firewall.mock import MockFirewallBackend
from bastion.models.actors import ThreatActorProfile
from bastion.models.events import EventType, SecurityEvent
from bastion.pipeline import SentinelPipeline, format_explainable_alert
from bastion.response.ban_manager import BanManager
from bastion.response.engine import ResponseEngine
from bastion.response.models import BanStatus, ResponseAction, ResponseDecision, ResponseMode
from bastion.response.policy import PolicyConfig, PolicyEngine
from bastion.risk.scorer import RiskEngine
from bastion.storage.sqlite import SQLiteStorage


def test_pipeline_multi_detection_risk_response_and_storage() -> None:
    events_received: list[SecurityEvent] = []
    alerts_received: list[tuple[SecurityEvent, ThreatActorProfile, list[DetectionResult], ResponseDecision | None]] = []

    def on_event(e: SecurityEvent) -> None:
        events_received.append(e)

    def on_alert(
        e: SecurityEvent,
        p: ThreatActorProfile,
        d: list[DetectionResult],
        dec: ResponseDecision | None,
    ) -> None:
        alerts_received.append((e, p, d, dec))

    storage = SQLiteStorage(":memory:")
    firewall = MockFirewallBackend()
    ban_manager = BanManager(storage=storage, firewall=firewall)
    policy_engine = PolicyEngine(PolicyConfig(isolation_threshold=40))
    response_engine = ResponseEngine(
        policy=policy_engine,
        ban_manager=ban_manager,
        default_mode=ResponseMode.AUTOMATIC,
    )

    detection_engine = DetectionEngine(
        brute_force=BruteForceDetector(threshold=3, window_seconds=60),
    )
    risk_engine = RiskEngine()

    pipeline = SentinelPipeline(
        parser=SSHLogParser(),
        engine=detection_engine,
        risk_engine=risk_engine,
        response_engine=response_engine,
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
    assert results[1].profile.threat_score == 20

    # Event 3: Non-security log line
    assert results[2].event is None
    assert results[2].profile is None

    # Event 4: Hits brute force threshold and crosses isolation threshold (40)
    assert results[3].event is not None
    assert results[3].profile is not None
    assert results[3].profile.threat_score == 45
    assert results[3].is_alert is True
    assert results[3].decision is not None
    assert results[3].decision.action == ResponseAction.TEMPORARY_ISOLATION
    assert results[3].decision.executed is True
    assert results[3].ban is not None
    assert results[3].ban.status == BanStatus.ACTIVE

    # Verify firewall was blocked
    assert firewall.is_ip_blocked("192.0.2.10") is True

    # Verify storage persisted ban
    active_bans = storage.get_active_bans()
    assert len(active_bans) == 1
    assert active_bans[0].source_ip == "192.0.2.10"

    storage.close()


def test_format_explainable_alert_with_defense() -> None:
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
    decision = ResponseDecision(
        source_ip="198.51.100.23",
        action=ResponseAction.TEMPORARY_ISOLATION,
        threat_score=87,
        reason="Critical threat",
        duration_seconds=900,
        mode=ResponseMode.DRY_RUN,
    )
    alert = format_explainable_alert(event, profile, [], decision=decision)
    assert "🚨 THREAT DETECTED" in alert
    assert "198.51.100.23" in alert
    assert "87 / 100" in alert
    assert "Defense Action    : WOULD BLOCK [DRY-RUN] (15m)" in alert
