"""Unit tests for the Investigation Timeline generator."""

from datetime import datetime, timedelta, timezone

from bastion.models.actors import ScoreFactor, Severity
from bastion.models.events import EventType, SecurityEvent, ServiceType
from bastion.response.audit import ResponseAuditRecord
from bastion.response.models import BanRecord, BanStatus, ResponseAction
from bastion.storage.sqlite import SQLiteStorage
from bastion.timeline.generator import TimelineGenerator
from bastion.timeline.models import TimelineEntryType


def test_timeline_generation_for_ip() -> None:
    storage = SQLiteStorage(":memory:")
    gen = TimelineGenerator(storage)
    t0 = datetime(2026, 8, 21, 10, 0, 0, tzinfo=timezone.utc)

    # 1. Event
    storage.save_event(
        SecurityEvent(
            timestamp=t0,
            source_ip="198.51.100.23",
            service=ServiceType.SSH,
            event_type=EventType.AUTH_FAILURE,
            username="root",
        )
    )

    # 2. Detection
    storage.save_detection(
        source_ip="198.51.100.23",
        detector_name="brute_force",
        reason="Exceeded 10 failed attempts",
        event_count=10,
        threshold=10,
        timestamp=t0 + timedelta(seconds=10),
    )

    # 3. Score update
    storage.save_score_history(
        source_ip="198.51.100.23",
        score=85,
        severity=Severity.CRITICAL,
        factors=[ScoreFactor("brute_force", 20, "brute force threshold crossed")],
        timestamp=t0 + timedelta(seconds=11),
    )

    # 4. Ban
    storage.save_ban(
        BanRecord(
            ban_id="ban-test1",
            source_ip="198.51.100.23",
            reason="High threat isolation",
            threat_score=85,
            created_at=t0 + timedelta(seconds=12),
            expires_at=t0 + timedelta(minutes=15),
            action=ResponseAction.TEMPORARY_ISOLATION,
            status=BanStatus.ACTIVE,
        )
    )

    # 5. Response Audit
    storage.save_response_audit(
        ResponseAuditRecord(
            action="block_ip",
            target="198.51.100.23",
            executed_by="auto_ips",
            dry_run=False,
            success=True,
            timestamp=t0 + timedelta(seconds=13),
        )
    )

    timeline = gen.generate_for_ip("198.51.100.23")
    assert len(timeline) == 5

    # Check chronological ordering
    assert timeline[0].entry_type == TimelineEntryType.EVENT
    assert timeline[1].entry_type == TimelineEntryType.DETECTION
    assert timeline[2].entry_type == TimelineEntryType.RISK_CHANGE
    assert timeline[3].entry_type == TimelineEntryType.RESPONSE_ACTION
    assert timeline[4].entry_type == TimelineEntryType.RESPONSE_ACTION
