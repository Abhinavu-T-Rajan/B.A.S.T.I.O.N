"""Unit and integration tests for the SentinelPipeline."""

from bastion.collector.ssh import SSHLogParser
from bastion.detection.brute_force import BruteForceDetector, DetectionResult
from bastion.models.events import EventType, SecurityEvent
from bastion.pipeline import SentinelPipeline


def test_pipeline_event_and_alert_dispatch() -> None:
    events_received: list[SecurityEvent] = []
    alerts_received: list[tuple[SecurityEvent, DetectionResult]] = []

    def on_event(e: SecurityEvent) -> None:
        events_received.append(e)

    def on_alert(e: SecurityEvent, r: DetectionResult) -> None:
        alerts_received.append((e, r))

    detector = BruteForceDetector(threshold=3, window_seconds=60)
    pipeline = SentinelPipeline(
        detector=detector,
        on_event=on_event,
        on_alert=on_alert,
    )

    log_stream = [
        "Failed password for root from 192.0.2.10 port 5001 ssh2",
        "Invalid user admin from 192.0.2.10 port 5002",
        "Server listening on 0.0.0.0 port 22.",
        "Failed password for invalid user admin from 192.0.2.10 port 5003 ssh2",
    ]

    results = list(pipeline.process(log_stream))

    assert len(results) == 4
    # Event 1: Auth failure
    assert results[0].event is not None
    assert results[0].detection is not None
    assert results[0].detection.detected is False
    assert results[0].detection.event_count == 1

    # Event 2: Invalid user
    assert results[1].event is not None
    assert results[1].detection is not None
    assert results[1].detection.detected is False
    assert results[1].detection.event_count == 2

    # Event 3: Non-security log line
    assert results[2].event is None
    assert results[2].detection is None

    # Event 4: Third failure -> hits threshold 3
    assert results[3].event is not None
    assert results[3].detection is not None
    assert results[3].detection.detected is True
    assert results[3].detection.event_count == 3

    assert len(events_received) == 3
    assert len(alerts_received) == 1
    alert_event, alert_result = alerts_received[0]
    assert alert_event.source_ip == "192.0.2.10"
    assert alert_result.detected is True
    assert alert_result.event_count == 3
