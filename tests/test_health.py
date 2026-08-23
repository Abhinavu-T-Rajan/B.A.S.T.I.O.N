"""Unit tests for the HealthTracker and operational status diagnostics."""

import json
from datetime import datetime, timezone
from pathlib import Path

from bastion.daemon.state import (
    DaemonHealthSnapshot,
    HealthStatus,
    HealthTracker,
    ServiceState,
    Subsystem,
    SubsystemHealth,
)


def test_health_tracker_initial_state() -> None:
    tracker = HealthTracker(response_mode="DRY_RUN", firewall_backend="MOCK")
    assert tracker.service_state == ServiceState.STARTING
    assert tracker.calculate_overall_health() == HealthStatus.UNKNOWN

    snapshot = tracker.get_snapshot()
    assert snapshot.service_state == ServiceState.STARTING
    assert snapshot.overall_health == HealthStatus.UNKNOWN
    assert snapshot.events_processed == 0
    assert snapshot.detections_count == 0


def test_health_tracker_state_transitions() -> None:
    tracker = HealthTracker()

    # Transition to RUNNING
    tracker.set_service_state(ServiceState.RUNNING)
    assert tracker.service_state == ServiceState.RUNNING
    assert tracker._subsystems[Subsystem.SERVICE.value].status == HealthStatus.HEALTHY

    # Set all subsystems to HEALTHY
    for sub in Subsystem:
        tracker.set_subsystem_health(sub, HealthStatus.HEALTHY, "Subsystem operational")

    assert tracker.calculate_overall_health() == HealthStatus.HEALTHY

    # Mark one subsystem DEGRADED
    tracker.set_subsystem_health(Subsystem.FIREWALL, HealthStatus.DEGRADED, "Firewall warning")
    assert tracker.calculate_overall_health() == HealthStatus.DEGRADED

    # Mark one subsystem FAILED
    tracker.set_subsystem_health(Subsystem.DATABASE, HealthStatus.FAILED, "DB connection lost")
    assert tracker.calculate_overall_health() == HealthStatus.FAILED


def test_health_tracker_error_accumulation() -> None:
    tracker = HealthTracker()
    tracker.set_subsystem_health(Subsystem.TELEMETRY, HealthStatus.HEALTHY)

    # 1st error
    tracker.record_subsystem_error(Subsystem.TELEMETRY, "Timeout 1")
    assert tracker._subsystems[Subsystem.TELEMETRY.value].error_count == 1
    assert tracker._subsystems[Subsystem.TELEMETRY.value].status == HealthStatus.HEALTHY

    # 2nd error
    tracker.record_subsystem_error(Subsystem.TELEMETRY, "Timeout 2")
    assert tracker._subsystems[Subsystem.TELEMETRY.value].error_count == 2
    assert tracker._subsystems[Subsystem.TELEMETRY.value].status == HealthStatus.HEALTHY

    # 3rd error -> auto degrades
    tracker.record_subsystem_error(Subsystem.TELEMETRY, "Timeout 3")
    assert tracker._subsystems[Subsystem.TELEMETRY.value].error_count == 3
    assert tracker._subsystems[Subsystem.TELEMETRY.value].status == HealthStatus.DEGRADED


def test_health_tracker_events_and_detections_metrics() -> None:
    tracker = HealthTracker()
    now = datetime.now(timezone.utc)
    tracker.record_event_processed(now)
    tracker.record_event_processed(now)
    tracker.record_detection()
    tracker.set_active_bans_count(4)

    snapshot = tracker.get_snapshot()
    assert snapshot.events_processed == 2
    assert snapshot.detections_count == 1
    assert snapshot.active_bans_count == 4
    assert snapshot.last_event_time == now


def test_health_snapshot_save_and_load(tmp_path: Path) -> None:
    health_file = tmp_path / "health.json"
    tracker = HealthTracker(response_mode="AUTOMATIC", firewall_backend="NFTABLES")
    tracker.set_service_state(ServiceState.RUNNING)
    for sub in Subsystem:
        tracker.set_subsystem_health(sub, HealthStatus.HEALTHY, "OK")

    tracker.save_to_file(health_file)
    assert health_file.exists()

    loaded = HealthTracker.load_from_file(health_file)
    assert loaded is not None
    assert loaded.service_state == ServiceState.RUNNING
    assert loaded.overall_health == HealthStatus.HEALTHY
    assert loaded.response_mode == "AUTOMATIC"
    assert loaded.firewall_backend == "NFTABLES"
    assert loaded.subsystems[Subsystem.DATABASE.value].status == HealthStatus.HEALTHY


def test_format_health_report() -> None:
    tracker = HealthTracker(response_mode="DRY_RUN")
    tracker.set_service_state(ServiceState.RUNNING)
    for sub in Subsystem:
        tracker.set_subsystem_health(sub, HealthStatus.HEALTHY, "All systems nominal")

    snapshot = tracker.get_snapshot()
    report = HealthTracker.format_health_report(snapshot)

    assert "B.A.S.T.I.O.N. Health" in report
    assert "Service       : HEALTHY" in report
    assert "Telemetry     : HEALTHY" in report
    assert "Detection     : HEALTHY" in report
    assert "Database      : HEALTHY" in report
    assert "Firewall      : HEALTHY" in report
    assert "Response      : DRY_RUN" in report
    assert "Uptime        :" in report
