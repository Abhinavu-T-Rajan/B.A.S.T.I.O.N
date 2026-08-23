"""Unit and integration tests for the BastionDaemon service runner."""

import time
from pathlib import Path

import pytest

from bastion.config import BastionConfig
from bastion.daemon.runner import BastionDaemon
from bastion.daemon.state import HealthStatus, ServiceState, Subsystem
from bastion.firewall.mock import MockFirewallBackend
from bastion.storage.sqlite import SQLiteStorage


def test_daemon_initialization_and_lifecycle(tmp_path: Path) -> None:
    health_file = str(tmp_path / "health.json")
    db_file = str(tmp_path / "daemon_test.db")

    cfg = BastionConfig()
    cfg.storage.db_path = db_file
    cfg.daemon.health_state_path = health_file
    cfg.response.backend = "mock"
    cfg.response.mode = "dry_run"

    storage = SQLiteStorage(db_file)
    firewall = MockFirewallBackend()

    daemon = BastionDaemon(
        config=cfg,
        storage=storage,
        firewall=firewall,
        custom_collector_stream=[],
    )

    daemon.initialize()
    assert daemon.health_tracker.service_state == ServiceState.INITIALIZING
    assert daemon.health_tracker._subsystems[Subsystem.DATABASE.value].status == HealthStatus.HEALTHY
    assert daemon.health_tracker._subsystems[Subsystem.FIREWALL.value].status == HealthStatus.HEALTHY

    # Verify health state file was written
    assert Path(health_file).exists()

    daemon.stop()
    assert daemon.health_tracker.service_state == ServiceState.STOPPED


def test_daemon_stream_processing_and_metrics(tmp_path: Path) -> None:
    health_file = str(tmp_path / "health_stream.json")
    db_file = str(tmp_path / "daemon_stream.db")

    cfg = BastionConfig()
    cfg.storage.db_path = db_file
    cfg.daemon.health_state_path = health_file
    cfg.response.backend = "mock"
    cfg.response.mode = "automatic"
    cfg.response.rate_limit_threshold = 30
    cfg.response.isolation_threshold = 40

    log_stream = [
        "Failed password for root from 198.51.100.50 port 2222 ssh2",
        "Failed password for invalid user admin from 198.51.100.50 port 2223 ssh2",
        "Failed password for invalid user test from 198.51.100.50 port 2224 ssh2",
        "maximum authentication attempts exceeded for invalid user oracle from 198.51.100.50 port 2225 ssh2 [preauth]",
    ]

    storage = SQLiteStorage(db_file)
    firewall = MockFirewallBackend()

    daemon = BastionDaemon(
        config=cfg,
        storage=storage,
        firewall=firewall,
        custom_collector_stream=log_stream,
    )

    ret = daemon.run()
    assert ret == 0
    assert daemon.health_tracker.service_state == ServiceState.STOPPED

    snapshot = daemon.health_tracker.get_snapshot()
    assert snapshot.events_processed == 4
    assert snapshot.detections_count >= 1

    # Verify ban was enforced at firewall
    assert firewall.is_ip_blocked("198.51.100.50") is True


def test_daemon_resilience_to_malformed_lines(tmp_path: Path) -> None:
    health_file = str(tmp_path / "health_malformed.json")
    db_file = str(tmp_path / "daemon_malformed.db")

    cfg = BastionConfig()
    cfg.storage.db_path = db_file
    cfg.daemon.health_state_path = health_file
    cfg.response.backend = "mock"

    # Stream containing corrupted/unparseable and non-standard lines
    log_stream = [
        "Normal kernel info line unrelated to ssh",
        "Corrupted binary data \x00\xff\xfe\x12 random garbage",
        "Failed password for root from 192.0.2.11 port 22 ssh2",
        "",
        "--- invalid format line ---",
    ]

    storage = SQLiteStorage(db_file)
    firewall = MockFirewallBackend()

    daemon = BastionDaemon(
        config=cfg,
        storage=storage,
        firewall=firewall,
        custom_collector_stream=log_stream,
    )

    # Daemon must not raise an unhandled exception or terminate early
    ret = daemon.run()
    assert ret == 0
    assert daemon.health_tracker.service_state == ServiceState.STOPPED

    # The 1 valid SSH failed password event was persisted in database
    verify_storage = SQLiteStorage(db_file)
    evs = verify_storage.get_events(source_ip="192.0.2.11")
    assert len(evs) == 1
    verify_storage.close()
