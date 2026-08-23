"""Unit and regression tests for graceful daemon shutdown and subprocess cleanup."""

import subprocess
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from bastion.collector.journal import JournalCollector
from bastion.config import BastionConfig
from bastion.daemon.runner import BastionDaemon
from bastion.daemon.state import ServiceState
from bastion.firewall.mock import MockFirewallBackend
from bastion.storage.sqlite import SQLiteStorage


def test_journal_collector_stop_terminates_process() -> None:
    collector = JournalCollector(units="ssh.service")
    mock_proc = MagicMock(spec=subprocess.Popen)
    mock_proc.poll.return_value = None  # Process is running

    collector._active_proc = mock_proc
    collector.stop()

    assert mock_proc.terminate.called
    assert mock_proc.wait.called
    assert collector._active_proc is None


def test_daemon_graceful_shutdown(tmp_path: Path) -> None:
    health_file = str(tmp_path / "shutdown_health.json")
    db_file = str(tmp_path / "shutdown_test.db")

    cfg = BastionConfig()
    cfg.storage.db_path = db_file
    cfg.daemon.health_state_path = health_file
    cfg.response.backend = "mock"

    storage = SQLiteStorage(db_file)
    firewall = MockFirewallBackend()
    collector = JournalCollector()
    mock_proc = MagicMock(spec=subprocess.Popen)
    mock_proc.poll.return_value = None
    collector._active_proc = mock_proc

    daemon = BastionDaemon(
        config=cfg,
        storage=storage,
        firewall=firewall,
    )
    daemon.initialize()
    daemon.collector = collector
    daemon._running = True
    daemon.health_tracker.set_service_state(ServiceState.RUNNING)

    # Trigger graceful shutdown
    daemon.stop()

    assert daemon._running is False
    assert daemon.health_tracker.service_state == ServiceState.STOPPED
    assert mock_proc.terminate.called

    # Repeated stop is idempotent and safe
    daemon.stop()
    assert daemon.health_tracker.service_state == ServiceState.STOPPED


def test_daemon_shutdown_unblocks_streaming_loop(tmp_path: Path) -> None:
    health_file = str(tmp_path / "unblock_health.json")
    db_file = str(tmp_path / "unblock_test.db")

    cfg = BastionConfig()
    cfg.storage.db_path = db_file
    cfg.daemon.health_state_path = health_file
    cfg.response.backend = "mock"

    daemon = BastionDaemon(
        config=cfg,
        storage=SQLiteStorage(db_file),
        firewall=MockFirewallBackend(),
    )
    daemon.initialize()

    # Simulate blocked stream in a background thread
    stop_called = threading.Event()

    def run_daemon() -> None:
        def blocked_stream() -> None:
            while not daemon._stop_event.is_set():
                time.sleep(0.05)
                yield "sshd[100]: Failed password for root from 192.0.2.99 port 22 ssh2"

        daemon._injected_stream = blocked_stream()
        daemon.run()
        stop_called.set()

    t = threading.Thread(target=run_daemon, daemon=True)
    t.start()

    time.sleep(0.2)
    daemon.stop()

    t.join(timeout=2.0)
    assert not t.is_alive(), "Daemon runner thread hung after stop() was called"
    assert stop_called.is_set()
