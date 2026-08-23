from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from bastion.core.models.telemetry import RawTelemetry
from bastion.infrastructure.telemetry.adapters.composite import CompositeEventNormalizer
from bastion.infrastructure.telemetry.adapters.ssh import SSHLogAdapter
from bastion.infrastructure.telemetry.file import FileCollector
from bastion.infrastructure.telemetry.stdin import StdinCollector
from bastion.models.events import EventType, ServiceType


def test_raw_telemetry_attributes() -> None:
    """Test RawTelemetry fields, immutability, and defaults."""
    now = datetime.now(timezone.utc)
    raw = RawTelemetry(
        raw_message="Failed password for invalid user root from 198.51.100.1 port 2222 ssh2",
        source="journald",
        timestamp=now,
        transport="unix_socket",
        unit="sshd.service",
        identifier="sshd-session",
        pid=12345,
        metadata={"custom": "meta"},
    )

    assert raw.source == "journald"
    assert raw.unit == "sshd.service"
    assert raw.identifier == "sshd-session"
    assert raw.pid == 12345
    assert raw.metadata["custom"] == "meta"


def test_stdin_collector_streaming() -> None:
    """Test StdinCollector streaming RawTelemetry records."""
    sample_lines = [
        "Failed password for root from 198.51.100.10 port 4000 ssh2\n",
        "Invalid user admin from 198.51.100.11 port 4001\n",
    ]
    collector = StdinCollector(stream_source=sample_lines)
    records = list(collector.stream())

    assert len(records) == 2
    assert records[0].source == "stdin"
    assert records[0].transport == "pipe"
    assert "198.51.100.10" in records[0].raw_message
    assert "admin" in records[1].raw_message


def test_file_collector_streaming(tmp_path: Path) -> None:
    """Test FileCollector reading and streaming RawTelemetry from a log file."""
    log_file = tmp_path / "auth.log"
    log_file.write_text(
        "Aug 23 10:00:00 server sshd[999]: Failed password for user1 from 198.51.100.20 port 5555 ssh2\n"
        "Aug 23 10:00:01 server sshd-session[1000]: Invalid user hacker from 198.51.100.21 port 5556\n",
        encoding="utf-8",
    )

    collector = FileCollector(file_path=log_file)
    assert collector.is_available() is True

    records = list(collector.stream())
    assert len(records) == 2
    assert records[0].source == "file"
    assert records[0].transport == "file_io"
    assert records[0].metadata["file_path"] == str(log_file.resolve())


def test_ssh_log_adapter_normalizes_raw_telemetry() -> None:
    """Test SSHLogAdapter normalizes various RawTelemetry formats including sshd-session."""
    adapter = SSHLogAdapter()

    # 1. sshd-session invalid user
    raw1 = RawTelemetry(
        raw_message="sshd-session[4567]: Invalid user testuser from 203.0.113.50 port 3333",
        source="journald",
        identifier="sshd-session",
        pid=4567,
    )
    assert adapter.can_handle(raw1) is True
    ev1 = adapter.normalize(raw1)
    assert ev1 is not None
    assert ev1.source_ip == "203.0.113.50"
    assert ev1.username == "testuser"
    assert ev1.event_type == EventType.INVALID_USER
    assert ev1.metadata["invalid_user"] is True
    assert ev1.metadata["pid"] == 4567

    # 2. Failed password
    raw2 = RawTelemetry(
        raw_message="Failed password for root from 198.51.100.99 port 2222 ssh2",
        source="stdin",
    )
    assert adapter.can_handle(raw2) is True
    ev2 = adapter.normalize(raw2)
    assert ev2 is not None
    assert ev2.source_ip == "198.51.100.99"
    assert ev2.username == "root"
    assert ev2.event_type == EventType.AUTH_FAILURE

    # 3. Accepted publickey
    raw3 = RawTelemetry(
        raw_message="Accepted publickey for deployer from 192.0.2.1 port 55555 ssh2: RSA SHA256:abc",
        source="file",
    )
    assert adapter.can_handle(raw3) is True
    ev3 = adapter.normalize(raw3)
    assert ev3 is not None
    assert ev3.source_ip == "192.0.2.1"
    assert ev3.username == "deployer"
    assert ev3.event_type == EventType.AUTH_SUCCESS


def test_composite_normalizer_dispatch() -> None:
    """Test CompositeEventNormalizer registering adapters and dispatching records."""
    normalizer = CompositeEventNormalizer()
    assert len(normalizer.adapters) >= 1

    raw = RawTelemetry(
        raw_message="Failed password for invalid user guest from 198.51.100.40 port 12345 ssh2",
        source="journald",
    )
    event = normalizer.normalize(raw)
    assert event is not None
    assert event.source_ip == "198.51.100.40"
    assert event.username == "guest"
    assert event.event_type == EventType.AUTH_FAILURE

    # Test string fallback normalization
    str_event = normalizer.normalize(
        "Invalid user attacker from 198.51.100.41 port 12345"
    )
    assert str_event is not None
    assert str_event.source_ip == "198.51.100.41"
    assert str_event.username == "attacker"
