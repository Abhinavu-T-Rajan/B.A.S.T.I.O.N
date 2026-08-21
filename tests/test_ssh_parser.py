"""Unit tests for OpenSSH log parser."""

from datetime import datetime, timezone

import pytest

from bastion.collector.ssh import SSHLogParser
from bastion.models.events import EventType, ServiceType


@pytest.fixture
def parser() -> SSHLogParser:
    return SSHLogParser()


def test_parse_failed_password_valid_user(parser: SSHLogParser) -> None:
    line = "Failed password for root from 192.168.1.50 port 54321 ssh2"
    event = parser.parse(line)

    assert event is not None
    assert event.source_ip == "192.168.1.50"
    assert event.username == "root"
    assert event.service == ServiceType.SSH
    assert event.event_type == EventType.AUTH_FAILURE
    assert event.metadata.get("method") == "password"
    assert event.metadata.get("port") == 54321
    assert event.metadata.get("invalid_user") is False


def test_parse_failed_password_invalid_user(parser: SSHLogParser) -> None:
    line = "Failed password for invalid user admin from 10.0.0.99 port 38291 ssh2"
    event = parser.parse(line)

    assert event is not None
    assert event.source_ip == "10.0.0.99"
    assert event.username == "admin"
    assert event.event_type == EventType.AUTH_FAILURE
    assert event.metadata.get("invalid_user") is True
    assert event.metadata.get("port") == 38291


def test_parse_invalid_user_standalone(parser: SSHLogParser) -> None:
    line = "Invalid user test from 198.51.100.2 port 40122"
    event = parser.parse(line)

    assert event is not None
    assert event.source_ip == "198.51.100.2"
    assert event.username == "test"
    assert event.event_type == EventType.INVALID_USER
    assert event.metadata.get("invalid_user") is True
    assert event.metadata.get("port") == 40122


def test_parse_accepted_password(parser: SSHLogParser) -> None:
    line = "Accepted password for ubuntu from 192.168.1.15 port 51234 ssh2"
    event = parser.parse(line)

    assert event is not None
    assert event.source_ip == "192.168.1.15"
    assert event.username == "ubuntu"
    assert event.event_type == EventType.AUTH_SUCCESS
    assert event.metadata.get("method") == "password"
    assert event.metadata.get("port") == 51234


def test_parse_accepted_publickey(parser: SSHLogParser) -> None:
    line = "Accepted publickey for deploy from 203.0.113.5 port 44321 ssh2: RSA SHA256:abc123xyz"
    event = parser.parse(line)

    assert event is not None
    assert event.source_ip == "203.0.113.5"
    assert event.username == "deploy"
    assert event.event_type == EventType.AUTH_SUCCESS
    assert event.metadata.get("method") == "publickey"
    assert "RSA SHA256:abc123xyz" in event.metadata.get("auth_info", "")


def test_parse_max_attempts_exceeded(parser: SSHLogParser) -> None:
    line = "maximum authentication attempts exceeded for root from 192.0.2.1 port 2222 ssh2 [preauth]"
    event = parser.parse(line)

    assert event is not None
    assert event.source_ip == "192.0.2.1"
    assert event.username == "root"
    assert event.event_type == EventType.AUTH_FAILURE
    assert event.metadata.get("reason") == "max_auth_attempts_exceeded"
    assert event.metadata.get("stage") == "preauth"


def test_parse_connection_closed_preauth(parser: SSHLogParser) -> None:
    line = "Connection closed by authenticating user root 192.0.2.55 port 60123 [preauth]"
    event = parser.parse(line)

    assert event is not None
    assert event.source_ip == "192.0.2.55"
    assert event.username == "root"
    assert event.event_type == EventType.CONNECTION
    assert event.metadata.get("stage") == "preauth"


def test_parse_ipv6_addresses(parser: SSHLogParser) -> None:
    line = "Failed password for root from 2001:db8::8a2e:370:7334 port 54321 ssh2"
    event = parser.parse(line)

    assert event is not None
    assert event.source_ip == "2001:db8::8a2e:370:7334"
    assert event.username == "root"
    assert event.event_type == EventType.AUTH_FAILURE


def test_parse_ipv4_mapped_ipv6(parser: SSHLogParser) -> None:
    line = "Failed password for root from ::ffff:192.0.2.88 port 54321 ssh2"
    event = parser.parse(line)

    assert event is not None
    assert event.source_ip == "192.0.2.88"


def test_parse_syslog_prefixed_line(parser: SSHLogParser) -> None:
    line = "Aug 21 14:22:01 server sshd[9876]: Failed password for root from 192.0.2.10 port 4444 ssh2"
    event = parser.parse(line)

    assert event is not None
    assert event.source_ip == "192.0.2.10"
    assert event.username == "root"
    assert event.timestamp.hour == 14
    assert event.timestamp.minute == 22
    assert event.timestamp.second == 1
    assert event.timestamp.tzinfo == timezone.utc


def test_parse_iso_prefixed_line(parser: SSHLogParser) -> None:
    line = "2026-08-21T18:30:15.123456+00:00 bastion sshd[123]: Accepted password for user1 from 10.10.10.10 port 22 ssh2"
    event = parser.parse(line)

    assert event is not None
    assert event.source_ip == "10.10.10.10"
    assert event.username == "user1"
    assert event.timestamp.hour == 18
    assert event.timestamp.minute == 30
    assert event.timestamp.second == 15


def test_parse_pam_auth_failure(parser: SSHLogParser) -> None:
    line = "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=198.51.100.77  user=root"
    event = parser.parse(line)

    assert event is not None
    assert event.source_ip == "198.51.100.77"
    assert event.username == "root"
    assert event.event_type == EventType.AUTH_FAILURE


def test_parse_unrelated_logs_return_none(parser: SSHLogParser) -> None:
    assert parser.parse("Server listening on 0.0.0.0 port 22.") is None
    assert parser.parse("Received signal 15; terminating.") is None
    assert parser.parse("pam_unix(sshd:session): session opened for user admin by (uid=0)") is None
    assert parser.parse("") is None
    assert parser.parse("   ") is None
