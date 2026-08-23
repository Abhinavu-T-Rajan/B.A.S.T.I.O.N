"""Regression tests for production OpenSSH telemetry collection and stdin monitoring."""

import io
from pathlib import Path
from unittest.mock import patch

import pytest

from bastion.cli import build_parser
from bastion.collector.journal import JournalCollector
from bastion.collector.ssh import SSHLogParser
from bastion.models.events import EventType, ServiceType


def test_ssh_parser_sshd_and_sshd_session_formats() -> None:
    parser = SSHLogParser()

    # 1. Standard traditional OpenSSH format (sshd)
    line_traditional = "Aug 23 09:15:00 myhost sshd[12345]: Failed password for invalid user admin from 192.0.2.10 port 2222 ssh2"
    ev1 = parser.parse(line_traditional)
    assert ev1 is not None
    assert ev1.event_type == EventType.AUTH_FAILURE
    assert ev1.source_ip == "192.0.2.10"
    assert ev1.username == "admin"
    assert ev1.metadata.get("invalid_user") is True

    # 2. Modern OpenSSH session format (sshd-session) with ISO timestamp
    line_session_iso = "2026-08-23T09:15:00.123456+00:00 prod-server sshd-session[45123]: Invalid user developer from 198.51.100.40 port 54321"
    ev2 = parser.parse(line_session_iso)
    assert ev2 is not None
    assert ev2.event_type == EventType.INVALID_USER
    assert ev2.source_ip == "198.51.100.40"
    assert ev2.username == "developer"

    # 3. Modern OpenSSH failed password under sshd-session
    line_session_failed = "sshd-session[45123]: Failed password for root from 203.0.113.88 port 39120 ssh2"
    ev3 = parser.parse(line_session_failed)
    assert ev3 is not None
    assert ev3.event_type == EventType.AUTH_FAILURE
    assert ev3.source_ip == "203.0.113.88"
    assert ev3.username == "root"

    # 4. Modern OpenSSH connection closed preauth under sshd-session
    line_session_closed = "sshd-session[45123]: Connection closed by 198.51.100.99 port 44321 [preauth]"
    ev4 = parser.parse(line_session_closed)
    assert ev4 is not None
    assert ev4.event_type == EventType.CONNECTION
    assert ev4.source_ip == "198.51.100.99"

    # 5. PAM authentication failure under sshd-session
    line_pam = "pam_unix(sshd-session:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=198.51.100.77  user=deploy"
    ev5 = parser.parse(line_pam)
    assert ev5 is not None
    assert ev5.event_type == EventType.AUTH_FAILURE
    assert ev5.source_ip == "198.51.100.77"
    assert ev5.username == "deploy"


def test_journal_collector_multi_identifier_support() -> None:
    # 1. Single identifier
    c1 = JournalCollector(units="ssh.service", identifier="sshd")
    cmd1 = c1._build_base_command()
    assert "--unit" in cmd1 and "ssh.service" in cmd1
    assert "--identifier" in cmd1 and "sshd" in cmd1

    # 2. Multiple identifiers (sshd and sshd-session)
    c2 = JournalCollector(units=["ssh.service", "sshd.service"], identifier=["sshd", "sshd-session"])
    cmd2 = c2._build_base_command()
    assert cmd2.count("--identifier") == 2
    assert "sshd" in cmd2
    assert "sshd-session" in cmd2

    # 3. No identifier filter (unit-only collection)
    c3 = JournalCollector(units=["ssh.service", "sshd.service"], identifier=None)
    cmd3 = c3._build_base_command()
    assert "--identifier" not in cmd3
    assert cmd3.count("--unit") == 2


def test_cli_monitor_stdin_processes_and_emits_events(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    db_file = str(tmp_path / "monitor_stdin_test.db")
    parser = build_parser()

    monitor_args = parser.parse_args(["--db", db_file, "monitor", "--stdin", "--dry-run"])
    fake_stdin = io.StringIO(
        "sshd-session[12001]: Invalid user developer from 192.0.2.10 port 2222\n"
        "sshd-session[12002]: Failed password for root from 198.51.100.50 port 3333 ssh2\n"
    )

    with patch("sys.stdin", fake_stdin):
        ret = monitor_args.handler(monitor_args)

    assert ret == 0
    captured = capsys.readouterr()
    assert "Starting B.A.S.T.I.O.N. Guardian IPS Monitor" in captured.out
    assert "192.0.2.10" in captured.out
    assert "developer" in captured.out
    assert "198.51.100.50" in captured.out
