"""Unit tests for the B.A.S.T.I.O.N. CLI interface."""

import io
from pathlib import Path
from unittest.mock import patch

import pytest

from bastion.cli import build_parser


def test_cli_version(capsys: pytest.CaptureFixture[str]) -> None:
    parser = build_parser()
    with pytest.raises(SystemExit) as exc:
        parser.parse_args(["--version"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "B.A.S.T.I.O.N. v0.1.2" in captured.out


def test_cli_status(capsys: pytest.CaptureFixture[str]) -> None:
    parser = build_parser()
    args = parser.parse_args(["status", "--db", ":memory:"])
    ret = args.handler(args)

    assert ret == 0
    captured = capsys.readouterr()
    assert "Status      : DEVELOPMENT (Aegis)" in captured.out
    assert "Mode        : THREAT INTELLIGENCE & RISK SCORING" in captured.out
    assert "Detectors   : Brute-Force, Password Spray, Username Enumeration, Burst Velocity" in captured.out


def test_cli_config_show(capsys: pytest.CaptureFixture[str]) -> None:
    parser = build_parser()
    args = parser.parse_args(["config", "show"])
    ret = args.handler(args)

    assert ret == 0
    captured = capsys.readouterr()
    assert "[storage]" in captured.out
    assert "[detectors.password_spray]" in captured.out
    assert "[risk]" in captured.out


def test_cli_test_detection(capsys: pytest.CaptureFixture[str]) -> None:
    parser = build_parser()
    args = parser.parse_args(["test-detection", "--attempts", "5", "--threshold", "3"])
    ret = args.handler(args)

    assert ret == 0
    captured = capsys.readouterr()
    assert "B.A.S.T.I.O.N. Detection Test" in captured.out
    assert "Detected  : True" in captured.out


def test_cli_parse_single_line(capsys: pytest.CaptureFixture[str]) -> None:
    parser = build_parser()
    args = parser.parse_args(["parse", "Failed password for root from 192.168.1.50 port 22 ssh2"])
    ret = args.handler(args)

    assert ret == 0
    captured = capsys.readouterr()
    assert "STATUS: [PARSED]" in captured.out
    assert "Source IP : 192.168.1.50" in captured.out
    assert "User      : root" in captured.out


def test_cli_monitor_and_inspection_flow(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    db_file = str(tmp_path / "cli_test.db")
    parser = build_parser()

    # 1. Feed 3 failed attempts into monitor
    monitor_args = parser.parse_args(["--db", db_file, "monitor", "--stdin"])
    fake_stdin = io.StringIO(
        "Failed password for invalid user admin from 198.51.100.23 port 22 ssh2\n"
        "Failed password for invalid user test from 198.51.100.23 port 22 ssh2\n"
        "Failed password for invalid user root from 198.51.100.23 port 22 ssh2\n"
    )

    with patch("sys.stdin", fake_stdin):
        ret = monitor_args.handler(monitor_args)
    assert ret == 0

    # 2. Query threats
    threats_args = parser.parse_args(["--db", db_file, "threats"])
    ret = threats_args.handler(threats_args)
    assert ret == 0
    captured = capsys.readouterr()
    assert "198.51.100.23" in captured.out

    # 3. Inspect IP
    inspect_args = parser.parse_args(["--db", db_file, "inspect", "198.51.100.23"])
    ret = inspect_args.handler(inspect_args)
    assert ret == 0
    captured = capsys.readouterr()
    assert "THREAT PROFILE: 198.51.100.23" in captured.out
    assert "Contributing Score Factors:" in captured.out

    # 4. Query events
    events_args = parser.parse_args(["--db", db_file, "events", "--ip", "198.51.100.23"])
    ret = events_args.handler(events_args)
    assert ret == 0
    captured = capsys.readouterr()
    assert "198.51.100.23" in captured.out

    # 5. Query stats
    stats_args = parser.parse_args(["--db", db_file, "stats"])
    ret = stats_args.handler(stats_args)
    assert ret == 0
    captured = capsys.readouterr()
    assert "Total Telemetry Events    : 3" in captured.out
