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
    assert "B.A.S.T.I.O.N. v0.2.0-alpha (Oracle)" in captured.out


def test_cli_status(capsys: pytest.CaptureFixture[str]) -> None:
    parser = build_parser()
    args = parser.parse_args(["status", "--db", ":memory:"])
    ret = args.handler(args)

    assert ret == 0
    captured = capsys.readouterr()
    assert "Status      : DEVELOPMENT (Oracle v0.2.0-alpha)" in captured.out
    assert "Mode        : INTRUSION PREVENTION & THREAT ISOLATION" in captured.out


def test_cli_config_show(capsys: pytest.CaptureFixture[str]) -> None:
    parser = build_parser()
    args = parser.parse_args(["config", "show"])
    ret = args.handler(args)

    assert ret == 0
    captured = capsys.readouterr()
    assert "[storage]" in captured.out
    assert "[response]" in captured.out
    assert "isolation_threshold" in captured.out


def test_cli_manual_ban_and_unban_flow(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    db_file = str(tmp_path / "cli_ban_test.db")
    parser = build_parser()

    # 1. Ban IP
    ban_args = parser.parse_args(["--db", db_file, "ban", "203.0.113.88", "--duration", "600"])
    ret = ban_args.handler(ban_args)
    assert ret == 0
    captured = capsys.readouterr()
    assert "203.0.113.88 successfully isolated" in captured.out

    # 2. Check bans list
    bans_args = parser.parse_args(["--db", db_file, "bans"])
    ret = bans_args.handler(bans_args)
    assert ret == 0
    captured = capsys.readouterr()
    assert "203.0.113.88" in captured.out

    # 3. Check inspect
    inspect_args = parser.parse_args(["--db", db_file, "inspect", "203.0.113.88"])
    ret = inspect_args.handler(inspect_args)
    assert ret == 0
    captured = capsys.readouterr()
    assert "Active Ban ID" in captured.out

    # 4. Unban IP
    unban_args = parser.parse_args(["--db", db_file, "unban", "203.0.113.88"])
    ret = unban_args.handler(unban_args)
    assert ret == 0
    captured = capsys.readouterr()
    assert "successfully released from isolation" in captured.out


def test_cli_firewall_status_and_flush(capsys: pytest.CaptureFixture[str]) -> None:
    parser = build_parser()

    status_args = parser.parse_args(["firewall", "status", "--backend", "mock"])
    ret = status_args.handler(status_args)
    assert ret == 0
    captured = capsys.readouterr()
    assert "B.A.S.T.I.O.N. Firewall Status" in captured.out
    assert "Backend Name : MOCK" in captured.out

    flush_args = parser.parse_args(["firewall", "flush", "--backend", "mock"])
    ret = flush_args.handler(flush_args)
    assert ret == 0
    captured = capsys.readouterr()
    assert "firewall blacklist rules successfully flushed" in captured.out


def test_cli_monitor_dry_run_simulation(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    db_file = str(tmp_path / "cli_sim_test.db")
    parser = build_parser()

    monitor_args = parser.parse_args(["--db", db_file, "monitor", "--stdin", "--dry-run"])
    fake_stdin = io.StringIO(
        "Failed password for invalid user admin from 198.51.100.23 port 22 ssh2\n"
        "Failed password for invalid user test from 198.51.100.23 port 22 ssh2\n"
        "maximum authentication attempts exceeded for invalid user oracle from 198.51.100.23 port 22 ssh2 [preauth]\n"
    )

    with patch("sys.stdin", fake_stdin):
        ret = monitor_args.handler(monitor_args)
    assert ret == 0
    captured = capsys.readouterr()
    assert "B.A.S.T.I.O.N. Guardian IPS Monitor" in captured.out
    assert "Response    : DRY_RUN" in captured.out
