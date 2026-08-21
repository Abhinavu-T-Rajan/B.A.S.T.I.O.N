"""Unit tests for the B.A.S.T.I.O.N. CLI interface."""

import io
from contextlib import redirect_stdout
from unittest.mock import patch

import pytest

from bastion.cli import build_parser, main


def test_cli_version(capsys: pytest.CaptureFixture[str]) -> None:
    parser = build_parser()
    with pytest.raises(SystemExit) as exc:
        parser.parse_args(["--version"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "B.A.S.T.I.O.N. v0.1.1" in captured.out


def test_cli_status(capsys: pytest.CaptureFixture[str]) -> None:
    parser = build_parser()
    args = parser.parse_args(["status"])
    ret = args.handler(args)

    assert ret == 0
    captured = capsys.readouterr()
    assert "Status      : DEVELOPMENT (Sentinel)" in captured.out
    assert "Parsers     : OpenSSH (sshd)" in captured.out


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


def test_cli_monitor_stdin(capsys: pytest.CaptureFixture[str]) -> None:
    parser = build_parser()
    args = parser.parse_args(["monitor", "--stdin", "--threshold", "2"])

    fake_stdin = io.StringIO(
        "Failed password for root from 192.0.2.1 port 22 ssh2\n"
        "Failed password for root from 192.0.2.1 port 22 ssh2\n"
    )

    with patch("sys.stdin", fake_stdin):
        ret = args.handler(args)

    assert ret == 0
    captured = capsys.readouterr()
    assert "B.A.S.T.I.O.N. Sentinel Monitor v0.1.1" in captured.out
    assert "Processed 2 log entries -> 2 security events." in captured.out
