"""Unit tests for Sentinel Core CLI commands: health, config validate, daemon."""

import json
from pathlib import Path

import pytest

from bastion.cli import build_parser


def test_cli_config_validate_valid(capsys: pytest.CaptureFixture[str]) -> None:
    parser = build_parser()
    args = parser.parse_args(["config", "validate"])
    ret = args.handler(args)

    assert ret == 0
    captured = capsys.readouterr()
    assert "✓ Configuration is valid" in captured.out


def test_cli_config_validate_invalid(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    bad_config = tmp_path / "bad_bastion.toml"
    bad_config.write_text(
        """
        [storage]
        db_path = ""

        [detectors.brute_force]
        threshold = -5
        window_seconds = 0

        [response]
        mode = "invalid_mode"
        isolation_threshold = 150
        """
    )

    parser = build_parser()
    args = parser.parse_args(["-c", str(bad_config), "config", "validate"])
    ret = args.handler(args)

    assert ret == 1
    captured = capsys.readouterr()
    assert "Configuration validation failed" in captured.out
    assert "storage.db_path" in captured.out
    assert "brute_force.threshold" in captured.out


def test_cli_health_live_diagnostics(capsys: pytest.CaptureFixture[str]) -> None:
    parser = build_parser()
    args = parser.parse_args(["health", "--db", ":memory:", "--backend", "mock"])
    ret = args.handler(args)

    assert ret == 0
    captured = capsys.readouterr()
    assert "B.A.S.T.I.O.N. Health" in captured.out
    assert "Service       :" in captured.out
    assert "Database      : HEALTHY" in captured.out
    assert "Firewall      : HEALTHY" in captured.out


def test_cli_health_json_format(capsys: pytest.CaptureFixture[str]) -> None:
    parser = build_parser()
    args = parser.parse_args(["health", "--json", "--db", ":memory:", "--backend", "mock"])
    ret = args.handler(args)

    assert ret == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert "version" in data
    assert "subsystems" in data
    assert data["subsystems"]["Database"]["status"] == "HEALTHY"


def test_cli_daemon_parser_help(capsys: pytest.CaptureFixture[str]) -> None:
    parser = build_parser()
    with pytest.raises(SystemExit) as exc:
        parser.parse_args(["daemon", "--help"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "--dry-run" in captured.out
    assert "--enforce" in captured.out
    assert "--source" in captured.out
