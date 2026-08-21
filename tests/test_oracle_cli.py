"""Unit tests for Oracle CLI commands (ioc, incident, timeline, attack)."""

from pathlib import Path
import pytest

from bastion.cli import build_parser


def test_cli_attack_catalog(capsys: pytest.CaptureFixture[str]) -> None:
    parser = build_parser()

    # List techniques
    args = parser.parse_args(["attack"])
    ret = args.handler(args)
    assert ret == 0
    captured = capsys.readouterr()
    assert "MITRE ATT&CK Technique Catalog" in captured.out
    assert "T1110.001" in captured.out
    assert "T1110.003" in captured.out

    # Inspect technique
    args_inspect = parser.parse_args(["attack", "T1110.003"])
    ret = args_inspect.handler(args_inspect)
    assert ret == 0
    captured = capsys.readouterr()
    assert "Password Spraying" in captured.out


def test_cli_ioc_workflow(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    db_file = str(tmp_path / "cli_ioc_test.db")
    parser = build_parser()

    # 1. Add IOC
    add_args = parser.parse_args([
        "--db", db_file,
        "ioc", "add",
        "--type", "ip",
        "--value", "198.51.100.77",
        "--confidence", "85",
        "--tags", "scanner,bruteforce",
    ])
    ret = add_args.handler(add_args)
    assert ret == 0
    captured = capsys.readouterr()
    assert "Added IOC" in captured.out
    assert "198.51.100.77" in captured.out

    # 2. List IOCs
    list_args = parser.parse_args(["--db", db_file, "ioc", "list"])
    ret = list_args.handler(list_args)
    assert ret == 0
    captured = capsys.readouterr()
    assert "198.51.100.77" in captured.out

    # 3. Search IOC
    search_args = parser.parse_args(["--db", db_file, "ioc", "search", "scanner"])
    ret = search_args.handler(search_args)
    assert ret == 0
    captured = capsys.readouterr()
    assert "198.51.100.77" in captured.out


def test_cli_incident_workflow(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    db_file = str(tmp_path / "cli_inc_test.db")
    parser = build_parser()

    # 1. Create Incident
    create_args = parser.parse_args([
        "--db", db_file,
        "incident", "create",
        "--title", "SSH Brute Force Outbreak",
        "--severity", "high",
        "--risk", "85",
        "--actors", "198.51.100.77,198.51.100.78",
    ])
    ret = create_args.handler(create_args)
    assert ret == 0
    captured = capsys.readouterr()
    assert "Created incident" in captured.out

    # 2. List Incidents
    list_args = parser.parse_args(["--db", db_file, "incident", "list"])
    ret = list_args.handler(list_args)
    assert ret == 0
    captured = capsys.readouterr()
    assert "SSH Brute Force Outbreak" in captured.out


def test_cli_timeline_command(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    db_file = str(tmp_path / "cli_timeline_test.db")
    parser = build_parser()

    args = parser.parse_args(["--db", db_file, "timeline", "--ip", "198.51.100.77"])
    ret = args.handler(args)
    assert ret == 0
    captured = capsys.readouterr()
    assert "No timeline entries found." in captured.out
