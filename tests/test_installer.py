"""Tests for the B.A.S.T.I.O.N. installer suite and CLI database provisioning."""

import os
import subprocess
from pathlib import Path

import pytest

from bastion.cli import build_parser


def test_install_script_help() -> None:
    repo_root = Path(__file__).parent.parent
    script = repo_root / "installer" / "install.sh"

    result = subprocess.run(
        [str(script), "--help"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert "B.A.S.T.I.O.N. Host Intrusion Defense System" in result.stdout
    assert "Usage: sudo ./install.sh" in result.stdout


def test_install_script_check_only() -> None:
    repo_root = Path(__file__).parent.parent
    script = repo_root / "installer" / "install.sh"

    result = subprocess.run(
        [str(script), "--check-only"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert "Preflight checks completed successfully" in result.stdout


def test_install_script_invalid_arg() -> None:
    repo_root = Path(__file__).parent.parent
    script = repo_root / "installer" / "install.sh"

    result = subprocess.run(
        [str(script), "--invalid-flag-12345"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "Unknown option" in result.stderr


def test_uninstall_script_help() -> None:
    repo_root = Path(__file__).parent.parent
    script = repo_root / "installer" / "uninstall.sh"

    result = subprocess.run(
        [str(script), "--help"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert "B.A.S.T.I.O.N. Uninstaller" in result.stdout
    assert "--keep-data" in result.stdout
    assert "--purge-all" in result.stdout


def test_upgrade_script_help() -> None:
    repo_root = Path(__file__).parent.parent
    script = repo_root / "installer" / "upgrade.sh"

    result = subprocess.run(
        [str(script), "--help"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert "B.A.S.T.I.O.N. Upgrader" in result.stdout
    assert "--backup-dir" in result.stdout


def test_modular_libraries_syntax_and_sourcing() -> None:
    repo_root = Path(__file__).parent.parent
    lib_dir = repo_root / "installer" / "lib"

    libs = [
        "common.sh",
        "detect_os.sh",
        "dependencies.sh",
        "filesystem.sh",
        "service.sh",
        "verify.sh",
    ]

    for lib in libs:
        lib_path = lib_dir / lib
        assert lib_path.exists(), f"Missing library: {lib}"

        # Test bash sourcing
        cmd = f"source '{lib_path}' && type log_info detect_os >/dev/null 2>&1 || true"
        result = subprocess.run(
            ["bash", "-c", cmd],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        assert result.returncode == 0, f"Failed to source {lib}: {result.stderr}"


def test_cli_db_init_and_status(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    db_file = str(tmp_path / "installer_db_test.db")
    parser = build_parser()

    # 1. Test 'bastion db init'
    init_args = parser.parse_args(["--db", db_file, "db", "init"])
    ret = init_args.handler(init_args)
    assert ret == 0
    captured = capsys.readouterr()
    assert "SQLite database schema initialized" in captured.out
    assert Path(db_file).exists()

    # 2. Test 'bastion db status'
    status_args = parser.parse_args(["--db", db_file, "db", "status"])
    ret = status_args.handler(status_args)
    assert ret == 0
    captured = capsys.readouterr()
    assert "B.A.S.T.I.O.N. Database Status" in captured.out
    assert "Schema Version : 2" in captured.out
