"""Unit tests for JournalCollector."""

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from bastion.collector.journal import JournalCollector, JournalError


def test_journal_collector_availability() -> None:
    with patch("shutil.which", return_value="/usr/bin/journalctl"):
        assert JournalCollector.is_available() is True

    with patch("shutil.which", return_value=None):
        assert JournalCollector.is_available() is False


def test_journal_collector_custom_units() -> None:
    collector = JournalCollector(units=["sshd.service", "ssh.service"], identifier="sshd")
    cmd = collector._build_base_command()
    assert "--unit" in cmd
    assert "sshd.service" in cmd
    assert "ssh.service" in cmd
    assert "--identifier" in cmd
    assert "sshd" in cmd


def test_journal_collector_read_lines_validation() -> None:
    collector = JournalCollector()
    with pytest.raises(ValueError, match="lines must be greater than zero"):
        list(collector.read(lines=0))


def test_journal_collector_read_success() -> None:
    collector = JournalCollector(units="ssh.service")

    mock_result = MagicMock()
    mock_result.stdout = "line 1\nline 2\n\nline 3\n"
    mock_result.returncode = 0

    with patch("shutil.which", return_value="/usr/bin/journalctl"), patch(
        "subprocess.run", return_value=mock_result
    ) as mock_run:
        entries = list(collector.read(lines=3, since="10m ago"))

        assert entries == ["line 1", "line 2", "line 3"]
        cmd = mock_run.call_args[0][0]
        assert "--lines" in cmd
        assert "3" in cmd
        assert "--since" in cmd
        assert "10m ago" in cmd


def test_journal_collector_read_failure_raises_error() -> None:
    collector = JournalCollector()

    with patch("shutil.which", return_value="/usr/bin/journalctl"), patch(
        "subprocess.run",
        side_effect=subprocess.CalledProcessError(
            returncode=1, cmd=["journalctl"], stderr="Access denied"
        ),
    ):
        with pytest.raises(JournalError, match="journalctl failed with exit code 1"):
            list(collector.read(lines=10))


def test_journal_collector_follow_streaming() -> None:
    collector = JournalCollector()

    mock_proc = MagicMock()
    mock_proc.stdout = iter(["stream line 1\n", "stream line 2\n", "\n", "stream line 3\n"])
    mock_proc.poll.return_value = None

    with patch("shutil.which", return_value="/usr/bin/journalctl"), patch(
        "subprocess.Popen", return_value=mock_proc
    ) as mock_popen:
        generator = collector.follow(lines=5)
        res = [next(generator), next(generator), next(generator)]

        assert res == ["stream line 1", "stream line 2", "stream line 3"]
        cmd = mock_popen.call_args[0][0]
        assert "--follow" in cmd
