from __future__ import annotations

import shutil
import subprocess
from collections.abc import Iterator
from typing import Sequence


class JournalError(RuntimeError):
    """Raised when journald collection cannot be performed."""


class JournalCollector:
    """Read Linux authentication messages from systemd-journald."""

    DEFAULT_UNITS = ("ssh.service", "sshd.service")

    def __init__(
        self,
        *,
        units: str | Sequence[str] = DEFAULT_UNITS,
        identifier: str | None = None,
    ) -> None:
        if isinstance(units, str):
            self.units = [units]
        else:
            self.units = list(units)
        self.identifier = identifier

    @classmethod
    def is_available(cls) -> bool:
        """Return whether journalctl is installed and executable."""
        return shutil.which("journalctl") is not None

    def _build_base_command(self) -> list[str]:
        """Construct the common journalctl command arguments."""
        cmd = ["journalctl", "--no-pager", "--output=cat"]
        for unit in self.units:
            cmd.extend(["--unit", unit])
        if self.identifier:
            cmd.extend(["--identifier", self.identifier])
        return cmd

    def read(
        self,
        *,
        lines: int = 50,
        since: str | None = None,
    ) -> Iterator[str]:
        """Yield recent journal entries for the configured service(s)."""
        if not self.is_available():
            raise JournalError("journalctl is not available on this system")

        if lines <= 0:
            raise ValueError("lines must be greater than zero")

        command = self._build_base_command()
        command.extend(["--lines", str(lines)])

        if since:
            command.extend(["--since", since])

        try:
            result = subprocess.run(
                command,
                check=True,
                capture_output=True,
                text=True,
            )
        except subprocess.CalledProcessError as exc:
            raise JournalError(
                f"journalctl failed with exit code {exc.returncode}: {exc.stderr.strip()}"
            ) from exc

        for line in result.stdout.splitlines():
            cleaned = line.strip()
            if cleaned:
                yield cleaned

    def follow(
        self,
        *,
        lines: int = 10,
        since: str | None = None,
    ) -> Iterator[str]:
        """Continuously stream journal entries in real-time."""
        if not self.is_available():
            raise JournalError("journalctl is not available on this system")

        command = self._build_base_command()
        command.append("--follow")

        if lines > 0:
            command.extend(["--lines", str(lines)])
        if since:
            command.extend(["--since", since])

        proc = None
        try:
            proc = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )

            if proc.stdout is None:
                raise JournalError("Failed to open journalctl standard output stream")

            for raw_line in proc.stdout:
                cleaned = raw_line.strip()
                if cleaned:
                    yield cleaned

        except Exception as exc:
            if proc and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
            if isinstance(exc, JournalError):
                raise
            raise JournalError(f"journal stream failed: {exc}") from exc
        finally:
            if proc and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()