from __future__ import annotations

import shutil
import subprocess
import threading
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
        identifier: str | Sequence[str] | None = None,
    ) -> None:
        if isinstance(units, str):
            self.units = [units]
        else:
            self.units = list(units)

        if isinstance(identifier, str):
            self.identifiers = [identifier]
        elif identifier is not None:
            self.identifiers = list(identifier)
        else:
            self.identifiers = []

        self._lock = threading.Lock()
        self._active_proc: subprocess.Popen[str] | None = None

    @property
    def identifier(self) -> str | None:
        """Backward-compatibility property returning first identifier or None."""
        return self.identifiers[0] if self.identifiers else None

    @classmethod
    def is_available(cls) -> bool:
        """Return whether journalctl is installed and executable."""
        return shutil.which("journalctl") is not None

    def _build_base_command(self) -> list[str]:
        """Construct the common journalctl command arguments."""
        cmd = ["journalctl", "--no-pager", "--output=cat"]
        for unit in self.units:
            cmd.extend(["--unit", unit])
        for ident in self.identifiers:
            cmd.extend(["--identifier", ident])
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

            with self._lock:
                self._active_proc = proc

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
            with self._lock:
                if self._active_proc is proc:
                    self._active_proc = None
            if proc and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()

    def stop(self) -> None:
        """Cleanly terminate and wait for any running journalctl subprocess."""
        with self._lock:
            proc = self._active_proc
            if proc and proc.poll() is None:
                try:
                    proc.terminate()
                    try:
                        proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=1)
                except Exception:
                    pass
                finally:
                    self._active_proc = None