from __future__ import annotations

import shutil
import subprocess
import threading
from collections.abc import Iterator
from datetime import datetime, timezone
from typing import Sequence

from bastion.core.contracts.collector import CollectorProvider
from bastion.core.models.telemetry import RawTelemetry


class JournaldCollectorError(RuntimeError):
    """Raised when journald collection cannot be performed."""


class JournaldCollector(CollectorProvider):
    """Reads Linux authentication telemetry from systemd-journald into RawTelemetry."""

    DEFAULT_UNITS = ("ssh.service", "sshd.service")

    def __init__(
        self,
        *,
        units: str | Sequence[str] = DEFAULT_UNITS,
        identifiers: str | Sequence[str] | None = None,
    ) -> None:
        self.name = "journald"
        if isinstance(units, str):
            self.units = [units]
        else:
            self.units = list(units)

        if isinstance(identifiers, str):
            self.identifiers = [identifiers]
        elif identifiers is not None:
            self.identifiers = list(identifiers)
        else:
            self.identifiers = []

        self._lock = threading.Lock()
        self._active_proc: subprocess.Popen[str] | None = None

    @property
    def identifier(self) -> str | None:
        """Backward compatibility property returning first identifier or None."""
        return self.identifiers[0] if self.identifiers else None

    @classmethod
    def is_available(cls) -> bool:
        """Return whether journalctl is installed and executable."""
        return shutil.which("journalctl") is not None

    def _build_base_command(self) -> list[str]:
        """Construct common journalctl command arguments."""
        cmd = ["journalctl", "--no-pager", "--output=cat"]
        for unit in self.units:
            cmd.extend(["--unit", unit])
        for ident in self.identifiers:
            cmd.extend(["--identifier", ident])
        return cmd

    def read(self, limit: int = 50, since: str | None = None) -> Iterator[RawTelemetry]:
        """Yield recent journal entries as RawTelemetry records."""
        if not self.is_available():
            raise JournaldCollectorError("journalctl is not available on this system")

        if limit <= 0:
            raise ValueError("limit must be greater than zero")

        command = self._build_base_command()
        command.extend(["--lines", str(limit)])
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
            raise JournaldCollectorError(
                f"journalctl failed with exit code {exc.returncode}: {exc.stderr.strip()}"
            ) from exc

        now = datetime.now(timezone.utc)
        for line in result.stdout.splitlines():
            cleaned = line.strip()
            if cleaned:
                yield RawTelemetry(
                    raw_message=cleaned,
                    source="journald",
                    timestamp=now,
                    transport="unix_socket",
                    unit=self.units[0] if self.units else None,
                    identifier=self.identifiers[0] if self.identifiers else None,
                )

    def stream(self, lines: int = 10, since: str | None = None) -> Iterator[RawTelemetry]:
        """Continuously stream journal entries as RawTelemetry records in real-time."""
        if not self.is_available():
            raise JournaldCollectorError("journalctl is not available on this system")

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
                raise JournaldCollectorError("Failed to open journalctl standard output stream")

            for raw_line in proc.stdout:
                cleaned = raw_line.strip()
                if cleaned:
                    yield RawTelemetry(
                        raw_message=cleaned,
                        source="journald",
                        timestamp=datetime.now(timezone.utc),
                        transport="unix_socket",
                        unit=self.units[0] if self.units else None,
                        identifier=self.identifiers[0] if self.identifiers else None,
                    )

        except Exception as exc:
            if proc and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
            if isinstance(exc, JournaldCollectorError):
                raise
            raise JournaldCollectorError(f"journal stream failed: {exc}") from exc
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
