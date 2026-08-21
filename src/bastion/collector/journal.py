from __future__ import annotations

import shutil
import subprocess
from collections.abc import Iterator


class JournalError(RuntimeError):
    # Raised when journald collection cannot be performed.


class JournalCollector:
    #Read Linux authentication messages from systemd-journald.

    def __init__(self, *, unit: str = "sshd.service") -> None:
        self.unit = unit

    def is_available(self) -> bool:
        # Return whether journalctl is available.
        return shutil.which("journalctl") is not None

    def read(self, *, lines: int = 50) -> Iterator[str]:
        # Yield recent journal entries for the configured service.
        if not self.is_available():
            raise JournalError("journalctl is not available on this system")

        if lines <= 0:
            raise ValueError("lines must be greater than zero")

        command = [
            "journalctl",
            "--no-pager",
            "--output=cat",
            "--unit",
            self.unit,
            "--lines",
            str(lines),
        ]

        try:
            result = subprocess.run(
                command,
                check=True,
                capture_output=True,
                text=True,
            )
        except subprocess.CalledProcessError as exc:
            raise JournalError(
                f"journalctl failed with exit code {exc.returncode}"
            ) from exc

        for line in result.stdout.splitlines():
            cleaned = line.strip()

            if cleaned:
                yield cleaned