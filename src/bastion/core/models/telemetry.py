from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True, slots=True)
class RawTelemetry:
    """Unnormalized telemetry record captured directly from a system source."""

    raw_message: str
    source: str  # "journald", "stdin", "file", "syslog"
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    transport: str = "pipe"  # "unix_socket", "pipe", "file_io"
    unit: str | None = None  # e.g. "ssh.service", "sshd.service"
    identifier: str | None = None  # e.g. "sshd", "sshd-session", "sshd-auth"
    pid: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
