from __future__ import annotations

import time
from typing import Any

from bastion.firewall.base import FirewallBackend


class MockFirewallBackend(FirewallBackend):
    """In-memory firewall backend for testing, dry runs, and non-root execution."""

    def __init__(self) -> None:
        self.initialized = False
        self._blocked: dict[str, float | None] = {}  # ip -> expiry timestamp (or None)

    @property
    def name(self) -> str:
        return "mock"

    def is_available(self) -> bool:
        return True

    def initialize(self) -> None:
        self.initialized = True

    def block_ip(self, ip: str, duration_seconds: int | None = None) -> bool:
        expiry = (time.time() + duration_seconds) if duration_seconds else None
        self._blocked[ip] = expiry
        return True

    def unblock_ip(self, ip: str) -> bool:
        if ip in self._blocked:
            del self._blocked[ip]
            return True
        return False

    def list_blocked_ips(self) -> list[str]:
        now = time.time()
        # Filter out expired IPs
        active: list[str] = []
        for ip, expiry in list(self._blocked.items()):
            if expiry is not None and expiry < now:
                del self._blocked[ip]
            else:
                active.append(ip)
        return active

    def is_ip_blocked(self, ip: str) -> bool:
        return ip in self.list_blocked_ips()

    def flush(self) -> None:
        self._blocked.clear()
