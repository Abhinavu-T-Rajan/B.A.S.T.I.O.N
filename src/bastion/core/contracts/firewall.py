from __future__ import annotations

from abc import ABC, abstractmethod


class FirewallError(RuntimeError):
    """Base exception for packet filtering and firewall operations."""


class FirewallProvider(ABC):
    """Abstract base interface for host packet filtering and isolation backends."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the unique identifier of the firewall backend."""
        ...

    @abstractmethod
    def is_available(self) -> bool:
        """Return True if the underlying firewall subsystem is operational."""
        ...

    @abstractmethod
    def initialize(self) -> None:
        """Idempotently configure tables, chains, and blacklist sets."""
        ...

    @abstractmethod
    def block_ip(self, ip: str, duration_seconds: int | None = None) -> bool:
        """Add an IP address to the blacklist with optional timeout."""
        ...

    @abstractmethod
    def unblock_ip(self, ip: str) -> bool:
        """Remove an IP address from the blacklist."""
        ...

    @abstractmethod
    def list_blocked_ips(self) -> list[str]:
        """Return a list of currently isolated IP addresses."""
        ...

    @abstractmethod
    def is_ip_blocked(self, ip: str) -> bool:
        """Return True if an IP is currently in the blacklist."""
        ...

    @abstractmethod
    def flush(self) -> None:
        """Flush all isolated IPs from the dedicated table sets."""
        ...
