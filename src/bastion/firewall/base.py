from __future__ import annotations

from abc import ABC, abstractmethod


class FirewallError(RuntimeError):
    """Raised when firewall operations fail."""


class FirewallBackend(ABC):
    """Abstract interface for host packet filtering and blocking."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the firewall backend."""

    @abstractmethod
    def is_available(self) -> bool:
        """Check if the firewall subsystem is available on this host."""

    @abstractmethod
    def initialize(self) -> None:
        """Create required tables, chains, and sets."""

    @abstractmethod
    def block_ip(self, ip: str, duration_seconds: int | None = None) -> bool:
        """Add an IP address to the blacklist with optional timeout."""

    @abstractmethod
    def unblock_ip(self, ip: str) -> bool:
        """Remove an IP address from the blacklist."""

    @abstractmethod
    def list_blocked_ips(self) -> list[str]:
        """Return all currently blocked IP addresses."""

    @abstractmethod
    def is_ip_blocked(self, ip: str) -> bool:
        """Return whether an IP is currently blocked."""

    @abstractmethod
    def flush(self) -> None:
        """Remove all bastion firewall rules and clear blacklists."""
