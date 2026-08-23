from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from bastion.firewall.base import FirewallBackend, FirewallError
from bastion.response.ban_manager import BanManager
from bastion.response.models import BanRecord, BanStatus
from bastion.storage.sqlite import SQLiteStorage


@dataclass(slots=True)
class ReconciliationReport:
    """Detailed report resulting from firewall and ban state reconciliation."""

    timestamp: datetime
    backend_name: str
    expected_active_bans: int
    firewall_blocked_ips: int
    restored_bans: list[str] = field(default_factory=list)
    expired_cleaned: list[str] = field(default_factory=list)
    mismatches_found: int = 0
    is_healthy: bool = True
    error_message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "backend_name": self.backend_name,
            "expected_active_bans": self.expected_active_bans,
            "firewall_blocked_ips": self.firewall_blocked_ips,
            "restored_bans": self.restored_bans,
            "expired_cleaned": self.expired_cleaned,
            "mismatches_found": self.mismatches_found,
            "is_healthy": self.is_healthy,
            "error_message": self.error_message,
        }


class FirewallReconciler:
    """State synchronization engine reconciling persisted SQLite active bans with live firewall rules."""

    def __init__(
        self,
        *,
        storage: SQLiteStorage,
        ban_manager: BanManager,
        firewall: FirewallBackend,
    ) -> None:
        self.storage = storage
        self.ban_manager = ban_manager
        self.firewall = firewall

    def reconcile(self) -> ReconciliationReport:
        """Perform full bidirectional verification between DB bans and firewall packet filtering rules."""
        now = datetime.now(timezone.utc)

        # 1. Check firewall availability
        if not self.firewall.is_available():
            return ReconciliationReport(
                timestamp=now,
                backend_name=self.firewall.name,
                expected_active_bans=0,
                firewall_blocked_ips=0,
                is_healthy=False,
                error_message=f"Firewall backend '{self.firewall.name}' is unavailable",
            )

        try:
            # 2. Expire past bans in storage & unblock
            expired_records = self.ban_manager.check_expirations()
            expired_ips = [b.source_ip for b in expired_records]

            # 3. Retrieve live firewall blocked IPs
            firewall_ips = set(self.firewall.list_blocked_ips())

            # 4. Retrieve active unexpired bans from storage
            active_bans = self.storage.get_active_bans()
            expected_ips = {b.source_ip: b for b in active_bans if not b.is_expired}

            restored: list[str] = []
            mismatches = 0

            # 5. Check for missing rules (expected in DB but missing from firewall)
            for ip, ban in expected_ips.items():
                if ip not in firewall_ips:
                    remaining: int | None = None
                    if ban.expires_at:
                        remaining = max(1, int((ban.expires_at - now).total_seconds()))
                    self.firewall.block_ip(ip, remaining)
                    restored.append(ip)
                    mismatches += 1

            # 6. Check for lingering unmanaged rules in firewall that are not in DB
            for ip in firewall_ips:
                if ip not in expected_ips:
                    mismatches += 1

            return ReconciliationReport(
                timestamp=now,
                backend_name=self.firewall.name,
                expected_active_bans=len(expected_ips),
                firewall_blocked_ips=len(firewall_ips),
                restored_bans=restored,
                expired_cleaned=expired_ips,
                mismatches_found=mismatches,
                is_healthy=True,
            )

        except Exception as exc:
            return ReconciliationReport(
                timestamp=now,
                backend_name=self.firewall.name,
                expected_active_bans=0,
                firewall_blocked_ips=0,
                is_healthy=False,
                error_message=str(exc),
            )
