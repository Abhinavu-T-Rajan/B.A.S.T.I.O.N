from __future__ import annotations

from typing import Any

from bastion.core.contracts.firewall import FirewallProvider
from bastion.core.contracts.storage import StorageProvider
from bastion.models.actors import ThreatActorProfile
from bastion.response.ban_manager import BanManager
from bastion.response.models import BanRecord, BanStatus, ResponseAction
from bastion.timeline.generator import TimelineGenerator


class DefenseAppService:
    """Application service for host defense, IP threat inspection, manual isolation, and firewall operations."""

    def __init__(
        self,
        storage: StorageProvider,
        firewall: FirewallProvider,
    ) -> None:
        self.storage = storage
        self.firewall = firewall
        self.ban_manager = BanManager(storage=self.storage, firewall=self.firewall)
        self.timeline_gen = TimelineGenerator(storage=self.storage)

    def get_status_overview(self, response_mode: str = "DRY_RUN") -> dict[str, Any]:
        """Aggregate high-level defense engine metrics and system state."""
        stats = self.storage.get_stats()
        fw_avail = self.firewall.is_available()
        return {
            "response_mode": response_mode.upper(),
            "firewall_backend": self.firewall.name,
            "firewall_available": fw_avail,
            "total_events": stats.get("total_events", 0),
            "total_detections": stats.get("total_detections", 0),
            "total_threat_actors": stats.get("total_threat_actors", 0),
            "active_threats": stats.get("active_threats", 0),
            "active_bans": stats.get("active_bans", 0),
            "active_iocs": stats.get("active_iocs", 0),
            "open_incidents": stats.get("open_incidents", 0),
        }

    def inspect_ip(self, source_ip: str) -> dict[str, Any]:
        """Fetch threat actor profile, timeline entries, and active ban for an IP."""
        profile = self.storage.get_threat_actor(source_ip)
        timeline = self.timeline_gen.generate_for_ip(source_ip)
        active_ban = self.ban_manager.get_ban_by_ip(source_ip)
        return {
            "profile": profile,
            "timeline": timeline,
            "active_ban": active_ban,
        }

    def list_threats(
        self,
        min_score: int = 0,
        limit: int = 25,
        severity: str | None = None,
    ) -> list[ThreatActorProfile]:
        """List threat actor profiles filtered by minimum score and optional severity."""
        actors = self.storage.list_threat_actors(min_score=min_score, limit=limit)
        if severity:
            sev_clean = severity.lower()
            actors = [a for a in actors if a.severity.value == sev_clean]
        return actors

    def list_bans(self, active_only: bool = True, limit: int = 50) -> list[BanRecord]:
        """List active or historical ban records."""
        return self.storage.list_bans(active_only=active_only, limit=limit)

    def ban_ip(
        self,
        source_ip: str,
        duration_seconds: int = 900,
        permanent: bool = False,
        reason: str = "Manual operator ban",
    ) -> tuple[bool, str, BanRecord | None]:
        """Manually isolate an IP address via the ban manager."""
        action = ResponseAction.PERMANENT_BAN if permanent else ResponseAction.TEMPORARY_ISOLATION
        dur = None if permanent else duration_seconds

        existing = self.ban_manager.get_ban_by_ip(source_ip)
        if existing and existing.status == BanStatus.ACTIVE:
            return True, f"IP {source_ip} is already actively banned (Ban ID: {existing.ban_id})", existing

        ban = self.ban_manager.create_ban(
            source_ip=source_ip,
            reason=reason,
            threat_score=100 if permanent else 85,
            duration_seconds=dur,
            action=action,
            status=BanStatus.ACTIVE,
        )
        return True, f"IP {source_ip} successfully isolated (Ban ID: {ban.ban_id})", ban

    def unban_ip(self, source_ip: str, reason: str = "Operator unban") -> tuple[bool, str]:
        """Manually unban and release an IP address from isolation."""
        success = self.ban_manager.unban(source_ip=source_ip, reason=reason)
        if success:
            return True, f"IP {source_ip} successfully released from isolation"
        return False, f"No active ban found for IP {source_ip}"

    def get_firewall_status(self) -> dict[str, Any]:
        """Query blocked elements in firewall sets."""
        is_avail = self.firewall.is_available()
        blocked_ips = self.firewall.list_blocked_ips() if is_avail else []
        return {
            "backend_name": self.firewall.name,
            "available": is_avail,
            "blocked_count": len(blocked_ips),
            "blocked_ips": blocked_ips,
        }

    def flush_firewall(self) -> tuple[bool, str]:
        """Flush elements from firewall sets."""
        if not self.firewall.is_available():
            return False, f"Firewall backend '{self.firewall.name}' is unavailable"
        self.firewall.flush()
        return True, f"Firewall blacklist rules successfully flushed"
