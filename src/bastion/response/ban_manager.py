from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from bastion.firewall.base import FirewallBackend
from bastion.models.actors import ActorState, RecommendedAction, ThreatActorProfile
from bastion.response.models import BanRecord, BanStatus, ResponseAction
from bastion.storage.sqlite import SQLiteStorage


class BanManager:
    """Manages ban lifecycle, state transitions, automatic expiration, and firewall synchronization."""

    def __init__(
        self,
        storage: SQLiteStorage,
        firewall: FirewallBackend,
    ) -> None:
        self.storage = storage
        self.firewall = firewall

    def create_ban(
        self,
        *,
        source_ip: str,
        reason: str,
        threat_score: int,
        duration_seconds: int | None = None,
        action: ResponseAction = ResponseAction.TEMPORARY_ISOLATION,
        status: BanStatus = BanStatus.ACTIVE,
        metadata: dict[str, Any] | None = None,
    ) -> BanRecord:
        """Create and enforce a ban record."""
        now = datetime.now(timezone.utc)
        expires_at = (
            now + timedelta(seconds=duration_seconds)
            if duration_seconds and duration_seconds > 0
            else None
        )

        ban_id = uuid.uuid4().hex[:12]
        record = BanRecord(
            ban_id=ban_id,
            source_ip=source_ip,
            reason=reason,
            threat_score=threat_score,
            created_at=now,
            expires_at=expires_at,
            action=action,
            status=status,
            metadata=metadata or {},
        )

        if status == BanStatus.ACTIVE:
            if self.firewall.is_available():
                self.firewall.block_ip(source_ip, duration_seconds)
            else:
                record.status = BanStatus.FAILED

        self.storage.save_ban(record)

        # Update or create threat actor profile
        profile = self.storage.get_threat_actor(source_ip)
        if profile:
            if record.status == BanStatus.ACTIVE:
                profile.state = ActorState.ISOLATED
            self.storage.upsert_threat_actor(profile)
        else:
            new_profile = ThreatActorProfile(
                source_ip=source_ip,
                first_seen=now,
                last_seen=now,
                threat_score=threat_score,
                state=ActorState.ISOLATED if status == BanStatus.ACTIVE else ActorState.NEUTRAL,
                recommended_action=RecommendedAction(action.value),
            )
            self.storage.upsert_threat_actor(new_profile)

        return record

    def unban(self, source_ip: str, reason: str = "Operator unban") -> bool:
        """Release an active ban and unblock the IP at the firewall."""
        self.firewall.unblock_ip(source_ip)

        active_ban = self.storage.get_ban_by_ip(source_ip)
        if active_ban:
            self.storage.update_ban_status(active_ban.ban_id, BanStatus.UNBANNED)

        profile = self.storage.get_threat_actor(source_ip)
        if profile:
            profile.state = ActorState.RELEASED
            self.storage.upsert_threat_actor(profile)

        return active_ban is not None

    def check_expirations(self) -> list[BanRecord]:
        """Check all active bans and release expired ones."""
        active_bans = self.storage.get_active_bans()
        expired: list[BanRecord] = []

        for ban in active_bans:
            if ban.is_expired:
                self.firewall.unblock_ip(ban.source_ip)
                self.storage.update_ban_status(ban.ban_id, BanStatus.EXPIRED)

                profile = self.storage.get_threat_actor(ban.source_ip)
                if profile:
                    profile.state = ActorState.EXPIRED
                    self.storage.upsert_threat_actor(profile)

                expired.append(ban)

        return expired

    def sync_on_startup(self) -> int:
        """Fail-safe startup recovery: re-synchronize active unexpired bans into the firewall."""
        try:
            self.firewall.initialize()
        except Exception:
            pass

        now = datetime.now(timezone.utc)
        active_bans = self.storage.get_active_bans()
        synced_count = 0

        for ban in active_bans:
            if ban.is_expired:
                self.storage.update_ban_status(ban.ban_id, BanStatus.EXPIRED)
            else:
                remaining: int | None = None
                if ban.expires_at:
                    remaining = max(1, int((ban.expires_at - now).total_seconds()))
                self.firewall.block_ip(ban.source_ip, remaining)
                synced_count += 1

        return synced_count

    def get_active_bans(self) -> list[BanRecord]:
        return self.storage.get_active_bans()

    def get_ban_by_ip(self, source_ip: str) -> BanRecord | None:
        return self.storage.get_ban_by_ip(source_ip)

    def list_bans(
        self,
        status: BanStatus | None = None,
        limit: int = 50,
    ) -> list[BanRecord]:
        return self.storage.list_bans(status=status, limit=limit)
