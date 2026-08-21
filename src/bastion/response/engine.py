from __future__ import annotations

from dataclasses import replace
from typing import Any

from bastion.models.actors import ThreatActorProfile
from bastion.response.ban_manager import BanManager
from bastion.response.models import (
    BanRecord,
    BanStatus,
    ResponseAction,
    ResponseDecision,
    ResponseMode,
)
from bastion.response.policy import PolicyEngine


class ResponseEngine:
    """Orchestrates defensive response execution, safety checks, and ban management."""

    def __init__(
        self,
        *,
        policy: PolicyEngine,
        ban_manager: BanManager,
        default_mode: ResponseMode = ResponseMode.DRY_RUN,
    ) -> None:
        self.policy = policy
        self.ban_manager = ban_manager
        self.default_mode = default_mode

    def process(
        self,
        profile: ThreatActorProfile,
        mode_override: ResponseMode | None = None,
    ) -> tuple[ResponseDecision, BanRecord | None]:
        """Evaluate policy and execute or simulate the defensive response."""
        mode = mode_override or self.default_mode
        decision = self.policy.evaluate(profile, mode=mode)

        if decision.action not in {
            ResponseAction.TEMPORARY_ISOLATION,
            ResponseAction.PERMANENT_BAN,
        }:
            return decision, None

        if decision.is_allowlisted or mode == ResponseMode.DISABLED:
            return decision, None

        # Check if already actively banned
        existing_ban = self.ban_manager.get_ban_by_ip(profile.source_ip)
        if existing_ban and existing_ban.status == BanStatus.ACTIVE:
            return decision, existing_ban

        ban_record: BanRecord | None = None

        if mode == ResponseMode.AUTOMATIC:
            ban_record = self.ban_manager.create_ban(
                source_ip=profile.source_ip,
                reason=decision.reason,
                threat_score=decision.threat_score,
                duration_seconds=decision.duration_seconds,
                action=decision.action,
                status=BanStatus.ACTIVE,
            )
            decision = replace(decision, executed=True)

        elif mode == ResponseMode.DRY_RUN:
            ban_record = self.ban_manager.create_ban(
                source_ip=profile.source_ip,
                reason=decision.reason,
                threat_score=decision.threat_score,
                duration_seconds=decision.duration_seconds,
                action=decision.action,
                status=BanStatus.DRY_RUN,
            )
            decision = replace(decision, executed=False)

        elif mode == ResponseMode.MANUAL_APPROVAL:
            ban_record = self.ban_manager.create_ban(
                source_ip=profile.source_ip,
                reason=decision.reason,
                threat_score=decision.threat_score,
                duration_seconds=decision.duration_seconds,
                action=decision.action,
                status=BanStatus.PENDING_APPROVAL,
            )
            decision = replace(decision, executed=False)

        return decision, ban_record
