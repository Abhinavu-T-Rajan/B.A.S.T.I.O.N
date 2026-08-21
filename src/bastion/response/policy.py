from __future__ import annotations

import ipaddress
from collections.abc import Sequence
from dataclasses import dataclass, field

from bastion.models.actors import ThreatActorProfile
from bastion.response.models import ResponseAction, ResponseDecision, ResponseMode


@dataclass(slots=True)
class PolicyConfig:
    """Policy thresholds and safety controls."""

    isolation_threshold: int = 85
    rate_limit_threshold: int = 60
    default_ban_duration_seconds: int = 900  # 15 minutes
    repeat_offender_ban_duration_seconds: int = 3600  # 1 hour
    max_ban_duration_seconds: int = 86400  # 24 hours
    allowlist_cidrs: list[str] = field(
        default_factory=lambda: [
            "127.0.0.0/8",
            "::1/128",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
        ]
    )


class PolicyEngine:
    """Evaluates threat profiles against safety rules and determines defensive actions."""

    def __init__(self, config: PolicyConfig | None = None) -> None:
        self.config = config or PolicyConfig()
        self._parsed_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for cidr in self.config.allowlist_cidrs:
            try:
                self._parsed_networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                pass

    def is_ip_allowlisted(self, ip_str: str) -> bool:
        """Check if an IP address belongs to any configured allowlisted CIDR block."""
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            return any(ip_obj in net for net in self._parsed_networks)
        except ValueError:
            return False

    def evaluate(
        self,
        profile: ThreatActorProfile,
        mode: ResponseMode = ResponseMode.DRY_RUN,
    ) -> ResponseDecision:
        """Derive an enforceable response decision from a threat profile."""
        source_ip = profile.source_ip
        score = profile.threat_score

        # 1. Safety Check: Allowlist Protection
        if self.is_ip_allowlisted(source_ip):
            return ResponseDecision(
                source_ip=source_ip,
                action=ResponseAction.NONE,
                threat_score=score,
                reason="IP is within allowlisted CIDR management range",
                is_allowlisted=True,
                mode=mode,
            )

        # Build explainable rationale summary
        factor_reasons = [f.description for f in profile.factors if f.score_delta > 0]
        reason_summary = "; ".join(factor_reasons) if factor_reasons else "Score threshold crossed"

        # 2. Permanent Ban check for extreme repeated attacks
        if score >= 100 and profile.auth_failures >= 30:
            return ResponseDecision(
                source_ip=source_ip,
                action=ResponseAction.PERMANENT_BAN,
                threat_score=score,
                reason=f"Severe persistent offender: {reason_summary}",
                duration_seconds=None,
                mode=mode,
            )

        # 3. Temporary Isolation check
        if score >= self.config.isolation_threshold:
            duration = (
                self.config.repeat_offender_ban_duration_seconds
                if profile.auth_failures >= 15
                else self.config.default_ban_duration_seconds
            )
            duration = min(duration, self.config.max_ban_duration_seconds)

            return ResponseDecision(
                source_ip=source_ip,
                action=ResponseAction.TEMPORARY_ISOLATION,
                threat_score=score,
                reason=f"Critical threat score ({score}/100): {reason_summary}",
                duration_seconds=duration,
                mode=mode,
            )

        # 4. Rate Limiting check
        if score >= self.config.rate_limit_threshold:
            return ResponseDecision(
                source_ip=source_ip,
                action=ResponseAction.RATE_LIMIT,
                threat_score=score,
                reason=f"High risk score ({score}/100): {reason_summary}",
                duration_seconds=self.config.default_ban_duration_seconds,
                mode=mode,
            )

        # 5. Monitoring
        if profile.auth_failures > 0:
            return ResponseDecision(
                source_ip=source_ip,
                action=ResponseAction.MONITOR,
                threat_score=score,
                reason=f"Suspicious activity ({score}/100): {reason_summary}",
                mode=mode,
            )

        return ResponseDecision(
            source_ip=source_ip,
            action=ResponseAction.NONE,
            threat_score=score,
            reason="Normal host activity",
            mode=mode,
        )
