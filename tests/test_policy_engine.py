"""Unit tests for the PolicyEngine."""

from datetime import datetime, timezone

from bastion.models.actors import ScoreFactor, Severity, ThreatActorProfile
from bastion.response.models import ResponseAction, ResponseMode
from bastion.response.policy import PolicyConfig, PolicyEngine


def make_profile(
    *,
    source_ip: str = "198.51.100.23",
    threat_score: int = 85,
    auth_failures: int = 10,
    factors: list[ScoreFactor] | None = None,
) -> ThreatActorProfile:
    now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    return ThreatActorProfile(
        source_ip=source_ip,
        first_seen=now,
        last_seen=now,
        threat_score=threat_score,
        auth_failures=auth_failures,
        factors=factors or [ScoreFactor("brute_force", 20, "brute-force threshold crossed")],
    )


def test_cidr_allowlist_matching() -> None:
    policy = PolicyEngine(
        PolicyConfig(allowlist_cidrs=["127.0.0.0/8", "10.0.0.0/8", "::1/128"])
    )

    assert policy.is_ip_allowlisted("127.0.0.1") is True
    assert policy.is_ip_allowlisted("127.255.255.255") is True
    assert policy.is_ip_allowlisted("10.50.1.2") is True
    assert policy.is_ip_allowlisted("::1") is True
    assert policy.is_ip_allowlisted("198.51.100.23") is False
    assert policy.is_ip_allowlisted("invalid_ip") is False


def test_policy_allowlist_bypasses_blocking() -> None:
    policy = PolicyEngine(PolicyConfig(allowlist_cidrs=["10.0.0.0/8"]))
    profile = make_profile(source_ip="10.1.2.3", threat_score=100)

    decision = policy.evaluate(profile)
    assert decision.action == ResponseAction.NONE
    assert decision.is_allowlisted is True


def test_temporary_isolation_decision() -> None:
    policy = PolicyEngine(PolicyConfig(isolation_threshold=85, default_ban_duration_seconds=900))
    profile = make_profile(threat_score=88, auth_failures=10)

    decision = policy.evaluate(profile, mode=ResponseMode.DRY_RUN)
    assert decision.action == ResponseAction.TEMPORARY_ISOLATION
    assert decision.threat_score == 88
    assert decision.duration_seconds == 900
    assert decision.mode == ResponseMode.DRY_RUN


def test_repeat_offender_extended_duration() -> None:
    policy = PolicyEngine(
        PolicyConfig(
            isolation_threshold=85,
            default_ban_duration_seconds=900,
            repeat_offender_ban_duration_seconds=3600,
        )
    )
    profile = make_profile(threat_score=90, auth_failures=20)

    decision = policy.evaluate(profile)
    assert decision.action == ResponseAction.TEMPORARY_ISOLATION
    assert decision.duration_seconds == 3600


def test_permanent_ban_for_extreme_offender() -> None:
    policy = PolicyEngine()
    profile = make_profile(threat_score=100, auth_failures=35)

    decision = policy.evaluate(profile)
    assert decision.action == ResponseAction.PERMANENT_BAN
    assert decision.duration_seconds is None


def test_rate_limit_and_monitor_decisions() -> None:
    policy = PolicyEngine(PolicyConfig(isolation_threshold=85, rate_limit_threshold=60))

    # Score 65 -> Rate limit
    dec_rl = policy.evaluate(make_profile(threat_score=65))
    assert dec_rl.action == ResponseAction.RATE_LIMIT

    # Score 30 -> Monitor
    dec_mon = policy.evaluate(make_profile(threat_score=30, auth_failures=2))
    assert dec_mon.action == ResponseAction.MONITOR
