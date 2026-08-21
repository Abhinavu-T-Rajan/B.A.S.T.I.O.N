"""Unit tests for the ResponseEngine execution modes."""

from datetime import datetime, timezone

import pytest

from bastion.firewall.mock import MockFirewallBackend
from bastion.models.actors import ScoreFactor, ThreatActorProfile
from bastion.response.ban_manager import BanManager
from bastion.response.engine import ResponseEngine
from bastion.response.models import BanStatus, ResponseAction, ResponseMode
from bastion.response.policy import PolicyConfig, PolicyEngine
from bastion.storage.sqlite import SQLiteStorage


@pytest.fixture
def response_engine() -> ResponseEngine:
    storage = SQLiteStorage(":memory:")
    firewall = MockFirewallBackend()
    ban_manager = BanManager(storage=storage, firewall=firewall)
    policy = PolicyEngine(PolicyConfig(isolation_threshold=85))
    return ResponseEngine(policy=policy, ban_manager=ban_manager, default_mode=ResponseMode.DRY_RUN)


def make_profile(*, source_ip: str = "198.51.100.23", threat_score: int = 90) -> ThreatActorProfile:
    now = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    return ThreatActorProfile(
        source_ip=source_ip,
        first_seen=now,
        last_seen=now,
        threat_score=threat_score,
        auth_failures=10,
        factors=[ScoreFactor("brute_force", 20, "brute force detected")],
    )


def test_dry_run_mode(response_engine: ResponseEngine) -> None:
    profile = make_profile(threat_score=95)
    decision, ban = response_engine.process(profile, mode_override=ResponseMode.DRY_RUN)

    assert decision.action == ResponseAction.TEMPORARY_ISOLATION
    assert decision.mode == ResponseMode.DRY_RUN
    assert decision.executed is False

    assert ban is not None
    assert ban.status == BanStatus.DRY_RUN
    # Firewall should NOT have blocked IP in dry run
    assert response_engine.ban_manager.firewall.is_ip_blocked("198.51.100.23") is False


def test_automatic_enforcement_mode(response_engine: ResponseEngine) -> None:
    profile = make_profile(threat_score=95)
    decision, ban = response_engine.process(profile, mode_override=ResponseMode.AUTOMATIC)

    assert decision.action == ResponseAction.TEMPORARY_ISOLATION
    assert decision.mode == ResponseMode.AUTOMATIC
    assert decision.executed is True

    assert ban is not None
    assert ban.status == BanStatus.ACTIVE
    # Firewall MUST have blocked IP in automatic mode
    assert response_engine.ban_manager.firewall.is_ip_blocked("198.51.100.23") is True


def test_manual_approval_mode(response_engine: ResponseEngine) -> None:
    profile = make_profile(threat_score=90)
    decision, ban = response_engine.process(profile, mode_override=ResponseMode.MANUAL_APPROVAL)

    assert decision.executed is False
    assert ban is not None
    assert ban.status == BanStatus.PENDING_APPROVAL
    assert response_engine.ban_manager.firewall.is_ip_blocked("198.51.100.23") is False


def test_disabled_mode(response_engine: ResponseEngine) -> None:
    profile = make_profile(threat_score=100)
    decision, ban = response_engine.process(profile, mode_override=ResponseMode.DISABLED)

    assert ban is None
    assert response_engine.ban_manager.firewall.is_ip_blocked("198.51.100.23") is False
