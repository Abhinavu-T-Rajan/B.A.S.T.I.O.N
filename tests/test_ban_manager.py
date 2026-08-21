"""Unit tests for BanManager lifecycle and synchronization."""

from datetime import datetime, timedelta, timezone

import pytest

from bastion.firewall.mock import MockFirewallBackend
from bastion.models.actors import ActorState, ThreatActorProfile
from bastion.response.ban_manager import BanManager
from bastion.response.models import BanStatus, ResponseAction
from bastion.storage.sqlite import SQLiteStorage


@pytest.fixture
def ban_manager() -> BanManager:
    storage = SQLiteStorage(":memory:")
    firewall = MockFirewallBackend()
    return BanManager(storage=storage, firewall=firewall)


def test_create_and_enforce_ban(ban_manager: BanManager) -> None:
    # Setup initial profile
    profile = ThreatActorProfile(
        source_ip="198.51.100.23",
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
        threat_score=90,
    )
    ban_manager.storage.upsert_threat_actor(profile)

    ban = ban_manager.create_ban(
        source_ip="198.51.100.23",
        reason="Brute force attack",
        threat_score=90,
        duration_seconds=900,
        status=BanStatus.ACTIVE,
    )

    assert ban.ban_id is not None
    assert ban.source_ip == "198.51.100.23"
    assert ban.status == BanStatus.ACTIVE
    assert ban.expires_at is not None

    # Check firewall state
    assert ban_manager.firewall.is_ip_blocked("198.51.100.23") is True

    # Check actor state transition to ISOLATED
    updated_profile = ban_manager.storage.get_threat_actor("198.51.100.23")
    assert updated_profile is not None
    assert updated_profile.state == ActorState.ISOLATED


def test_unban_lifecycle(ban_manager: BanManager) -> None:
    ban_manager.create_ban(
        source_ip="198.51.100.23",
        reason="Test",
        threat_score=90,
        status=BanStatus.ACTIVE,
    )
    assert ban_manager.firewall.is_ip_blocked("198.51.100.23") is True

    success = ban_manager.unban("198.51.100.23")
    assert success is True
    assert ban_manager.firewall.is_ip_blocked("198.51.100.23") is False

    active = ban_manager.get_active_bans()
    assert len(active) == 0


def test_check_expirations(ban_manager: BanManager) -> None:
    # Create an expired ban (10 seconds ago)
    now = datetime.now(timezone.utc)
    ban = ban_manager.create_ban(
        source_ip="192.0.2.88",
        reason="Expired test",
        threat_score=85,
        duration_seconds=10,
        status=BanStatus.ACTIVE,
    )
    # Manually backdate expiration in SQLite
    ban.expires_at = now - timedelta(seconds=1)
    ban_manager.storage.save_ban(ban)

    expired = ban_manager.check_expirations()
    assert len(expired) == 1
    assert expired[0].source_ip == "192.0.2.88"
    assert ban_manager.firewall.is_ip_blocked("192.0.2.88") is False


def test_sync_on_startup(ban_manager: BanManager) -> None:
    # Create active ban in storage
    ban_manager.create_ban(
        source_ip="192.0.2.99",
        reason="Startup sync test",
        threat_score=95,
        duration_seconds=600,
        status=BanStatus.ACTIVE,
    )
    # Simulate firewall wipe / restart
    ban_manager.firewall.flush()
    assert ban_manager.firewall.is_ip_blocked("192.0.2.99") is False

    # Run startup recovery sync
    restored = ban_manager.sync_on_startup()
    assert restored == 1
    assert ban_manager.firewall.is_ip_blocked("192.0.2.99") is True
