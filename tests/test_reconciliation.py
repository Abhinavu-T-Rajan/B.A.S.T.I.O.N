"""Unit tests for the FirewallReconciler and ban synchronization."""

import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from bastion.daemon.reconciliation import FirewallReconciler
from bastion.firewall.mock import MockFirewallBackend
from bastion.response.ban_manager import BanManager
from bastion.response.models import BanRecord, BanStatus, ResponseAction
from bastion.storage.sqlite import SQLiteStorage


def test_reconciliation_restores_missing_rules() -> None:
    storage = SQLiteStorage(":memory:")
    firewall = MockFirewallBackend()
    firewall.initialize()
    ban_manager = BanManager(storage=storage, firewall=firewall)

    # Create active ban in storage directly, but simulate missing firewall rule
    now = datetime.now(timezone.utc)
    ban1 = BanRecord(
        ban_id="ban1",
        source_ip="198.51.100.10",
        reason="Brute force",
        threat_score=90,
        created_at=now,
        expires_at=now + timedelta(seconds=600),
        action=ResponseAction.TEMPORARY_ISOLATION,
        status=BanStatus.ACTIVE,
    )
    storage.save_ban(ban1)

    # Firewall currently has NO rules
    assert firewall.list_blocked_ips() == []

    reconciler = FirewallReconciler(
        storage=storage,
        ban_manager=ban_manager,
        firewall=firewall,
    )
    report = reconciler.reconcile()

    assert report.is_healthy is True
    assert "198.51.100.10" in report.restored_bans
    assert report.expected_active_bans == 1
    assert firewall.is_ip_blocked("198.51.100.10") is True


def test_reconciliation_cleans_expired_bans() -> None:
    storage = SQLiteStorage(":memory:")
    firewall = MockFirewallBackend()
    firewall.initialize()
    ban_manager = BanManager(storage=storage, firewall=firewall)

    # Create ban that expired 10 seconds ago
    past = datetime.now(timezone.utc) - timedelta(seconds=10)
    ban_expired = BanRecord(
        ban_id="ban_exp",
        source_ip="198.51.100.99",
        reason="Expired threat",
        threat_score=85,
        created_at=past - timedelta(seconds=900),
        expires_at=past,
        action=ResponseAction.TEMPORARY_ISOLATION,
        status=BanStatus.ACTIVE,
    )
    storage.save_ban(ban_expired)
    firewall.block_ip("198.51.100.99", duration_seconds=1000)

    reconciler = FirewallReconciler(
        storage=storage,
        ban_manager=ban_manager,
        firewall=firewall,
    )
    report = reconciler.reconcile()

    assert report.is_healthy is True
    assert "198.51.100.99" in report.expired_cleaned
    # Check that storage status was updated to EXPIRED
    updated_ban = storage.get_ban("ban_exp")
    assert updated_ban is not None
    assert updated_ban.status == BanStatus.EXPIRED


def test_reconciliation_handles_firewall_unavailable() -> None:
    storage = SQLiteStorage(":memory:")
    firewall = MockFirewallBackend()

    # Mock is_available() returning False
    class UnavailableFirewall(MockFirewallBackend):
        def is_available(self) -> bool:
            return False

    unavail_fw = UnavailableFirewall()
    ban_manager = BanManager(storage=storage, firewall=unavail_fw)

    reconciler = FirewallReconciler(
        storage=storage,
        ban_manager=ban_manager,
        firewall=unavail_fw,
    )
    report = reconciler.reconcile()

    assert report.is_healthy is False
    assert "unavailable" in (report.error_message or "").lower()
