"""Unit tests for the Experimental Response Framework and response auditing."""

from bastion.firewall.mock import MockFirewallBackend
from bastion.response.audit import ResponseAuditRecord
from bastion.response.experimental import ExperimentalResponseCoordinator
from bastion.storage.sqlite import SQLiteStorage


def test_experimental_response_block_ip_validation() -> None:
    storage = SQLiteStorage(":memory:")
    fw = MockFirewallBackend()
    coordinator = ExperimentalResponseCoordinator(storage=storage, firewall=fw)

    # Valid IP in dry run
    res = coordinator.block_ip("198.51.100.23", duration_seconds=600, dry_run=True)
    assert res.success is True
    assert res.dry_run is True
    assert "198.51.100.23" not in fw.list_blocked_ips()  # Dry run must not touch firewall!

    # Valid IP in enforce mode
    res_enforce = coordinator.block_ip("198.51.100.23", duration_seconds=600, dry_run=False)
    assert res_enforce.success is True
    assert res_enforce.dry_run is False
    assert "198.51.100.23" in fw.list_blocked_ips()  # Enforced must touch firewall!

    # Invalid IP
    res_bad = coordinator.block_ip("not_an_ip")
    assert res_bad.success is False
    assert "Invalid target IP" in res_bad.message


def test_experimental_response_account_and_session_hooks() -> None:
    storage = SQLiteStorage(":memory:")
    coordinator = ExperimentalResponseCoordinator(storage=storage)

    # Valid account containment
    res_acct = coordinator.contain_account("compromised_dev", dry_run=True, reason="Abuse detected")
    assert res_acct.success is True

    # Invalid account name
    res_bad_acct = coordinator.contain_account("invalid user with spaces & symbols!")
    assert res_bad_acct.success is False

    # Valid session termination
    res_sess = coordinator.terminate_session("pts/2_ssh_session_9921", dry_run=True)
    assert res_sess.success is True

    # Check that audit log entries were saved in storage
    audits = storage.list_response_audits()
    assert len(audits) >= 2
