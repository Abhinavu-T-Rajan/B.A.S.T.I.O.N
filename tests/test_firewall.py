"""Unit tests for the Firewall Abstraction layer."""

import subprocess
import time
from unittest.mock import MagicMock, patch

import pytest

from bastion.firewall.base import FirewallError
from bastion.firewall.mock import MockFirewallBackend
from bastion.firewall.nftables import NFTablesBackend


def test_mock_firewall_lifecycle() -> None:
    fw = MockFirewallBackend()
    assert fw.name == "mock"
    assert fw.is_available() is True

    fw.initialize()
    assert fw.initialized is True

    # Block IP with 10s duration
    assert fw.block_ip("198.51.100.23", duration_seconds=10) is True
    assert fw.is_ip_blocked("198.51.100.23") is True
    assert "198.51.100.23" in fw.list_blocked_ips()

    # Block another permanently
    assert fw.block_ip("203.0.113.5", duration_seconds=None) is True
    assert len(fw.list_blocked_ips()) == 2

    # Unblock IP
    assert fw.unblock_ip("198.51.100.23") is True
    assert fw.is_ip_blocked("198.51.100.23") is False
    assert fw.unblock_ip("198.51.100.23") is False

    # Flush
    fw.flush()
    assert len(fw.list_blocked_ips()) == 0


def test_mock_firewall_expiry() -> None:
    fw = MockFirewallBackend()
    # Expired 1 second in the past
    fw._blocked["192.0.2.1"] = time.time() - 1

    assert fw.is_ip_blocked("192.0.2.1") is False
    assert "192.0.2.1" not in fw.list_blocked_ips()


def test_nftables_backend_availability() -> None:
    with patch("shutil.which", return_value="/usr/sbin/nft"):
        nft = NFTablesBackend()
        assert nft.is_available() is True

    with patch("shutil.which", return_value=None):
        nft = NFTablesBackend()
        assert nft.is_available() is False


def test_nftables_backend_initialize() -> None:
    nft = NFTablesBackend(table_name="test_bastion")

    with patch("shutil.which", return_value="/usr/sbin/nft"), patch(
        "subprocess.run"
    ) as mock_run:
        nft.initialize()
        assert mock_run.called
        cmd = mock_run.call_args[0][0]
        assert "nft" in cmd
        script = mock_run.call_args[1]["input"]
        assert "add table inet test_bastion" in script
        assert "add set inet test_bastion blacklist_v4" in script


def test_nftables_block_and_unblock_ipv4() -> None:
    nft = NFTablesBackend(table_name="bastion")

    with patch("shutil.which", return_value="/usr/sbin/nft"), patch(
        "subprocess.run"
    ) as mock_run:
        # Block with 900s timeout
        nft.block_ip("198.51.100.23", duration_seconds=900)
        args = mock_run.call_args[0][0]
        assert "blacklist_v4" in args
        assert "{ 198.51.100.23 timeout 900s }" in args

        # Block IPv6
        nft.block_ip("2001:db8::1", duration_seconds=600)
        args6 = mock_run.call_args[0][0]
        assert "blacklist_v6" in args6
        assert "{ 2001:db8::1 timeout 600s }" in args6

        # Unblock IPv4
        nft.unblock_ip("198.51.100.23")
        args_del = mock_run.call_args[0][0]
        assert "delete" in args_del
        assert "blacklist_v4" in args_del


def test_nftables_error_handling() -> None:
    nft = NFTablesBackend()
    with patch("shutil.which", return_value="/usr/sbin/nft"), patch(
        "subprocess.run",
        side_effect=subprocess.CalledProcessError(
            returncode=1, cmd=["nft"], stderr="Permission denied"
        ),
    ):
        with pytest.raises(FirewallError, match="Permission denied"):
            nft.block_ip("1.2.3.4")
