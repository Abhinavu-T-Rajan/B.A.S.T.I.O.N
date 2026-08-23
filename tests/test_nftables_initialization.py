"""Unit and regression tests for NFTablesBackend initialization and idempotency."""

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from bastion.firewall.base import FirewallError
from bastion.firewall.nftables import NFTablesBackend


def test_nftables_fresh_initialization() -> None:
    backend = NFTablesBackend(table_name="bastion_test")

    with patch.object(backend, "is_available", return_value=True), \
         patch.object(backend, "_table_exists", return_value=False), \
         patch("subprocess.run") as mock_run:

        mock_run.return_value = MagicMock(returncode=0)
        backend.initialize()

        assert mock_run.called
        call_kwargs = mock_run.call_args[1]
        script = call_kwargs["input"]
        assert "add table inet bastion_test" in script
        assert "add set inet bastion_test blacklist_v4 { type ipv4_addr; flags timeout; }" in script
        assert "add set inet bastion_test blacklist_v6 { type ipv6_addr; flags timeout; }" in script
        assert "add chain inet bastion_test input { type filter hook input priority -100; policy accept; }" in script
        assert "add rule inet bastion_test input ip saddr @blacklist_v4 drop" in script
        assert "add rule inet bastion_test input ip6 saddr @blacklist_v6 drop" in script


def test_nftables_repeated_idempotent_initialization() -> None:
    backend = NFTablesBackend(table_name="bastion_test")

    existing_table_output = """
    table inet bastion_test {
        set blacklist_v4 {
            type ipv4_addr
            flags timeout
        }
        set blacklist_v6 {
            type ipv6_addr
            flags timeout
        }
        chain input {
            type filter hook input priority -100; policy accept;
            ip saddr @blacklist_v4 drop
            ip6 saddr @blacklist_v6 drop
        }
    }
    """

    with patch.object(backend, "is_available", return_value=True), \
         patch.object(backend, "_table_exists", return_value=True), \
         patch.object(backend, "_get_table_listing", return_value=existing_table_output), \
         patch("subprocess.run") as mock_run:

        # Repeated initialization when full compatible table exists should be a no-op
        backend.initialize()
        assert not mock_run.called


def test_nftables_reconcile_missing_sets_and_rules() -> None:
    backend = NFTablesBackend(table_name="bastion_test")

    # Table exists with chain but missing v6 set and drop rules
    partial_table_output = """
    table inet bastion_test {
        set blacklist_v4 {
            type ipv4_addr
            flags timeout
        }
        chain input {
            type filter hook input priority -100; policy accept;
        }
    }
    """

    with patch.object(backend, "is_available", return_value=True), \
         patch.object(backend, "_table_exists", return_value=True), \
         patch.object(backend, "_get_table_listing", return_value=partial_table_output), \
         patch("subprocess.run") as mock_run:

        mock_run.return_value = MagicMock(returncode=0)
        backend.initialize()

        assert mock_run.called
        script = mock_run.call_args[1]["input"]
        assert "blacklist_v6" in script
        assert "@blacklist_v4 drop" in script
        assert "@blacklist_v6 drop" in script


def test_nftables_incompatible_chain_declaration_raises_error() -> None:
    backend = NFTablesBackend(table_name="bastion_test")

    # Table exists with incompatible chain (e.g. forward hook instead of input)
    incompatible_table_output = """
    table inet bastion_test {
        chain input {
            type nat hook prerouting priority 0; policy accept;
        }
    }
    """

    with patch.object(backend, "is_available", return_value=True), \
         patch.object(backend, "_table_exists", return_value=True), \
         patch.object(backend, "_get_table_listing", return_value=incompatible_table_output):

        with pytest.raises(FirewallError) as exc:
            backend.initialize()
        assert "Incompatible existing chain 'input'" in str(exc.value)


def test_nftables_ipv4_and_ipv6_block_and_unblock() -> None:
    backend = NFTablesBackend(table_name="bastion_test")

    with patch.object(backend, "is_available", return_value=True), \
         patch.object(backend, "_run_cmd") as mock_cmd:

        mock_cmd.return_value = MagicMock(returncode=0)

        # IPv4 with timeout
        backend.block_ip("192.0.2.10", duration_seconds=600)
        assert mock_cmd.called
        args4 = mock_cmd.call_args[0][0]
        assert "blacklist_v4" in args4
        assert "192.0.2.10 timeout 600s" in args4[-1]

        # IPv6 permanent
        backend.block_ip("2001:db8::1", duration_seconds=None)
        args6 = mock_cmd.call_args[0][0]
        assert "blacklist_v6" in args6
        assert "2001:db8::1" in args6[-1]

        # Unblock IPv4
        backend.unblock_ip("192.0.2.10")
        del_args = mock_cmd.call_args[0][0]
        assert "delete" in del_args
        assert "blacklist_v4" in del_args
