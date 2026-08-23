from __future__ import annotations

import ipaddress
import json
import shutil
import subprocess
from typing import Any

from bastion.firewall.base import FirewallBackend, FirewallError


class NFTablesBackend(FirewallBackend):
    """Linux nftables packet filtering backend operating in dedicated 'inet bastion' table."""

    DEFAULT_PRIORITY = -100

    def __init__(self, *, table_name: str = "bastion") -> None:
        self.table_name = table_name

    @property
    def name(self) -> str:
        return "nftables"

    def is_available(self) -> bool:
        """Return True if the nft CLI tool is installed."""
        return shutil.which("nft") is not None

    def _run_cmd(self, args: list[str]) -> subprocess.CompletedProcess[str]:
        """Execute an nft command with error wrapping."""
        if not self.is_available():
            raise FirewallError("nft utility is not installed or available in PATH")

        cmd = ["nft"] + args
        try:
            return subprocess.run(
                cmd,
                check=True,
                capture_output=True,
                text=True,
            )
        except subprocess.CalledProcessError as exc:
            err_msg = exc.stderr.strip() or f"exit code {exc.returncode}"
            raise FirewallError(f"nftables command failed ({' '.join(cmd)}): {err_msg}") from exc

    def _table_exists(self) -> bool:
        """Check if table inet <table_name> exists."""
        try:
            res = self._run_cmd(["list", "table", "inet", self.table_name])
            return res.returncode == 0
        except FirewallError:
            return False

    def _get_table_listing(self) -> str:
        """Return raw text listing of the table or empty string if not existing."""
        try:
            res = self._run_cmd(["list", "table", "inet", self.table_name])
            return res.stdout
        except FirewallError:
            return ""

    def initialize(self) -> None:
        """Create or safely reconcile dedicated bastion table, sets with timeout flags, and early drop rules."""
        if not self.is_available():
            raise FirewallError("nft utility is not installed on this system")

        if not self._table_exists():
            # 1. Fresh system: initialize table, sets, chain, and drop rules in one batch
            script = (
                f"add table inet {self.table_name}\n"
                f"add set inet {self.table_name} blacklist_v4 {{ type ipv4_addr; flags timeout; }}\n"
                f"add set inet {self.table_name} blacklist_v6 {{ type ipv6_addr; flags timeout; }}\n"
                f"add chain inet {self.table_name} input {{ type filter hook input priority {self.DEFAULT_PRIORITY}; policy accept; }}\n"
                f"add rule inet {self.table_name} input ip saddr @blacklist_v4 drop\n"
                f"add rule inet {self.table_name} input ip6 saddr @blacklist_v6 drop\n"
            )
            try:
                subprocess.run(
                    ["nft", "-f", "-"],
                    input=script,
                    text=True,
                    check=True,
                    capture_output=True,
                )
                return
            except subprocess.CalledProcessError as exc:
                raise FirewallError(
                    f"Failed to initialize nftables table '{self.table_name}': {exc.stderr.strip()}"
                ) from exc

        # 2. Table already exists: inspect and reconcile incrementally without destructive re-declarations
        table_content = self._get_table_listing()

        commands: list[str] = []

        # Reconcile sets
        if "set blacklist_v4" not in table_content:
            commands.append(f"add set inet {self.table_name} blacklist_v4 {{ type ipv4_addr; flags timeout; }}")
        if "set blacklist_v6" not in table_content:
            commands.append(f"add set inet {self.table_name} blacklist_v6 {{ type ipv6_addr; flags timeout; }}")

        # Reconcile chain
        if "chain input" not in table_content:
            commands.append(f"add chain inet {self.table_name} input {{ type filter hook input priority {self.DEFAULT_PRIORITY}; policy accept; }}")
        else:
            # Verify compatible hook type if chain is present
            if "hook input" not in table_content and "type filter" not in table_content:
                raise FirewallError(
                    f"Incompatible existing chain 'input' detected in table inet '{self.table_name}'. "
                    f"Expected 'type filter hook input', but found incompatible declaration."
                )

        # Reconcile drop rules
        if "@blacklist_v4 drop" not in table_content:
            commands.append(f"add rule inet {self.table_name} input ip saddr @blacklist_v4 drop")
        if "@blacklist_v6 drop" not in table_content:
            commands.append(f"add rule inet {self.table_name} input ip6 saddr @blacklist_v6 drop")

        if commands:
            script = "\n".join(commands) + "\n"
            try:
                subprocess.run(
                    ["nft", "-f", "-"],
                    input=script,
                    text=True,
                    check=True,
                    capture_output=True,
                )
            except subprocess.CalledProcessError as exc:
                raise FirewallError(
                    f"Failed to reconcile nftables table '{self.table_name}': {exc.stderr.strip()}"
                ) from exc

    def _is_ipv6(self, ip: str) -> bool:
        try:
            return isinstance(ipaddress.ip_address(ip), ipaddress.IPv6Address)
        except ValueError:
            return False

    def block_ip(self, ip: str, duration_seconds: int | None = None) -> bool:
        """Add an IP to the blacklist set with optional timeout."""
        set_name = "blacklist_v6" if self._is_ipv6(ip) else "blacklist_v4"
        if duration_seconds and duration_seconds > 0:
            element_expr = f"{ip} timeout {duration_seconds}s"
        else:
            element_expr = f"{ip}"

        self._run_cmd(["add", "element", "inet", self.table_name, set_name, f"{{ {element_expr} }}"])
        return True

    def unblock_ip(self, ip: str) -> bool:
        """Remove an IP from the blacklist set."""
        set_name = "blacklist_v6" if self._is_ipv6(ip) else "blacklist_v4"
        try:
            self._run_cmd(["delete", "element", "inet", self.table_name, set_name, f"{{ {ip} }}"])
            return True
        except FirewallError:
            return False

    def list_blocked_ips(self) -> list[str]:
        """Query elements in both v4 and v6 blacklist sets."""
        if not self.is_available():
            return []

        blocked: list[str] = []
        for set_name in ("blacklist_v4", "blacklist_v6"):
            try:
                res = self._run_cmd(["-j", "list", "set", "inet", self.table_name, set_name])
                data = json.loads(res.stdout)
                for item in data.get("nftables", []):
                    elem_list = item.get("set", {}).get("elem", [])
                    for elem in elem_list:
                        if isinstance(elem, str):
                            blocked.append(elem)
                        elif isinstance(elem, dict) and "elem" in elem:
                            val = elem["elem"].get("val")
                            if val:
                                blocked.append(str(val))
            except (FirewallError, json.JSONDecodeError):
                # Fallback to standard textual parsing if JSON mode is unavailable
                try:
                    res = self._run_cmd(["list", "set", "inet", self.table_name, set_name])
                    for line in res.stdout.splitlines():
                        cleaned = line.strip().strip(",;")
                        if cleaned and not cleaned.startswith(("{", "}", "type", "flags", "table", "set", "elements")):
                            ip_part = cleaned.split()[0]
                            try:
                                ipaddress.ip_address(ip_part)
                                blocked.append(ip_part)
                            except ValueError:
                                pass
                except FirewallError:
                    pass

        return blocked

    def is_ip_blocked(self, ip: str) -> bool:
        """Check if an IP is currently blocked."""
        return ip in self.list_blocked_ips()

    def flush(self) -> None:
        """Flush elements from both blacklist sets."""
        if not self.is_available():
            return
        try:
            self._run_cmd(["flush", "table", "inet", self.table_name])
        except FirewallError:
            pass
