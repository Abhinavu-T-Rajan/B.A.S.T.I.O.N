from __future__ import annotations

from bastion.core.contracts.firewall import FirewallError, FirewallProvider

# Backward compatibility alias
FirewallBackend = FirewallProvider

__all__ = [
    "FirewallError",
    "FirewallProvider",
    "FirewallBackend",
]
