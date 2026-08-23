"""Telemetry normalizer adapters for B.A.S.T.I.O.N."""

from bastion.infrastructure.telemetry.adapters.composite import CompositeEventNormalizer
from bastion.infrastructure.telemetry.adapters.ssh import SSHLogAdapter

__all__ = [
    "SSHLogAdapter",
    "CompositeEventNormalizer",
]
