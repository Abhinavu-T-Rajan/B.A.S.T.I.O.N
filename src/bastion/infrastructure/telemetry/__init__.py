"""Telemetry Gateway collectors and normalizers."""

from bastion.infrastructure.telemetry.adapters import CompositeEventNormalizer, SSHLogAdapter
from bastion.infrastructure.telemetry.file import FileCollector
from bastion.infrastructure.telemetry.journald import JournaldCollector, JournaldCollectorError
from bastion.infrastructure.telemetry.stdin import StdinCollector

__all__ = [
    "JournaldCollector",
    "JournaldCollectorError",
    "StdinCollector",
    "FileCollector",
    "SSHLogAdapter",
    "CompositeEventNormalizer",
]
