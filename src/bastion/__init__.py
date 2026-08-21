"""B.A.S.T.I.O.N. - Behavioral Attack Surveillance & Threat Isolation Operating Network."""

from __future__ import annotations

from bastion.collector.journal import JournalCollector, JournalError
from bastion.collector.ssh import SSHLogParser
from bastion.detection.brute_force import BruteForceDetector, DetectionResult
from bastion.models.events import EventType, SecurityEvent, ServiceType
from bastion.pipeline import PipelineResult, SentinelPipeline

__version__ = "0.1.1"

__all__ = [
    "BruteForceDetector",
    "DetectionResult",
    "EventType",
    "JournalCollector",
    "JournalError",
    "PipelineResult",
    "SSHLogParser",
    "SecurityEvent",
    "SentinelPipeline",
    "ServiceType",
    "__version__",
]
