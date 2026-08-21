"""B.A.S.T.I.O.N. - Behavioral Attack Surveillance & Threat Isolation Operating Network."""

from __future__ import annotations

from bastion.collector.journal import JournalCollector, JournalError
from bastion.collector.ssh import SSHLogParser
from bastion.config import BastionConfig, load_config
from bastion.detection.brute_force import BruteForceDetector, DetectionResult
from bastion.detection.burst import BurstDetector
from bastion.detection.engine import DetectionEngine
from bastion.detection.enumeration import UsernameEnumerationDetector
from bastion.detection.password_spray import PasswordSprayDetector
from bastion.models.actors import (
    ActorState,
    RecommendedAction,
    ScoreFactor,
    Severity,
    ThreatActorProfile,
)
from bastion.models.events import EventType, SecurityEvent, ServiceType
from bastion.pipeline import PipelineResult, SentinelPipeline, format_explainable_alert
from bastion.risk.scorer import RiskEngine, RiskScoringConfig
from bastion.storage.sqlite import SQLiteStorage

__version__ = "0.1.2"

__all__ = [
    "ActorState",
    "BastionConfig",
    "BruteForceDetector",
    "BurstDetector",
    "DetectionEngine",
    "DetectionResult",
    "EventType",
    "JournalCollector",
    "JournalError",
    "PasswordSprayDetector",
    "PipelineResult",
    "RecommendedAction",
    "RiskEngine",
    "RiskScoringConfig",
    "SQLiteStorage",
    "SSHLogParser",
    "ScoreFactor",
    "SecurityEvent",
    "SentinelPipeline",
    "ServiceType",
    "Severity",
    "ThreatActorProfile",
    "UsernameEnumerationDetector",
    "__version__",
    "format_explainable_alert",
    "load_config",
]
