"""B.A.S.T.I.O.N. - Behavioral Attack Surveillance & Threat Isolation Operating Network."""

from __future__ import annotations

from bastion.attack.models import AttackMapping, AttackTactic, AttackTechnique
from bastion.attack.registry import AttackRegistry
from bastion.collector.journal import JournalCollector, JournalError
from bastion.collector.ssh import SSHLogParser
from bastion.config import BastionConfig, load_config
from bastion.correlation.engine import CorrelationEngine
from bastion.correlation.models import CorrelationContext
from bastion.detection.brute_force import BruteForceDetector, DetectionResult
from bastion.detection.burst import BurstDetector
from bastion.detection.engine import DetectionEngine
from bastion.detection.enumeration import UsernameEnumerationDetector
from bastion.detection.password_spray import PasswordSprayDetector
from bastion.firewall.base import FirewallBackend, FirewallError
from bastion.firewall.mock import MockFirewallBackend
from bastion.firewall.nftables import NFTablesBackend
from bastion.incidents.manager import IncidentManager
from bastion.incidents.models import Incident, IncidentStatus
from bastion.intelligence.manager import IOCManager
from bastion.intelligence.models import IOCRecord, IOCStatus, IOCType, Provenance
from bastion.intelligence.validator import IOCValidator
from bastion.models.actors import (
    ActorState,
    RecommendedAction,
    ScoreFactor,
    Severity,
    ThreatActorProfile,
)
from bastion.models.events import EventType, SecurityEvent, ServiceType
from bastion.pipeline import PipelineResult, SentinelPipeline, format_explainable_alert
from bastion.response.audit import ResponseAuditRecord, ResponseResult
from bastion.response.ban_manager import BanManager
from bastion.response.engine import ResponseEngine
from bastion.response.experimental import ExperimentalResponseCoordinator
from bastion.response.models import (
    BanRecord,
    BanStatus,
    ResponseAction,
    ResponseDecision,
    ResponseMode,
)
from bastion.response.policy import PolicyConfig, PolicyEngine
from bastion.risk.scorer import RiskEngine, RiskScoringConfig
from bastion.storage.migrations import MigrationRunner
from bastion.storage.sqlite import SQLiteStorage
from bastion.timeline.generator import TimelineGenerator
from bastion.timeline.models import TimelineEntry, TimelineEntryType

__version__ = "0.2.0-alpha"

__all__ = [
    "ActorState",
    "AttackMapping",
    "AttackRegistry",
    "AttackTactic",
    "AttackTechnique",
    "BanManager",
    "BanRecord",
    "BanStatus",
    "BastionConfig",
    "BruteForceDetector",
    "BurstDetector",
    "CorrelationContext",
    "CorrelationEngine",
    "DetectionEngine",
    "DetectionResult",
    "EventType",
    "ExperimentalResponseCoordinator",
    "FirewallBackend",
    "FirewallError",
    "IOCManager",
    "IOCRecord",
    "IOCStatus",
    "IOCType",
    "IOCValidator",
    "Incident",
    "IncidentManager",
    "IncidentStatus",
    "JournalCollector",
    "JournalError",
    "MigrationRunner",
    "MockFirewallBackend",
    "NFTablesBackend",
    "PasswordSprayDetector",
    "PipelineResult",
    "PolicyConfig",
    "PolicyEngine",
    "Provenance",
    "RecommendedAction",
    "ResponseAction",
    "ResponseAuditRecord",
    "ResponseDecision",
    "ResponseEngine",
    "ResponseMode",
    "ResponseResult",
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
    "TimelineEntry",
    "TimelineEntryType",
    "TimelineGenerator",
    "UsernameEnumerationDetector",
    "__version__",
    "format_explainable_alert",
    "load_config",
]
