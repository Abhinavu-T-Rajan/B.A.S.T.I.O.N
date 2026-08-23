"""B.A.S.T.I.O.N. - Behavioral Attack Surveillance & Threat Isolation Operating Network."""

from __future__ import annotations

from bastion.version import __codename__, __version__
from bastion.attack.models import AttackMapping, AttackTactic, AttackTechnique
from bastion.attack.registry import AttackRegistry
from bastion.collector.journal import JournalCollector, JournalError
from bastion.collector.ssh import SSHLogParser
from bastion.config import (
    BastionConfig,
    ConfigValidationError,
    DaemonConfig,
    DetectorsConfig,
    ResponseConfig,
    RiskConfig,
    StorageConfig,
    TelemetryConfig,
    load_config,
    validate_config,
    validate_config_strict,
)
from bastion.core.contracts.collector import CollectorProvider, EventNormalizer, TelemetryAdapter
from bastion.core.contracts.detector import Detector, DetectorProvider
from bastion.core.contracts.firewall import FirewallError, FirewallProvider
from bastion.core.contracts.response import ResponseProvider
from bastion.core.contracts.storage import StorageProvider
from bastion.core.models.telemetry import RawTelemetry
from bastion.correlation.engine import CorrelationEngine
from bastion.correlation.models import CorrelationContext
from bastion.services.defense import DefenseAppService
from bastion.services.health import HealthAppService
from bastion.services.incidents import IncidentAppService
from bastion.services.intelligence import IntelligenceAppService
from bastion.services.pipeline import PipelineResult, SentinelPipeline, format_explainable_alert
from bastion.daemon.logging import (
    BAN_EXPIRED,
    BAN_RESTORED,
    COLLECTOR_FAILURE,
    CONFIG_ERROR,
    CONFIG_LOAD,
    DATABASE_FAILURE,
    DEGRADED_MODE,
    FIREWALL_FAILURE,
    RECOVERY,
    RESPONSE_EXECUTED,
    RESPONSE_FAILED,
    SERVICE_START,
    SERVICE_STOP,
    StructuredLogFormatter,
    log_audit,
    setup_daemon_logging,
)
from bastion.daemon.reconciliation import FirewallReconciler, ReconciliationReport
from bastion.daemon.runner import BastionDaemon
from bastion.daemon.state import (
    DaemonHealthSnapshot,
    HealthStatus,
    HealthTracker,
    ServiceState,
    Subsystem,
    SubsystemHealth,
)
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

__all__ = [
    "ActorState",
    "AttackMapping",
    "AttackRegistry",
    "AttackTactic",
    "AttackTechnique",
    "BAN_EXPIRED",
    "BAN_RESTORED",
    "BanManager",
    "BanRecord",
    "BanStatus",
    "BastionConfig",
    "BastionDaemon",
    "BruteForceDetector",
    "BurstDetector",
    "COLLECTOR_FAILURE",
    "CONFIG_ERROR",
    "CONFIG_LOAD",
    "ConfigValidationError",
    "CorrelationContext",
    "CorrelationEngine",
    "DATABASE_FAILURE",
    "DEGRADED_MODE",
    "DaemonConfig",
    "DaemonHealthSnapshot",
    "DetectionEngine",
    "DetectionResult",
    "DetectorsConfig",
    "EventType",
    "ExperimentalResponseCoordinator",
    "FIREWALL_FAILURE",
    "FirewallBackend",
    "FirewallError",
    "FirewallReconciler",
    "HealthStatus",
    "HealthTracker",
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
    "RECOVERY",
    "RESPONSE_EXECUTED",
    "RESPONSE_FAILED",
    "ReconciliationReport",
    "RecommendedAction",
    "ResponseAction",
    "ResponseAuditRecord",
    "ResponseConfig",
    "ResponseDecision",
    "ResponseEngine",
    "ResponseMode",
    "ResponseResult",
    "RiskConfig",
    "RiskEngine",
    "RiskScoringConfig",
    "SERVICE_START",
    "SERVICE_STOP",
    "SQLiteStorage",
    "SSHLogParser",
    "ScoreFactor",
    "SecurityEvent",
    "SentinelPipeline",
    "ServiceState",
    "ServiceType",
    "Severity",
    "StorageConfig",
    "StructuredLogFormatter",
    "Subsystem",
    "SubsystemHealth",
    "TelemetryConfig",
    "ThreatActorProfile",
    "TimelineEntry",
    "TimelineEntryType",
    "TimelineGenerator",
    "UsernameEnumerationDetector",
    "__codename__",
    "__version__",
    "format_explainable_alert",
    "load_config",
    "log_audit",
    "setup_daemon_logging",
    "validate_config",
    "validate_config_strict",
]
