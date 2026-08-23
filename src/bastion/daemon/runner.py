from __future__ import annotations

import os
import shutil
import signal
import sys
import threading
import time
from collections.abc import Iterable, Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from bastion.version import __version__
from bastion.attack.registry import AttackRegistry
from bastion.config import BastionConfig, load_config, validate_config_strict
from bastion.core.contracts.collector import CollectorProvider
from bastion.core.contracts.firewall import FirewallProvider
from bastion.core.contracts.storage import StorageProvider
from bastion.core.models.telemetry import RawTelemetry
from bastion.correlation.engine import CorrelationEngine
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
    log_audit,
    setup_daemon_logging,
)
from bastion.daemon.reconciliation import FirewallReconciler
from bastion.daemon.state import (
    DaemonHealthSnapshot,
    HealthStatus,
    HealthTracker,
    ServiceState,
    Subsystem,
)
from bastion.detection.brute_force import BruteForceDetector
from bastion.detection.burst import BurstDetector
from bastion.detection.engine import DetectionEngine
from bastion.detection.enumeration import UsernameEnumerationDetector
from bastion.detection.password_spray import PasswordSprayDetector
from bastion.firewall.base import FirewallBackend
from bastion.firewall.mock import MockFirewallBackend
from bastion.firewall.nftables import NFTablesBackend
from bastion.incidents.manager import IncidentManager
from bastion.infrastructure.telemetry.adapters.composite import CompositeEventNormalizer
from bastion.infrastructure.telemetry.file import FileCollector
from bastion.infrastructure.telemetry.journald import JournaldCollector, JournaldCollectorError
from bastion.infrastructure.telemetry.stdin import StdinCollector
from bastion.intelligence.manager import IOCManager
from bastion.models.actors import ThreatActorProfile
from bastion.models.events import SecurityEvent
from bastion.services.pipeline import SentinelPipeline
from bastion.response.ban_manager import BanManager
from bastion.response.engine import ResponseEngine
from bastion.response.models import ResponseMode
from bastion.response.policy import PolicyConfig, PolicyEngine
from bastion.risk.scorer import RiskEngine, RiskScoringConfig
from bastion.storage.sqlite import SQLiteStorage


class BastionDaemon:
    """Long-running B.A.S.T.I.O.N. Sentinel Core security service process."""

    def __init__(
        self,
        config: BastionConfig | None = None,
        *,
        config_path: str | Path | None = None,
        storage: SQLiteStorage | None = None,
        firewall: FirewallBackend | None = None,
        custom_collector_stream: Iterable[str] | None = None,
    ) -> None:
        self.config_path = config_path
        if config is not None:
            self.config = config
        else:
            self.config = load_config(config_path)

        # 1. Strictly validate configuration on initialization
        validate_config_strict(self.config)

        # 2. Setup structured daemon logger
        self.logger = setup_daemon_logging(
            log_level=self.config.daemon.log_level,
            log_format=self.config.daemon.log_format,
        )

        # 3. Setup health tracking subsystem
        self.health_tracker = HealthTracker(
            response_mode=self.config.response.mode.upper(),
            firewall_backend=self.config.response.backend.upper(),
        )

        self._injected_storage = storage
        self._injected_firewall = firewall
        self._injected_stream = custom_collector_stream

        self.storage: SQLiteStorage | None = None
        self.firewall: FirewallBackend | None = None
        self.ban_manager: BanManager | None = None
        self.reconciler: FirewallReconciler | None = None
        self.pipeline: SentinelPipeline | None = None
        self.collector: CollectorProvider | None = None

        self._running = False
        self._stop_event = threading.Event()
        self._maintenance_thread: threading.Thread | None = None
        self._consecutive_collector_errors = 0

    def initialize(self) -> None:
        """Initialize all subsystems, database schemas, firewall rules, and pipelines."""
        log_audit(
            self.logger,
            SERVICE_START,
            f"Initializing B.A.S.T.I.O.N. v{__version__} (Sentinel Core)",
            {"version": __version__, "config_version": self.config.config_version},
        )
        self.health_tracker.set_service_state(ServiceState.INITIALIZING)

        # 1. Initialize SQLite storage & migrations
        try:
            if self._injected_storage:
                self.storage = self._injected_storage
            else:
                self.storage = SQLiteStorage(self.config.storage.db_path)
            self.health_tracker.set_subsystem_health(
                Subsystem.DATABASE, HealthStatus.HEALTHY, "Database operational"
            )
        except Exception as exc:
            self.health_tracker.set_subsystem_health(
                Subsystem.DATABASE, HealthStatus.FAILED, f"Database init error: {exc}"
            )
            log_audit(
                self.logger,
                DATABASE_FAILURE,
                f"Storage initialization failed: {exc}",
                level=40,
            )
            raise

        # 2. Initialize Firewall Backend
        try:
            if self._injected_firewall:
                self.firewall = self._injected_firewall
            elif self.config.response.backend == "mock":
                self.firewall = MockFirewallBackend()
            else:
                if shutil.which("nft") is not None:
                    self.firewall = NFTablesBackend(table_name=self.config.response.table_name)
                else:
                    self.logger.warning(
                        "nftables utility not found in PATH; falling back to MockFirewallBackend"
                    )
                    self.firewall = MockFirewallBackend()

            if self.firewall.is_available():
                self.firewall.initialize()
                self.health_tracker.set_subsystem_health(
                    Subsystem.FIREWALL,
                    HealthStatus.HEALTHY,
                    f"Firewall '{self.firewall.name}' ready",
                )
            else:
                is_auto = self.config.response.mode.lower() == "automatic"
                fw_status = HealthStatus.FAILED if is_auto else HealthStatus.DEGRADED
                self.health_tracker.set_subsystem_health(
                    Subsystem.FIREWALL,
                    fw_status,
                    f"Firewall '{self.firewall.name}' unavailable",
                )
                if is_auto:
                    self.health_tracker.set_subsystem_health(
                        Subsystem.RESPONSE,
                        HealthStatus.DEGRADED,
                        "Automatic enforcement disabled; firewall backend unavailable",
                    )
                    log_audit(
                        self.logger,
                        DEGRADED_MODE,
                        "Automatic enforcement configured but firewall backend is unavailable; entering fail-safe mode",
                        level=30,
                    )
        except Exception as exc:
            is_auto = self.config.response.mode.lower() == "automatic"
            fw_status = HealthStatus.FAILED if is_auto else HealthStatus.DEGRADED
            self.health_tracker.set_subsystem_health(
                Subsystem.FIREWALL, fw_status, f"Firewall init warning: {exc}"
            )
            log_audit(
                self.logger,
                FIREWALL_FAILURE,
                f"Firewall backend init issue: {exc}",
                level=30,
            )

        # 3. Setup Response Policy & Ban Manager
        policy_cfg = PolicyConfig(
            isolation_threshold=self.config.response.isolation_threshold,
            rate_limit_threshold=self.config.response.rate_limit_threshold,
            default_ban_duration_seconds=self.config.response.default_ban_duration_seconds,
            repeat_offender_ban_duration_seconds=self.config.response.repeat_offender_ban_duration_seconds,
            max_ban_duration_seconds=self.config.response.max_ban_duration_seconds,
            allowlist_cidrs=self.config.response.allowlist_cidrs,
        )
        policy_engine = PolicyEngine(policy_cfg)

        self.ban_manager = BanManager(
            storage=self.storage,
            firewall=self.firewall,
        )

        # 4. Startup Ban Restoration & Reconciliation
        try:
            synced_count = self.ban_manager.sync_on_startup()
            self.reconciler = FirewallReconciler(
                storage=self.storage,
                ban_manager=self.ban_manager,
                firewall=self.firewall,
            )
            report = self.reconciler.reconcile()
            active_count = len(self.storage.get_active_bans())
            self.health_tracker.set_active_bans_count(active_count)

            if synced_count > 0 or report.restored_bans:
                log_audit(
                    self.logger,
                    BAN_RESTORED,
                    f"Restored {synced_count} active bans to firewall on startup",
                    {"synced_count": synced_count, "restored_bans": report.restored_bans},
                )
        except Exception as exc:
            log_audit(
                self.logger,
                FIREWALL_FAILURE,
                f"Startup ban sync failed: {exc}",
                level=30,
            )

        # 5. Initialize Behavioral Detection Engine
        det_cfg = self.config.detectors
        brute_force_det = (
            BruteForceDetector(
                threshold=det_cfg.brute_force.threshold,
                window_seconds=det_cfg.brute_force.window_seconds,
            )
            if det_cfg.brute_force.enabled
            else None
        )
        password_spray_det = (
            PasswordSprayDetector(
                min_usernames=det_cfg.password_spray.min_usernames,
                max_attempts_per_user=det_cfg.password_spray.max_attempts_per_user,
                window_seconds=det_cfg.password_spray.window_seconds,
            )
            if det_cfg.password_spray.enabled
            else None
        )
        enumeration_det = (
            UsernameEnumerationDetector(
                threshold=det_cfg.enumeration.threshold,
                window_seconds=det_cfg.enumeration.window_seconds,
            )
            if det_cfg.enumeration.enabled
            else None
        )
        burst_det = (
            BurstDetector(
                threshold=det_cfg.burst.threshold,
                window_seconds=det_cfg.burst.window_seconds,
            )
            if det_cfg.burst.enabled
            else None
        )
        detection_engine = DetectionEngine(
            brute_force=brute_force_det,
            password_spray=password_spray_det,
            enumeration=enumeration_det,
            burst=burst_det,
        )
        self.health_tracker.set_subsystem_health(
            Subsystem.DETECTION, HealthStatus.HEALTHY, "Detectors operational"
        )

        # 6. Initialize Threat Intel, Risk, and Incidents
        ioc_mgr = IOCManager(self.storage)
        inc_mgr = IncidentManager(self.storage)
        corr_engine = CorrelationEngine(
            storage=self.storage,
            ioc_manager=ioc_mgr,
            incident_manager=inc_mgr,
        )
        self.health_tracker.set_subsystem_health(
            Subsystem.THREAT_INTEL, HealthStatus.HEALTHY, "Threat Intel operational"
        )

        # 7. Initialize Response Engine
        resp_mode_enum = ResponseMode(self.config.response.mode.lower())
        response_engine = ResponseEngine(
            policy=policy_engine,
            ban_manager=self.ban_manager,
            default_mode=resp_mode_enum,
        )
        self.health_tracker.set_subsystem_health(
            Subsystem.RESPONSE, HealthStatus.HEALTHY, f"Response mode: {resp_mode_enum.value.upper()}"
        )

        # 8. Setup Core Pipeline
        risk_engine = RiskEngine()
        self.pipeline = SentinelPipeline(
            normalizer=CompositeEventNormalizer(),
            engine=detection_engine,
            risk_engine=risk_engine,
            response_engine=response_engine,
            storage=self.storage,
            correlation_engine=corr_engine,
            alert_min_score=self.config.response.isolation_threshold,
        )

        # 9. Setup Telemetry Collector
        if self._injected_stream is not None:
            self.collector = StdinCollector(stream_source=self._injected_stream)
            self.health_tracker.set_subsystem_health(
                Subsystem.TELEMETRY, HealthStatus.HEALTHY, "Stream: Custom stream"
            )
        elif self.config.telemetry.source == "stdin":
            self.collector = StdinCollector()
            self.health_tracker.set_subsystem_health(
                Subsystem.TELEMETRY, HealthStatus.HEALTHY, "Source: stdin"
            )
        elif self.config.telemetry.source == "file" and self.config.telemetry.log_file_path:
            self.collector = FileCollector(file_path=self.config.telemetry.log_file_path)
            self.health_tracker.set_subsystem_health(
                Subsystem.TELEMETRY, HealthStatus.HEALTHY, f"Source: file ({self.config.telemetry.log_file_path})"
            )
        else:
            self.collector = JournaldCollector(
                units=self.config.telemetry.journal_units,
                identifiers=self.config.telemetry.journal_identifier,
            )
            if self.collector.is_available():
                self.health_tracker.set_subsystem_health(
                    Subsystem.TELEMETRY,
                    HealthStatus.HEALTHY,
                    f"journald units: {self.config.telemetry.journal_units}",
                )
            else:
                self.health_tracker.set_subsystem_health(
                    Subsystem.TELEMETRY,
                    HealthStatus.DEGRADED,
                    "journalctl is not available on this host",
                )

        # Save health snapshot
        self._export_health_snapshot()

    def _on_pipeline_alert(
        self,
        event: SecurityEvent,
        profile: ThreatActorProfile,
        detections: list[Any],
        decision: Any | None,
    ) -> None:
        """Pipeline alert callback hook."""
        self.health_tracker.record_detection()
        det_names = [d.detector_name for d in detections if getattr(d, "detected", False)]
        log_audit(
            self.logger,
            RESPONSE_EXECUTED if decision and getattr(decision, "executed", False) else "THREAT_ALERT",
            f"Threat detected from {event.source_ip} (score={profile.threat_score}, severity={profile.severity.value})",
            {
                "ip": event.source_ip,
                "score": profile.threat_score,
                "severity": profile.severity.value,
                "detectors": det_names,
                "action": decision.action.value if decision else "NONE",
            },
        )

    def _export_health_snapshot(self) -> None:
        """Save health snapshot to configured JSON file."""
        try:
            self.health_tracker.save_to_file(self.config.daemon.health_state_path)
        except Exception as exc:
            self.logger.debug(f"Failed to export health snapshot: {exc}")

    def _start_maintenance_worker(self) -> None:
        """Start periodic worker for ban expirations, firewall reconciliation, and health export."""
        def worker() -> None:
            reconcile_counter = 0
            while not self._stop_event.is_set():
                # Sleep in 1s increments for responsive shutdown
                self._stop_event.wait(timeout=1.0)
                if self._stop_event.is_set():
                    break

                reconcile_counter += 1

                # 1. Periodic Ban Expiration Check (every 5 seconds)
                if reconcile_counter % 5 == 0:
                    try:
                        if self.ban_manager:
                            expired = self.ban_manager.check_expirations()
                            if expired:
                                for b in expired:
                                    log_audit(
                                        self.logger,
                                        BAN_EXPIRED,
                                        f"Ban expired and released for {b.source_ip}",
                                        {"ip": b.source_ip, "ban_id": b.ban_id},
                                    )
                                if self.storage:
                                    self.health_tracker.set_active_bans_count(
                                        len(self.storage.get_active_bans())
                                    )
                    except Exception as exc:
                        self.logger.warning(f"Error during ban expiration maintenance: {exc}")

                # 2. Periodic Firewall Reconciliation
                if reconcile_counter >= self.config.daemon.reconciliation_interval_seconds:
                    reconcile_counter = 0
                    try:
                        if self.reconciler:
                            report = self.reconciler.reconcile()
                            if report.is_healthy:
                                self.health_tracker.set_subsystem_health(
                                    Subsystem.FIREWALL, HealthStatus.HEALTHY, "Firewall in sync"
                                )
                            else:
                                self.health_tracker.set_subsystem_health(
                                    Subsystem.FIREWALL, HealthStatus.DEGRADED, report.error_message or "Sync warning"
                                )
                            if report.restored_bans:
                                log_audit(
                                    self.logger,
                                    BAN_RESTORED,
                                    f"Reconciled and restored {len(report.restored_bans)} missing rules",
                                    {"restored": report.restored_bans},
                                )
                    except Exception as exc:
                        self.logger.warning(f"Error during firewall reconciliation: {exc}")

                # 3. Periodic Health State Export
                if reconcile_counter % self.config.daemon.health_check_interval_seconds == 0:
                    self._export_health_snapshot()

        self._maintenance_thread = threading.Thread(
            target=worker,
            name="BastionMaintenanceWorker",
            daemon=True,
        )
        self._maintenance_thread.start()

    def _setup_signal_handlers(self) -> None:
        """Register graceful POSIX signal handlers."""
        def sig_handler(signum: int, frame: Any) -> None:
            sig_name = signal.Signals(signum).name
            self.logger.info(f"Received {sig_name} signal; initiating graceful shutdown...")
            self.stop()

        def hup_handler(signum: int, frame: Any) -> None:
            self.logger.info("Received SIGHUP; reloading configuration...")
            self.reload_config()

        try:
            signal.signal(signal.SIGTERM, sig_handler)
            signal.signal(signal.SIGINT, sig_handler)
            if hasattr(signal, "SIGHUP"):
                signal.signal(signal.SIGHUP, hup_handler)
        except (ValueError, AttributeError):
            # Not in main thread or platform doesn't support signal
            pass

    def run(self) -> int:
        """Start daemon service lifecycle and enter resilient event streaming loop."""
        self.initialize()
        self._setup_signal_handlers()
        self._running = True
        self._stop_event.clear()
        self.health_tracker.set_service_state(ServiceState.RUNNING)
        self._start_maintenance_worker()

        log_audit(
            self.logger,
            SERVICE_START,
            f"B.A.S.T.I.O.N. Sentinel Core service is RUNNING",
            {"mode": self.config.response.mode, "backend": self.config.response.backend},
        )

        try:
            assert self.collector is not None
            if self._injected_stream is not None or self.config.telemetry.source in {"stdin", "file"}:
                self._process_stream(self.collector.stream())
            else:
                self._run_journal_stream_loop()
        except KeyboardInterrupt:
            self.logger.info("KeyboardInterrupt received.")
        finally:
            self.stop()

        return 0

    def _process_stream(self, stream: Iterable[Any]) -> None:
        """Process an iterable stream of raw telemetry items with error containment."""
        assert self.pipeline is not None
        for item in stream:
            if self._stop_event.is_set() or not self._running:
                break
            try:
                if isinstance(item, RawTelemetry):
                    res = self.pipeline.process_raw(item)
                else:
                    line = item.strip() if isinstance(item, str) else str(item).strip()
                    if not line:
                        continue
                    res = self.pipeline.process_line(line)
                if res.event:
                    self.health_tracker.record_event_processed(res.event.timestamp)
                if res.is_alert:
                    self.health_tracker.record_detection()
            except Exception as exc:
                self.health_tracker.record_subsystem_error(
                    Subsystem.DETECTION, f"Malformed event error: {exc}"
                )
                self.logger.warning(
                    f"Error processing telemetry event: {exc}"
                )

    def _run_journal_stream_loop(self) -> None:
        """Resilient journald streaming loop with automatic reconnection and exponential backoff."""
        assert self.collector is not None
        while self._running and not self._stop_event.is_set():
            try:
                self.health_tracker.set_subsystem_health(
                    Subsystem.TELEMETRY, HealthStatus.HEALTHY, "Streaming journald events"
                )
                self._consecutive_collector_errors = 0
                for item in self.collector.stream():
                    if self._stop_event.is_set() or not self._running:
                        break
                    try:
                        assert self.pipeline is not None
                        if isinstance(item, RawTelemetry):
                            res = self.pipeline.process_raw(item)
                        else:
                            res = self.pipeline.process_line(str(item))
                        if res.event:
                            self.health_tracker.record_event_processed(res.event.timestamp)
                        if res.is_alert:
                            self.health_tracker.record_detection()
                    except Exception as exc:
                        self.health_tracker.record_subsystem_error(
                            Subsystem.DETECTION, f"Event processing error: {exc}"
                        )
                        self.logger.warning(f"Error handling log line: {exc}")

            except (JournaldCollectorError, Exception) as exc:
                if self._stop_event.is_set() or not self._running:
                    break
                self._consecutive_collector_errors += 1
                self.health_tracker.record_subsystem_error(
                    Subsystem.TELEMETRY, f"Collector stream interrupted: {exc}"
                )
                log_audit(
                    self.logger,
                    COLLECTOR_FAILURE,
                    f"Journal collector stream error: {exc}",
                    {"retry_count": self._consecutive_collector_errors},
                    level=30,
                )

                if self._consecutive_collector_errors >= self.config.daemon.max_collector_retries:
                    self.health_tracker.set_subsystem_health(
                        Subsystem.TELEMETRY,
                        HealthStatus.DEGRADED,
                        "Max collector retries exceeded; waiting to reconnect",
                    )

                backoff = min(60, self.config.daemon.journal_retry_backoff_seconds * (2 ** min(self._consecutive_collector_errors - 1, 4)))
                self.logger.info(f"Retrying journal collector connection in {backoff}s...")
                self._stop_event.wait(timeout=backoff)

    def reload_config(self) -> None:
        """Reload configuration safely and apply live updates."""
        try:
            new_cfg = load_config(self.config_path)
            validate_config_strict(new_cfg)
            self.config = new_cfg
            log_audit(
                self.logger,
                CONFIG_LOAD,
                f"Configuration reloaded successfully (version {new_cfg.config_version})",
                {"loaded_from": new_cfg.loaded_from},
            )
        except Exception as exc:
            log_audit(
                self.logger,
                CONFIG_ERROR,
                f"Failed to reload configuration: {exc}",
                level=40,
            )

    def stop(self) -> None:
        """Gracefully terminate background workers, flush rules, and save final state."""
        if not self._running and self.health_tracker.service_state == ServiceState.STOPPED:
            return

        self._running = False
        self._stop_event.set()
        self.health_tracker.set_service_state(ServiceState.STOPPING)
        log_audit(self.logger, SERVICE_STOP, "Stopping B.A.S.T.I.O.N. daemon service...")

        # 1. Stop collector subprocess immediately to unblock streaming loop
        if self.collector:
            try:
                self.collector.stop()
            except Exception:
                pass

        # 2. Join background maintenance worker
        if self._maintenance_thread and self._maintenance_thread.is_alive():
            self._maintenance_thread.join(timeout=2.0)

        # 3. Close database connection
        if self.storage:
            try:
                self.storage.close()
            except Exception:
                pass

        self.health_tracker.set_service_state(ServiceState.STOPPED)
        self._export_health_snapshot()
        log_audit(self.logger, SERVICE_STOP, "B.A.S.T.I.O.N. daemon service successfully stopped")
