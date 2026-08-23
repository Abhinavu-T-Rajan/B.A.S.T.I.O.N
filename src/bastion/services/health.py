from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from bastion.config import BastionConfig, validate_config
from bastion.core.contracts.firewall import FirewallProvider
from bastion.core.contracts.storage import StorageProvider
from bastion.daemon.state import (
    DaemonHealthSnapshot,
    HealthStatus,
    HealthTracker,
    ServiceState,
    Subsystem,
)
from bastion.infrastructure.telemetry.journald import JournaldCollector


class HealthAppService:
    """Application service for operational health diagnostics and system status inspection."""

    @staticmethod
    def load_snapshot(file_path: str | Path) -> DaemonHealthSnapshot | None:
        """Load daemon health snapshot from persistent JSON file."""
        return HealthTracker.load_from_file(file_path)

    @staticmethod
    def probe_live_health(
        config: BastionConfig,
        storage: StorageProvider,
        firewall: FirewallProvider,
    ) -> DaemonHealthSnapshot:
        """Perform diagnostic live health probe across all subsystems."""
        tracker = HealthTracker(
            response_mode=config.response.mode.upper(),
            firewall_backend=firewall.name.upper(),
        )
        tracker.set_service_state(ServiceState.STOPPED)

        # 1. Database check
        try:
            stats = storage.get_stats()
            tracker.set_subsystem_health(
                Subsystem.DATABASE,
                HealthStatus.HEALTHY,
                f"Storage ready ({stats.get('total_events', 0)} events, {stats.get('active_bans', 0)} bans)",
            )
            tracker.set_active_bans_count(stats.get("active_bans", 0))
        except Exception as exc:
            tracker.set_subsystem_health(
                Subsystem.DATABASE, HealthStatus.FAILED, f"Storage error: {exc}"
            )

        # 2. Firewall check
        is_auto = config.response.mode.lower() == "automatic"
        if firewall.is_available():
            tracker.set_subsystem_health(
                Subsystem.FIREWALL,
                HealthStatus.HEALTHY,
                f"Backend '{firewall.name}' available",
            )
        else:
            fw_st = HealthStatus.FAILED if is_auto else HealthStatus.DEGRADED
            tracker.set_subsystem_health(
                Subsystem.FIREWALL,
                fw_st,
                f"Backend '{firewall.name}' unavailable",
            )

        # 3. Detection & Response check
        val_errors = validate_config(config)
        if not val_errors:
            tracker.set_subsystem_health(Subsystem.DETECTION, HealthStatus.HEALTHY, "Detectors configured")
            tracker.set_subsystem_health(Subsystem.THREAT_INTEL, HealthStatus.HEALTHY, "Threat Intel ready")
            if is_auto and not firewall.is_available():
                tracker.set_subsystem_health(
                    Subsystem.RESPONSE,
                    HealthStatus.DEGRADED,
                    "Automatic enforcement disabled; firewall unavailable",
                )
            else:
                tracker.set_subsystem_health(
                    Subsystem.RESPONSE, HealthStatus.HEALTHY, f"Mode: {config.response.mode.upper()}"
                )
        else:
            tracker.set_subsystem_health(Subsystem.DETECTION, HealthStatus.DEGRADED, "Config warnings")

        # 4. Telemetry check
        if config.telemetry.source == "journald":
            if JournaldCollector.is_available():
                tracker.set_subsystem_health(Subsystem.TELEMETRY, HealthStatus.HEALTHY, "journalctl available")
            else:
                tracker.set_subsystem_health(Subsystem.TELEMETRY, HealthStatus.DEGRADED, "journalctl unavailable")
        else:
            tracker.set_subsystem_health(Subsystem.TELEMETRY, HealthStatus.HEALTHY, f"Source: {config.telemetry.source}")

        return tracker.get_snapshot()

    @staticmethod
    def format_report(snapshot: DaemonHealthSnapshot) -> str:
        """Render clean, human-readable operational health report."""
        return HealthTracker.format_health_report(snapshot)
