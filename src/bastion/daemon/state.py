from __future__ import annotations

import json
import os
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from bastion.version import __version__


class ServiceState(str, Enum):
    """Operational state of the B.A.S.T.I.O.N. service process."""

    STARTING = "STARTING"
    INITIALIZING = "INITIALIZING"
    RUNNING = "RUNNING"
    STOPPING = "STOPPING"
    STOPPED = "STOPPED"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"


class HealthStatus(str, Enum):
    """Subsystem and service health classifications."""

    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"


class Subsystem(str, Enum):
    """Recognized B.A.S.T.I.O.N. core architectural subsystems."""

    SERVICE = "Service"
    TELEMETRY = "Telemetry"
    DETECTION = "Detection"
    THREAT_INTEL = "Threat Intel"
    DATABASE = "Database"
    FIREWALL = "Firewall"
    RESPONSE = "Response"


@dataclass(slots=True)
class SubsystemHealth:
    """Health diagnostic status and metrics for a specific subsystem."""

    name: str
    status: HealthStatus = HealthStatus.UNKNOWN
    message: str = "Not initialized"
    last_check: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    error_count: int = 0
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status.value,
            "message": self.message,
            "last_check": self.last_check.isoformat(),
            "error_count": self.error_count,
            "details": self.details,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SubsystemHealth:
        last_check = datetime.fromisoformat(data["last_check"]) if "last_check" in data else datetime.now(timezone.utc)
        return cls(
            name=data.get("name", "Unknown"),
            status=HealthStatus(data.get("status", HealthStatus.UNKNOWN.value)),
            message=data.get("message", ""),
            last_check=last_check,
            error_count=data.get("error_count", 0),
            details=data.get("details", {}),
        )


@dataclass(slots=True)
class DaemonHealthSnapshot:
    """Serializable complete point-in-time health snapshot of the daemon."""

    service_state: ServiceState
    overall_health: HealthStatus
    subsystems: dict[str, SubsystemHealth]
    uptime_seconds: float
    start_time: datetime
    last_event_time: datetime | None
    events_processed: int
    detections_count: int
    active_bans_count: int
    version: str = __version__
    response_mode: str = "DRY_RUN"
    firewall_backend: str = "MOCK"

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "service_state": self.service_state.value,
            "overall_health": self.overall_health.value,
            "response_mode": self.response_mode,
            "firewall_backend": self.firewall_backend,
            "uptime_seconds": self.uptime_seconds,
            "start_time": self.start_time.isoformat(),
            "last_event_time": self.last_event_time.isoformat() if self.last_event_time else None,
            "events_processed": self.events_processed,
            "detections_count": self.detections_count,
            "active_bans_count": self.active_bans_count,
            "subsystems": {k: v.to_dict() for k, v in self.subsystems.items()},
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DaemonHealthSnapshot:
        subsystems = {
            k: SubsystemHealth.from_dict(v)
            for k, v in data.get("subsystems", {}).items()
        }
        start_time = datetime.fromisoformat(data["start_time"]) if "start_time" in data else datetime.now(timezone.utc)
        last_event_time = (
            datetime.fromisoformat(data["last_event_time"])
            if data.get("last_event_time")
            else None
        )
        return cls(
            version=data.get("version", __version__),
            service_state=ServiceState(data.get("service_state", ServiceState.UNKNOWN if hasattr(ServiceState, 'UNKNOWN') else ServiceState.STOPPED.value)),
            overall_health=HealthStatus(data.get("overall_health", HealthStatus.UNKNOWN.value)),
            response_mode=data.get("response_mode", "DRY_RUN"),
            firewall_backend=data.get("firewall_backend", "MOCK"),
            uptime_seconds=data.get("uptime_seconds", 0.0),
            start_time=start_time,
            last_event_time=last_event_time,
            events_processed=data.get("events_processed", 0),
            detections_count=data.get("detections_count", 0),
            active_bans_count=data.get("active_bans_count", 0),
            subsystems=subsystems,
        )


class HealthTracker:
    """Thread-safe manager for tracking subsystem health states and runtime metrics."""

    def __init__(
        self,
        *,
        response_mode: str = "DRY_RUN",
        firewall_backend: str = "MOCK",
    ) -> None:
        self._lock = threading.RLock()
        self._start_time = datetime.now(timezone.utc)
        self._service_state = ServiceState.STARTING
        self._last_event_time: datetime | None = None
        self._events_processed = 0
        self._detections_count = 0
        self._active_bans_count = 0
        self.response_mode = response_mode
        self.firewall_backend = firewall_backend

        # Initialize all known subsystems with UNKNOWN state
        self._subsystems: dict[str, SubsystemHealth] = {
            s.value: SubsystemHealth(name=s.value, status=HealthStatus.UNKNOWN)
            for s in Subsystem
        }

    @property
    def service_state(self) -> ServiceState:
        with self._lock:
            return self._service_state

    def set_service_state(self, state: ServiceState) -> None:
        with self._lock:
            self._service_state = state
            srv_health = self._subsystems.get(Subsystem.SERVICE.value)
            if srv_health:
                if state in (ServiceState.RUNNING, ServiceState.STARTING, ServiceState.INITIALIZING):
                    srv_health.status = HealthStatus.HEALTHY
                elif state == ServiceState.DEGRADED:
                    srv_health.status = HealthStatus.DEGRADED
                elif state == ServiceState.FAILED:
                    srv_health.status = HealthStatus.FAILED
                else:
                    srv_health.status = HealthStatus.UNKNOWN
                srv_health.message = f"State: {state.value}"
                srv_health.last_check = datetime.now(timezone.utc)

    def set_subsystem_health(
        self,
        subsystem: Subsystem | str,
        status: HealthStatus,
        message: str = "",
        details: dict[str, Any] | None = None,
    ) -> None:
        key = subsystem.value if isinstance(subsystem, Subsystem) else subsystem
        with self._lock:
            sub = self._subsystems.setdefault(
                key, SubsystemHealth(name=key)
            )
            sub.status = status
            if message:
                sub.message = message
            sub.last_check = datetime.now(timezone.utc)
            if details:
                sub.details.update(details)

    def record_subsystem_error(
        self,
        subsystem: Subsystem | str,
        error_msg: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        key = subsystem.value if isinstance(subsystem, Subsystem) else subsystem
        with self._lock:
            sub = self._subsystems.setdefault(
                key, SubsystemHealth(name=key)
            )
            sub.error_count += 1
            sub.message = error_msg
            sub.last_check = datetime.now(timezone.utc)
            if details:
                sub.details.update(details)
            if sub.error_count >= 3 and sub.status == HealthStatus.HEALTHY:
                sub.status = HealthStatus.DEGRADED

    def record_event_processed(self, timestamp: datetime | None = None) -> None:
        with self._lock:
            self._events_processed += 1
            self._last_event_time = timestamp or datetime.now(timezone.utc)
            # Update telemetry subsystem check
            telem = self._subsystems.get(Subsystem.TELEMETRY.value)
            if telem:
                telem.last_check = self._last_event_time

    def record_detection(self) -> None:
        with self._lock:
            self._detections_count += 1

    def set_active_bans_count(self, count: int) -> None:
        with self._lock:
            self._active_bans_count = count

    def calculate_overall_health(self) -> HealthStatus:
        with self._lock:
            statuses = [s.status for s in self._subsystems.values()]
            if self._service_state == ServiceState.FAILED or HealthStatus.FAILED in statuses:
                return HealthStatus.FAILED
            if self._service_state == ServiceState.DEGRADED or HealthStatus.DEGRADED in statuses:
                return HealthStatus.DEGRADED
            non_service_statuses = [
                s.status for k, s in self._subsystems.items()
                if k != Subsystem.SERVICE.value
            ]
            if non_service_statuses and all(st == HealthStatus.HEALTHY for st in non_service_statuses):
                return HealthStatus.HEALTHY
            return HealthStatus.UNKNOWN

    def get_snapshot(self) -> DaemonHealthSnapshot:
        with self._lock:
            now = datetime.now(timezone.utc)
            uptime = max(0.0, (now - self._start_time).total_seconds())
            overall = self.calculate_overall_health()

            # Deep copy subsystems
            subsystems_copy = {
                k: SubsystemHealth(
                    name=v.name,
                    status=v.status,
                    message=v.message,
                    last_check=v.last_check,
                    error_count=v.error_count,
                    details=dict(v.details),
                )
                for k, v in self._subsystems.items()
            }

            return DaemonHealthSnapshot(
                version=__version__,
                service_state=self._service_state,
                overall_health=overall,
                response_mode=self.response_mode,
                firewall_backend=self.firewall_backend,
                uptime_seconds=uptime,
                start_time=self._start_time,
                last_event_time=self._last_event_time,
                events_processed=self._events_processed,
                detections_count=self._detections_count,
                active_bans_count=self._active_bans_count,
                subsystems=subsystems_copy,
            )

    def save_to_file(self, file_path: str | Path) -> None:
        """Persist health snapshot to a JSON file for CLI and external observability."""
        p = Path(os.path.expanduser(str(file_path))).resolve()
        p.parent.mkdir(parents=True, exist_ok=True)
        snapshot = self.get_snapshot()

        tmp_file = p.with_suffix(f".tmp.{os.getpid()}")
        try:
            with open(tmp_file, "w", encoding="utf-8") as f:
                json.dump(snapshot.to_dict(), f, indent=2)
            tmp_file.replace(p)
        except Exception:
            if tmp_file.exists():
                try:
                    tmp_file.unlink()
                except Exception:
                    pass

    @staticmethod
    def load_from_file(file_path: str | Path) -> DaemonHealthSnapshot | None:
        """Load health snapshot from JSON file if available and valid."""
        p = Path(os.path.expanduser(str(file_path))).resolve()
        if not p.exists():
            return None
        try:
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)
            return DaemonHealthSnapshot.from_dict(data)
        except Exception:
            return None

    @classmethod
    def format_health_report(cls, snapshot: DaemonHealthSnapshot) -> str:
        """Render a clean, human-readable operational health report."""
        uptime_h = int(snapshot.uptime_seconds // 3600)
        uptime_m = int((snapshot.uptime_seconds % 3600) // 60)
        uptime_s = int(snapshot.uptime_seconds % 60)
        uptime_str = f"{uptime_h:02d}h {uptime_m:02d}m {uptime_s:02d}s"

        last_ev_str = (
            snapshot.last_event_time.strftime("%Y-%m-%d %H:%M:%S UTC")
            if snapshot.last_event_time
            else "None recorded"
        )

        lines = [
            "B.A.S.T.I.O.N. Health",
            "────────────────────────────",
        ]

        # Standard order of subsystem output
        order = [
            Subsystem.SERVICE.value,
            Subsystem.TELEMETRY.value,
            Subsystem.DETECTION.value,
            Subsystem.THREAT_INTEL.value,
            Subsystem.DATABASE.value,
            Subsystem.FIREWALL.value,
        ]

        for sub_name in order:
            sub = snapshot.subsystems.get(sub_name)
            st_val = sub.status.value if sub else HealthStatus.UNKNOWN.value
            lines.append(f"{sub_name:<14}: {st_val}")

        lines.append(f"{'Response':<14}: {snapshot.response_mode.upper()}")
        lines.append(f"{'Last Event':<14}: {last_ev_str}")
        lines.append(f"{'Uptime':<14}: {uptime_str}")

        return "\n".join(lines)
