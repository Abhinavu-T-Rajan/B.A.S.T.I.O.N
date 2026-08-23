from __future__ import annotations

import ipaddress
import os
import re
import tomllib
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


class ConfigValidationError(ValueError):
    """Raised when configuration validation fails."""

    def __init__(self, errors: list[str]) -> None:
        self.errors = errors
        msg = f"Configuration validation failed with {len(errors)} error(s):\n" + "\n".join(
            f"  - {err}" for err in errors
        )
        super().__init__(msg)


@dataclass(slots=True)
class StorageConfig:
    """Persistent storage configuration."""

    db_path: str = "~/.local/share/bastion/bastion.db"


@dataclass(slots=True)
class BruteForceConfig:
    enabled: bool = True
    threshold: int = 10
    window_seconds: int = 60


@dataclass(slots=True)
class PasswordSprayConfig:
    enabled: bool = True
    min_usernames: int = 3
    max_attempts_per_user: int = 3
    window_seconds: int = 120


@dataclass(slots=True)
class EnumerationConfig:
    enabled: bool = True
    threshold: int = 4
    window_seconds: int = 60


@dataclass(slots=True)
class BurstConfig:
    enabled: bool = True
    threshold: int = 5
    window_seconds: int = 5


@dataclass(slots=True)
class DetectorsConfig:
    """Configuration for all behavioral detectors."""

    brute_force: BruteForceConfig = field(default_factory=BruteForceConfig)
    password_spray: PasswordSprayConfig = field(default_factory=PasswordSprayConfig)
    enumeration: EnumerationConfig = field(default_factory=EnumerationConfig)
    burst: BurstConfig = field(default_factory=BurstConfig)


@dataclass(slots=True)
class RiskConfig:
    """Risk scoring thresholds and trusted source rules."""

    medium_threshold: int = 40
    high_threshold: int = 70
    critical_threshold: int = 85
    failed_auth_weight: int = 5
    invalid_user_weight: int = 10
    burst_velocity_weight: int = 25
    brute_force_weight: int = 20
    password_spray_weight: int = 20
    enumeration_weight: int = 20
    max_attempts_weight: int = 20
    repeat_offender_weight: int = 15
    success_auth_weight: int = -10
    trusted_ip_discount: int = -100
    trusted_ips: list[str] = field(
        default_factory=lambda: ["127.0.0.1", "::1", "localhost"]
    )


@dataclass(slots=True)
class ResponseConfig:
    """Automated defense and firewall response configuration."""

    mode: str = "dry_run"  # dry_run, manual, automatic, disabled
    backend: str = "nftables"  # nftables, mock
    isolation_threshold: int = 85
    rate_limit_threshold: int = 60
    default_ban_duration_seconds: int = 900
    repeat_offender_ban_duration_seconds: int = 3600
    max_ban_duration_seconds: int = 86400
    allowlist_cidrs: list[str] = field(
        default_factory=lambda: [
            "127.0.0.0/8",
            "::1/128",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
        ]
    )
    table_name: str = "bastion"


@dataclass(slots=True)
class TelemetryConfig:
    """Authentication log telemetry ingestion settings."""

    source: str = "journald"  # journald, file, stdin
    journal_units: list[str] = field(
        default_factory=lambda: ["ssh.service", "sshd.service"]
    )
    journal_identifier: str | None = "sshd"
    log_file_path: str | None = None


@dataclass(slots=True)
class DaemonConfig:
    """Service runtime, worker scheduling, and health monitoring settings."""

    health_check_interval_seconds: int = 30
    reconciliation_interval_seconds: int = 60
    journal_retry_backoff_seconds: int = 5
    max_collector_retries: int = 10
    health_state_path: str = "~/.local/share/bastion/health.json"
    log_level: str = "INFO"
    log_format: str = "text"  # text, json


@dataclass(slots=True)
class BastionConfig:
    """Root configuration for B.A.S.T.I.O.N. Sentinel Core."""

    config_version: int = 1
    storage: StorageConfig = field(default_factory=StorageConfig)
    detectors: DetectorsConfig = field(default_factory=DetectorsConfig)
    risk: RiskConfig = field(default_factory=RiskConfig)
    response: ResponseConfig = field(default_factory=ResponseConfig)
    telemetry: TelemetryConfig = field(default_factory=TelemetryConfig)
    daemon: DaemonConfig = field(default_factory=DaemonConfig)
    loaded_from: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def validate_config(config: BastionConfig) -> list[str]:
    """Validate a BastionConfig instance and return a list of validation errors."""
    errors: list[str] = []

    # Config version
    if config.config_version < 1:
        errors.append(f"config_version must be >= 1, got {config.config_version}")

    # Storage
    if not config.storage.db_path or not config.storage.db_path.strip():
        errors.append("storage.db_path cannot be empty")

    # Detectors
    bf = config.detectors.brute_force
    if bf.threshold <= 0:
        errors.append(f"detectors.brute_force.threshold must be > 0, got {bf.threshold}")
    if bf.window_seconds <= 0:
        errors.append(f"detectors.brute_force.window_seconds must be > 0, got {bf.window_seconds}")

    spray = config.detectors.password_spray
    if spray.min_usernames <= 0:
        errors.append(f"detectors.password_spray.min_usernames must be > 0, got {spray.min_usernames}")
    if spray.max_attempts_per_user <= 0:
        errors.append(f"detectors.password_spray.max_attempts_per_user must be > 0, got {spray.max_attempts_per_user}")
    if spray.window_seconds <= 0:
        errors.append(f"detectors.password_spray.window_seconds must be > 0, got {spray.window_seconds}")

    enum_cfg = config.detectors.enumeration
    if enum_cfg.threshold <= 0:
        errors.append(f"detectors.enumeration.threshold must be > 0, got {enum_cfg.threshold}")
    if enum_cfg.window_seconds <= 0:
        errors.append(f"detectors.enumeration.window_seconds must be > 0, got {enum_cfg.window_seconds}")

    burst = config.detectors.burst
    if burst.threshold <= 0:
        errors.append(f"detectors.burst.threshold must be > 0, got {burst.threshold}")
    if burst.window_seconds <= 0:
        errors.append(f"detectors.burst.window_seconds must be > 0, got {burst.window_seconds}")

    # Risk Scoring
    risk = config.risk
    if not (0 <= risk.medium_threshold <= 100):
        errors.append(f"risk.medium_threshold must be between 0 and 100, got {risk.medium_threshold}")
    if not (0 <= risk.high_threshold <= 100):
        errors.append(f"risk.high_threshold must be between 0 and 100, got {risk.high_threshold}")
    if not (0 <= risk.critical_threshold <= 100):
        errors.append(f"risk.critical_threshold must be between 0 and 100, got {risk.critical_threshold}")

    if not (risk.medium_threshold < risk.high_threshold < risk.critical_threshold):
        errors.append(
            f"Risk thresholds must strictly satisfy medium < high < critical "
            f"(got {risk.medium_threshold} < {risk.high_threshold} < {risk.critical_threshold})"
        )

    for weight_name in [
        "failed_auth_weight",
        "invalid_user_weight",
        "burst_velocity_weight",
        "brute_force_weight",
        "password_spray_weight",
        "enumeration_weight",
        "max_attempts_weight",
        "repeat_offender_weight",
    ]:
        val = getattr(risk, weight_name)
        if val < 0:
            errors.append(f"risk.{weight_name} must be >= 0, got {val}")

    # Response & Defense
    resp = config.response
    valid_modes = {"dry_run", "manual", "automatic", "disabled"}
    if resp.mode not in valid_modes:
        errors.append(f"response.mode must be one of {sorted(valid_modes)}, got '{resp.mode}'")

    valid_backends = {"nftables", "mock"}
    if resp.backend not in valid_backends:
        errors.append(f"response.backend must be one of {sorted(valid_backends)}, got '{resp.backend}'")

    if not (0 <= resp.rate_limit_threshold <= 100):
        errors.append(f"response.rate_limit_threshold must be between 0 and 100, got {resp.rate_limit_threshold}")
    if not (0 <= resp.isolation_threshold <= 100):
        errors.append(f"response.isolation_threshold must be between 0 and 100, got {resp.isolation_threshold}")
    if resp.rate_limit_threshold > resp.isolation_threshold:
        errors.append(
            f"response.rate_limit_threshold ({resp.rate_limit_threshold}) cannot exceed "
            f"isolation_threshold ({resp.isolation_threshold})"
        )

    if resp.default_ban_duration_seconds <= 0:
        errors.append(f"response.default_ban_duration_seconds must be > 0, got {resp.default_ban_duration_seconds}")
    if resp.repeat_offender_ban_duration_seconds < resp.default_ban_duration_seconds:
        errors.append(
            f"response.repeat_offender_ban_duration_seconds ({resp.repeat_offender_ban_duration_seconds}) "
            f"must be >= default_ban_duration_seconds ({resp.default_ban_duration_seconds})"
        )
    if resp.max_ban_duration_seconds < resp.repeat_offender_ban_duration_seconds:
        errors.append(
            f"response.max_ban_duration_seconds ({resp.max_ban_duration_seconds}) "
            f"must be >= repeat_offender_ban_duration_seconds ({resp.repeat_offender_ban_duration_seconds})"
        )

    if not resp.table_name or not re.match(r"^[a-zA-Z0-9_-]+$", resp.table_name):
        errors.append(f"response.table_name must be a valid alphanumeric identifier, got '{resp.table_name}'")

    for cidr in resp.allowlist_cidrs:
        try:
            ipaddress.ip_network(cidr, strict=False)
        except ValueError as exc:
            errors.append(f"Invalid CIDR in response.allowlist_cidrs '{cidr}': {exc}")

    # Telemetry
    telem = config.telemetry
    valid_sources = {"journald", "file", "stdin"}
    if telem.source not in valid_sources:
        errors.append(f"telemetry.source must be one of {sorted(valid_sources)}, got '{telem.source}'")
    if telem.source == "file" and not telem.log_file_path:
        errors.append("telemetry.log_file_path must be specified when telemetry.source is 'file'")
    if telem.source == "journald" and not telem.journal_units and not telem.journal_identifier:
        errors.append("telemetry requires at least one unit in journal_units or a journal_identifier")

    # Daemon
    daemon = config.daemon
    if daemon.health_check_interval_seconds <= 0:
        errors.append(f"daemon.health_check_interval_seconds must be > 0, got {daemon.health_check_interval_seconds}")
    if daemon.reconciliation_interval_seconds <= 0:
        errors.append(f"daemon.reconciliation_interval_seconds must be > 0, got {daemon.reconciliation_interval_seconds}")
    if daemon.journal_retry_backoff_seconds <= 0:
        errors.append(f"daemon.journal_retry_backoff_seconds must be > 0, got {daemon.journal_retry_backoff_seconds}")
    if daemon.max_collector_retries <= 0:
        errors.append(f"daemon.max_collector_retries must be > 0, got {daemon.max_collector_retries}")
    if daemon.log_level.upper() not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
        errors.append(f"daemon.log_level must be a valid log level, got '{daemon.log_level}'")
    if daemon.log_format not in {"text", "json"}:
        errors.append(f"daemon.log_format must be 'text' or 'json', got '{daemon.log_format}'")

    return errors


def validate_config_strict(config: BastionConfig) -> None:
    """Validate a BastionConfig instance and raise ConfigValidationError on failure."""
    errors = validate_config(config)
    if errors:
        raise ConfigValidationError(errors)


def find_config_file(explicit_path: str | Path | None = None) -> Path | None:
    """Locate the configuration file based on standard precedence."""
    if explicit_path:
        p = Path(explicit_path).expanduser().resolve()
        if p.exists():
            return p
        raise FileNotFoundError(f"Configuration file not found: {explicit_path}")

    env_path = os.environ.get("BASTION_CONFIG")
    if env_path:
        p = Path(env_path).expanduser().resolve()
        if p.exists():
            return p

    candidates = [
        Path("bastion.toml"),
        Path("~/.config/bastion/bastion.toml").expanduser(),
        Path("/etc/bastion/bastion.toml"),
    ]

    for cand in candidates:
        if cand.exists():
            return cand.resolve()

    return None


def load_config(config_path: str | Path | None = None) -> BastionConfig:
    """Load configuration from TOML file or return defaults."""
    found_path = find_config_file(config_path)
    if not found_path:
        return BastionConfig()

    try:
        with open(found_path, "rb") as f:
            raw = tomllib.load(f)
    except Exception as exc:
        raise RuntimeError(f"Failed to parse config '{found_path}': {exc}") from exc

    config_version = raw.get("config_version", 1)

    # Parse storage
    raw_storage = raw.get("storage", {})
    storage_cfg = StorageConfig(
        db_path=raw_storage.get("db_path", "~/.local/share/bastion/bastion.db")
    )

    # Parse detectors
    raw_detectors = raw.get("detectors", {})
    bf_raw = raw_detectors.get("brute_force", {})
    spray_raw = raw_detectors.get("password_spray", {})
    enum_raw = raw_detectors.get("enumeration", {})
    burst_raw = raw_detectors.get("burst", {})

    detectors_cfg = DetectorsConfig(
        brute_force=BruteForceConfig(
            enabled=bf_raw.get("enabled", True),
            threshold=bf_raw.get("threshold", 10),
            window_seconds=bf_raw.get("window_seconds", 60),
        ),
        password_spray=PasswordSprayConfig(
            enabled=spray_raw.get("enabled", True),
            min_usernames=spray_raw.get("min_usernames", 3),
            max_attempts_per_user=spray_raw.get("max_attempts_per_user", 3),
            window_seconds=spray_raw.get("window_seconds", 120),
        ),
        enumeration=EnumerationConfig(
            enabled=enum_raw.get("enabled", True),
            threshold=enum_raw.get("threshold", 4),
            window_seconds=enum_raw.get("window_seconds", 60),
        ),
        burst=BurstConfig(
            enabled=burst_raw.get("enabled", True),
            threshold=burst_raw.get("threshold", 5),
            window_seconds=burst_raw.get("window_seconds", 5),
        ),
    )

    # Parse risk
    raw_risk = raw.get("risk", {})
    risk_cfg = RiskConfig(
        medium_threshold=raw_risk.get("medium_threshold", 40),
        high_threshold=raw_risk.get("high_threshold", 70),
        critical_threshold=raw_risk.get("critical_threshold", 85),
        failed_auth_weight=raw_risk.get("failed_auth_weight", 5),
        invalid_user_weight=raw_risk.get("invalid_user_weight", 10),
        burst_velocity_weight=raw_risk.get("burst_velocity_weight", 25),
        brute_force_weight=raw_risk.get("brute_force_weight", 20),
        password_spray_weight=raw_risk.get("password_spray_weight", 20),
        enumeration_weight=raw_risk.get("enumeration_weight", 20),
        max_attempts_weight=raw_risk.get("max_attempts_weight", 20),
        repeat_offender_weight=raw_risk.get("repeat_offender_weight", 15),
        success_auth_weight=raw_risk.get("success_auth_weight", -10),
        trusted_ip_discount=raw_risk.get("trusted_ip_discount", -100),
        trusted_ips=raw_risk.get("trusted_ips", ["127.0.0.1", "::1", "localhost"]),
    )

    # Parse response
    raw_response = raw.get("response", {})
    response_cfg = ResponseConfig(
        mode=raw_response.get("mode", "dry_run"),
        backend=raw_response.get("backend", "nftables"),
        isolation_threshold=raw_response.get("isolation_threshold", 85),
        rate_limit_threshold=raw_response.get("rate_limit_threshold", 60),
        default_ban_duration_seconds=raw_response.get("default_ban_duration_seconds", 900),
        repeat_offender_ban_duration_seconds=raw_response.get("repeat_offender_ban_duration_seconds", 3600),
        max_ban_duration_seconds=raw_response.get("max_ban_duration_seconds", 86400),
        allowlist_cidrs=raw_response.get(
            "allowlist_cidrs",
            [
                "127.0.0.0/8",
                "::1/128",
                "10.0.0.0/8",
                "172.16.0.0/12",
                "192.168.0.0/16",
            ],
        ),
        table_name=raw_response.get("table_name", "bastion"),
    )

    # Parse telemetry
    raw_telemetry = raw.get("telemetry", {})
    telemetry_cfg = TelemetryConfig(
        source=raw_telemetry.get("source", "journald"),
        journal_units=raw_telemetry.get("journal_units", ["ssh.service", "sshd.service"]),
        journal_identifier=raw_telemetry.get("journal_identifier", "sshd"),
        log_file_path=raw_telemetry.get("log_file_path", None),
    )

    # Parse daemon
    raw_daemon = raw.get("daemon", {})
    daemon_cfg = DaemonConfig(
        health_check_interval_seconds=raw_daemon.get("health_check_interval_seconds", 30),
        reconciliation_interval_seconds=raw_daemon.get("reconciliation_interval_seconds", 60),
        journal_retry_backoff_seconds=raw_daemon.get("journal_retry_backoff_seconds", 5),
        max_collector_retries=raw_daemon.get("max_collector_retries", 10),
        health_state_path=raw_daemon.get("health_state_path", "~/.local/share/bastion/health.json"),
        log_level=raw_daemon.get("log_level", "INFO"),
        log_format=raw_daemon.get("log_format", "text"),
    )

    return BastionConfig(
        config_version=config_version,
        storage=storage_cfg,
        detectors=detectors_cfg,
        risk=risk_cfg,
        response=response_cfg,
        telemetry=telemetry_cfg,
        daemon=daemon_cfg,
        loaded_from=str(found_path),
    )
