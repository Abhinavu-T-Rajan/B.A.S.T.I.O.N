from __future__ import annotations

import os
import tomllib
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


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
class BastionConfig:
    """Root configuration for B.A.S.T.I.O.N."""

    storage: StorageConfig = field(default_factory=StorageConfig)
    detectors: DetectorsConfig = field(default_factory=DetectorsConfig)
    risk: RiskConfig = field(default_factory=RiskConfig)
    response: ResponseConfig = field(default_factory=ResponseConfig)
    loaded_from: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


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

    return BastionConfig(
        storage=storage_cfg,
        detectors=detectors_cfg,
        risk=risk_cfg,
        response=response_cfg,
        loaded_from=str(found_path),
    )
