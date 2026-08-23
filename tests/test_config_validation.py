"""Unit tests for B.A.S.T.I.O.N. configuration validation and schema versioning."""

import pytest

from bastion.config import (
    BastionConfig,
    ConfigValidationError,
    validate_config,
    validate_config_strict,
)


def test_default_config_is_valid() -> None:
    cfg = BastionConfig()
    errors = validate_config(cfg)
    assert errors == []
    validate_config_strict(cfg)


def test_invalid_config_version() -> None:
    cfg = BastionConfig(config_version=0)
    errors = validate_config(cfg)
    assert any("config_version" in e for e in errors)


def test_empty_db_path() -> None:
    cfg = BastionConfig()
    cfg.storage.db_path = ""
    errors = validate_config(cfg)
    assert any("storage.db_path" in e for e in errors)


def test_invalid_detector_thresholds_and_windows() -> None:
    cfg = BastionConfig()
    cfg.detectors.brute_force.threshold = 0
    cfg.detectors.brute_force.window_seconds = -10
    cfg.detectors.password_spray.min_usernames = 0
    cfg.detectors.password_spray.max_attempts_per_user = 0
    cfg.detectors.enumeration.threshold = -1
    cfg.detectors.burst.threshold = 0

    errors = validate_config(cfg)
    assert len(errors) >= 6
    assert any("brute_force.threshold" in e for e in errors)
    assert any("brute_force.window_seconds" in e for e in errors)
    assert any("password_spray.min_usernames" in e for e in errors)
    assert any("enumeration.threshold" in e for e in errors)
    assert any("burst.threshold" in e for e in errors)


def test_invalid_risk_thresholds() -> None:
    # 1. Negative or > 100
    cfg = BastionConfig()
    cfg.risk.medium_threshold = -5
    cfg.risk.high_threshold = 120
    errors = validate_config(cfg)
    assert any("risk.medium_threshold" in e for e in errors)
    assert any("risk.high_threshold" in e for e in errors)

    # 2. Out of order (medium > high)
    cfg2 = BastionConfig()
    cfg2.risk.medium_threshold = 80
    cfg2.risk.high_threshold = 70
    cfg2.risk.critical_threshold = 85
    errors2 = validate_config(cfg2)
    assert any("Risk thresholds must strictly satisfy" in e for e in errors2)


def test_invalid_response_modes_and_backends() -> None:
    cfg = BastionConfig()
    cfg.response.mode = "invalid_mode"
    cfg.response.backend = "iptables_unsupported"
    errors = validate_config(cfg)
    assert any("response.mode" in e for e in errors)
    assert any("response.backend" in e for e in errors)


def test_invalid_ban_durations() -> None:
    cfg = BastionConfig()
    cfg.response.default_ban_duration_seconds = 1000
    cfg.response.repeat_offender_ban_duration_seconds = 500  # less than default
    cfg.response.max_ban_duration_seconds = 200  # less than repeat offender
    errors = validate_config(cfg)
    assert any("repeat_offender_ban_duration_seconds" in e for e in errors)
    assert any("max_ban_duration_seconds" in e for e in errors)


def test_invalid_allowlist_cidrs() -> None:
    cfg = BastionConfig()
    cfg.response.allowlist_cidrs = ["192.168.1.500/24", "invalid-ip", "10.0.0.0/8"]
    errors = validate_config(cfg)
    assert len(errors) == 2
    assert any("192.168.1.500/24" in e for e in errors)
    assert any("invalid-ip" in e for e in errors)


def test_strict_validation_exception() -> None:
    cfg = BastionConfig()
    cfg.response.mode = "unsupported"
    with pytest.raises(ConfigValidationError) as exc:
        validate_config_strict(cfg)
    assert "Configuration validation failed" in str(exc.value)
    assert len(exc.value.errors) == 1
