"""Unit tests for configuration loading."""

from pathlib import Path

from bastion.config import BastionConfig, load_config


def test_default_config() -> None:
    cfg = load_config(config_path=None)
    assert isinstance(cfg, BastionConfig)
    assert cfg.storage.db_path == "~/.local/share/bastion/bastion.db"
    assert cfg.detectors.brute_force.enabled is True
    assert cfg.detectors.password_spray.min_usernames == 3
    assert cfg.risk.critical_threshold == 85
    assert "127.0.0.1" in cfg.risk.trusted_ips


def test_load_custom_toml(tmp_path: Path) -> None:
    toml_content = """
[storage]
db_path = "/tmp/custom_bastion.db"

[detectors.brute_force]
threshold = 5
window_seconds = 30

[risk]
critical_threshold = 90
trusted_ips = ["10.0.0.1", "10.0.0.2"]
"""
    config_file = tmp_path / "custom.toml"
    config_file.write_text(toml_content, encoding="utf-8")

    cfg = load_config(config_file)
    assert cfg.storage.db_path == "/tmp/custom_bastion.db"
    assert cfg.detectors.brute_force.threshold == 5
    assert cfg.detectors.brute_force.window_seconds == 30
    assert cfg.risk.critical_threshold == 90
    assert cfg.risk.trusted_ips == ["10.0.0.1", "10.0.0.2"]
