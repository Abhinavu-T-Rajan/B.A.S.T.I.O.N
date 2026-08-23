"""Unit and regression tests for response-mode safety and accurate dependency health tracking."""

from datetime import datetime, timezone
from pathlib import Path

import pytest

from bastion.cli import build_parser
from bastion.daemon.state import (
    HealthStatus,
    HealthTracker,
    ServiceState,
    Subsystem,
)
from bastion.firewall.mock import MockFirewallBackend
from bastion.models.actors import ActorState, ThreatActorProfile
from bastion.response.ban_manager import BanManager
from bastion.response.engine import ResponseEngine
from bastion.response.models import BanStatus, ResponseAction, ResponseMode
from bastion.response.policy import PolicyConfig, PolicyEngine
from bastion.storage.sqlite import SQLiteStorage


class UnavailableFirewall(MockFirewallBackend):
    def is_available(self) -> bool:
        return False


def test_automatic_response_refused_when_firewall_unavailable() -> None:
    storage = SQLiteStorage(":memory:")
    firewall = UnavailableFirewall()
    ban_manager = BanManager(storage=storage, firewall=firewall)

    policy = PolicyEngine(
        PolicyConfig(
            isolation_threshold=80,
            allowlist_cidrs=[],
        )
    )
    engine = ResponseEngine(
        policy=policy,
        ban_manager=ban_manager,
        default_mode=ResponseMode.AUTOMATIC,
    )

    now = datetime.now(timezone.utc)
    profile = ThreatActorProfile(
        source_ip="198.51.100.77",
        first_seen=now,
        last_seen=now,
        threat_score=95,
        state=ActorState.ACTIVE_THREAT,
    )

    decision, ban = engine.process(profile)

    # Must refuse execution and not claim active isolation
    assert decision.executed is False
    assert decision.mode == ResponseMode.DISABLED
    assert "ENFORCEMENT REFUSED" in decision.reason
    assert ban is not None
    assert ban.status == BanStatus.FAILED


def test_health_tracker_evaluates_firewall_dependency() -> None:
    tracker = HealthTracker(response_mode="AUTOMATIC", firewall_backend="NFTABLES")
    tracker.set_service_state(ServiceState.RUNNING)

    for sub in Subsystem:
        tracker.set_subsystem_health(sub, HealthStatus.HEALTHY, "OK")

    assert tracker.calculate_overall_health() == HealthStatus.HEALTHY

    # Mark firewall as FAILED in automatic mode
    tracker.set_subsystem_health(Subsystem.FIREWALL, HealthStatus.FAILED, "Kernel module not loaded")
    assert tracker.calculate_overall_health() == HealthStatus.FAILED

    report = HealthTracker.format_health_report(tracker.get_snapshot())
    assert "Service       : FAILED" in report
    assert "Firewall      : FAILED" in report
    assert "Response      : DISABLED (Firewall unavailable)" in report


def test_cli_health_reports_degraded_when_firewall_unavailable_in_auto(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cfg_file = tmp_path / "auto_bastion.toml"
    cfg_file.write_text(
        """
        config_version = 1
        [storage]
        db_path = ":memory:"
        [response]
        mode = "automatic"
        backend = "mock"
        """
    )

    # Mock unavailable backend via CLI
    parser = build_parser()
    args = parser.parse_args(["-c", str(cfg_file), "health", "--db", ":memory:"])

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("bastion.cli._get_firewall_backend", lambda cfg, override: UnavailableFirewall())
        ret = args.handler(args)

    assert ret == 1
    captured = capsys.readouterr()
    assert "Firewall      : FAILED" in captured.out
    assert "Response      : DISABLED (Firewall unavailable)" in captured.out
