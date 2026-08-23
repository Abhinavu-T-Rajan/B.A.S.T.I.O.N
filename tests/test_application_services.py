from __future__ import annotations

from pathlib import Path

from bastion.config import BastionConfig
from bastion.firewall.mock import MockFirewallBackend
from bastion.services.defense import DefenseAppService
from bastion.services.health import HealthAppService
from bastion.services.incidents import IncidentAppService
from bastion.services.intelligence import IntelligenceAppService
from bastion.storage.sqlite import SQLiteStorage


def test_defense_app_service_workflows(tmp_path: Path) -> None:
    """Test DefenseAppService status, threat inspection, manual ban, unban, and firewall flush."""
    db_path = str(tmp_path / "defense_test.db")
    storage = SQLiteStorage(db_path)
    firewall = MockFirewallBackend()

    service = DefenseAppService(storage=storage, firewall=firewall)

    # 1. Overview
    overview = service.get_status_overview(response_mode="DRY_RUN")
    assert overview["response_mode"] == "DRY_RUN"
    assert overview["firewall_backend"] == "mock"
    assert overview["firewall_available"] is True

    # 2. Ban IP
    success, msg, ban = service.ban_ip(
        source_ip="203.0.113.88",
        duration_seconds=600,
        reason="Manual operator ban",
    )
    assert success is True
    assert ban is not None
    assert ban.source_ip == "203.0.113.88"
    assert firewall.is_ip_blocked("203.0.113.88") is True

    # 3. List bans
    bans = service.list_bans(active_only=True)
    assert len(bans) == 1
    assert bans[0].source_ip == "203.0.113.88"

    # 4. Inspect IP
    inspect_data = service.inspect_ip("203.0.113.88")
    assert inspect_data["active_ban"] is not None

    # 5. Unban IP
    unban_success, unban_msg = service.unban_ip("203.0.113.88")
    assert unban_success is True
    assert firewall.is_ip_blocked("203.0.113.88") is False

    # 6. Flush firewall
    firewall.block_ip("198.51.100.1")
    flush_success, flush_msg = service.flush_firewall()
    assert flush_success is True
    assert len(firewall.list_blocked_ips()) == 0

    storage.close()


def test_intelligence_app_service_workflows(tmp_path: Path) -> None:
    """Test IntelligenceAppService IOC addition, listing, search, and ATT&CK mapping."""
    db_path = str(tmp_path / "intel_test.db")
    storage = SQLiteStorage(db_path)
    service = IntelligenceAppService(storage=storage)

    # 1. Add IOC
    success, msg, ioc = service.add_ioc(
        ioc_type="ipv4",
        value="198.51.100.77",
        description="Known malicious scanner",
        confidence=90,
    )
    assert success is True
    assert ioc is not None
    assert ioc.value == "198.51.100.77"

    # 2. List IOCs
    iocs = service.list_iocs()
    assert len(iocs) == 1

    # 3. Search IOCs
    found = service.search_iocs("scanner")
    assert len(found) == 1
    assert found[0].value == "198.51.100.77"

    # 4. ATT&CK Catalog
    catalog = service.get_attack_catalog()
    assert len(catalog) >= 4
    tech = service.inspect_technique("T1110.001")
    assert tech is not None
    assert "Password Guessing" in tech["name"]

    # 5. Delete IOC
    del_success, del_msg = service.delete_ioc("198.51.100.77")
    assert del_success is True

    storage.close()


def test_incident_app_service_workflows(tmp_path: Path) -> None:
    """Test IncidentAppService incident creation, status updating, and timeline generation."""
    db_path = str(tmp_path / "incident_test.db")
    storage = SQLiteStorage(db_path)
    service = IncidentAppService(storage=storage)

    # 1. Create incident
    inc = service.create_incident(
        title="Brute-force investigation",
        severity="high",
        description="Repeated SSH authentication failures from multiple IPs",
        actor_ips=["198.51.100.5", "198.51.100.6"],
    )
    assert inc.incident_id.lower().startswith("inc-")
    assert inc.title == "Brute-force investigation"

    # 2. List incidents
    incidents = service.list_incidents()
    assert len(incidents) == 1

    # 3. Update status
    up_success, up_msg = service.update_status(inc.incident_id, "investigating", "Analyzing source IPs")
    assert up_success is True
    fetched = service.get_incident(inc.incident_id)
    assert fetched is not None
    assert fetched.status.value == "investigating"

    # 4. Generate timeline
    timeline = service.generate_timeline("198.51.100.5")
    assert isinstance(timeline, list)

    storage.close()


def test_health_app_service_probe(tmp_path: Path) -> None:
    """Test HealthAppService live health probing and report formatting."""
    db_path = str(tmp_path / "health_test.db")
    storage = SQLiteStorage(db_path)
    firewall = MockFirewallBackend()
    config = BastionConfig()
    config.storage.db_path = db_path
    config.response.backend = "mock"

    snapshot = HealthAppService.probe_live_health(config, storage, firewall)
    assert snapshot.overall_health.value.lower() in {"healthy", "degraded"}
    assert snapshot.subsystems["Database"].status.value.lower() == "healthy"
    assert snapshot.subsystems["Firewall"].status.value.lower() == "healthy"

    report = HealthAppService.format_report(snapshot)
    assert "B.A.S.T.I.O.N. Health" in report

    storage.close()
