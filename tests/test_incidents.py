"""Unit tests for the Incident model and lifecycle management."""

from datetime import datetime, timezone

from bastion.incidents.manager import IncidentManager
from bastion.incidents.models import Incident, IncidentStatus
from bastion.models.actors import Severity
from bastion.storage.sqlite import SQLiteStorage


def test_incident_creation_and_persistence() -> None:
    storage = SQLiteStorage(":memory:")
    manager = IncidentManager(storage)

    incident = manager.create_incident(
        title="Coordinated Password Spray Campaign",
        severity=Severity.HIGH,
        risk_score=85,
        summary="Automated multi-account probing detected.",
        actors=["198.51.100.23"],
        events=[1, 2, 3],
        iocs=["ioc-12345"],
        techniques=["T1110.003"],
    )

    assert incident.incident_id.startswith("inc-")
    assert incident.status == IncidentStatus.OPEN
    assert incident.severity == Severity.HIGH
    assert incident.risk_score == 85
    assert incident.related_actors == ["198.51.100.23"]
    assert incident.related_events == [1, 2, 3]

    # Fetch from storage
    fetched = manager.get_incident(incident.incident_id)
    assert fetched is not None
    assert fetched.title == "Coordinated Password Spray Campaign"
    assert fetched.related_events == [1, 2, 3]
    assert fetched.related_actors == ["198.51.100.23"]


def test_incident_status_transitions() -> None:
    storage = SQLiteStorage(":memory:")
    manager = IncidentManager(storage)

    inc = manager.create_incident(
        title="Active Brute Force Incident",
        severity=Severity.MEDIUM,
        risk_score=60,
    )
    assert inc.status == IncidentStatus.OPEN

    # Update to investigating
    updated = manager.update_status(inc.incident_id, IncidentStatus.INVESTIGATING, notes="Assigned to security analyst")
    assert updated is not None
    assert updated.status == IncidentStatus.INVESTIGATING
    assert "Assigned to security analyst" in updated.summary

    # Update to contained
    contained = manager.update_status(inc.incident_id, "contained", notes="Host firewall rules applied")
    assert contained is not None
    assert contained.status == IncidentStatus.CONTAINED


def test_incident_search_and_active_actor_lookup() -> None:
    storage = SQLiteStorage(":memory:")
    manager = IncidentManager(storage)

    inc1 = manager.create_incident(
        title="Incident 1",
        actors=["198.51.100.23"],
    )
    inc2 = manager.create_incident(
        title="Incident 2",
        actors=["203.0.113.50"],
    )
    # Close inc2
    manager.update_status(inc2.incident_id, IncidentStatus.CLOSED)

    # Active lookup for 198.51.100.23 should find inc1
    active_inc = manager.find_active_incident_for_actor("198.51.100.23")
    assert active_inc is not None
    assert active_inc.incident_id == inc1.incident_id

    # Active lookup for 203.0.113.50 should be None because it's closed
    active_inc2 = manager.find_active_incident_for_actor("203.0.113.50")
    assert active_inc2 is None
