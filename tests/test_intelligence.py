"""Unit tests for the Threat Intelligence and IOC subsystem."""

from datetime import datetime, timezone
import pytest

from bastion.intelligence.manager import IOCManager
from bastion.intelligence.models import IOCRecord, IOCStatus, IOCType, Provenance
from bastion.intelligence.validator import IOCValidator
from bastion.models.events import EventType, SecurityEvent, ServiceType
from bastion.storage.sqlite import SQLiteStorage


def test_ioc_validator_valid_types() -> None:
    # IP
    valid_ip, val = IOCValidator.validate(IOCType.IP, "198.51.100.23")
    assert valid_ip is True
    assert val == "198.51.100.23"

    # Domain
    valid_dom, val = IOCValidator.validate(IOCType.DOMAIN, "malicious-c2.example.com")
    assert valid_dom is True
    assert val == "malicious-c2.example.com"

    # Hashes
    valid_md5, val = IOCValidator.validate(IOCType.HASH_MD5, "d41d8cd98f00b204e9800998ecf8427e")
    assert valid_md5 is True
    assert val == "d41d8cd98f00b204e9800998ecf8427e"

    valid_sha256, val = IOCValidator.validate(
        IOCType.HASH_SHA256,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    )
    assert valid_sha256 is True

    # Username
    valid_user, val = IOCValidator.validate(IOCType.USERNAME, "admin_compromised")
    assert valid_user is True
    assert val == "admin_compromised"


def test_ioc_validator_invalid_inputs() -> None:
    # Invalid IP
    valid, err = IOCValidator.validate(IOCType.IP, "999.999.999.999")
    assert valid is False

    # Invalid Domain
    valid, err = IOCValidator.validate(IOCType.DOMAIN, "invalid_domain..com")
    assert valid is False

    # Invalid Hash length
    valid, err = IOCValidator.validate(IOCType.HASH_MD5, "tooshort")
    assert valid is False

    # Empty value
    valid, err = IOCValidator.validate(IOCType.USERNAME, "   ")
    assert valid is False


def test_ioc_manager_crud_operations() -> None:
    storage = SQLiteStorage(":memory:")
    manager = IOCManager(storage)

    # 1. Add IOC
    ioc = manager.add_ioc(
        ioc_type=IOCType.IP,
        value="198.51.100.23",
        confidence=90,
        source="threat_intel_feed",
        provenance=Provenance.CONFIRMED,
        tags=["ssh_scanner", "known_c2"],
        notes="High-velocity brute force scanner",
    )
    assert ioc.ioc_id.startswith("ioc-")
    assert ioc.confidence == 90
    assert "ssh_scanner" in ioc.tags

    # 2. Lookup by ID
    fetched = manager.get_ioc(ioc.ioc_id)
    assert fetched is not None
    assert fetched.value == "198.51.100.23"

    # 3. List with filtering
    iocs = manager.list_iocs(ioc_type=IOCType.IP, status=IOCStatus.ACTIVE)
    assert len(iocs) == 1

    # 4. Search
    results = manager.search("scanner")
    assert len(results) == 1
    assert results[0].value == "198.51.100.23"

    # 5. Delete
    deleted = manager.delete_ioc(ioc.ioc_id)
    assert deleted is True
    assert manager.get_ioc(ioc.ioc_id) is None


def test_ioc_manager_match_event() -> None:
    storage = SQLiteStorage(":memory:")
    manager = IOCManager(storage)

    manager.add_ioc(
        ioc_type=IOCType.IP,
        value="198.51.100.23",
        confidence=85,
    )
    manager.add_ioc(
        ioc_type=IOCType.USERNAME,
        value="compromised_account",
        confidence=95,
    )

    ev_match = SecurityEvent(
        timestamp=datetime.now(timezone.utc),
        source_ip="198.51.100.23",
        service=ServiceType.SSH,
        event_type=EventType.AUTH_FAILURE,
        username="compromised_account",
    )
    matches = manager.match_event(ev_match)
    assert len(matches) == 2

    ev_no_match = SecurityEvent(
        timestamp=datetime.now(timezone.utc),
        source_ip="10.0.0.1",
        service=ServiceType.SSH,
        event_type=EventType.AUTH_FAILURE,
        username="clean_user",
    )
    matches_clean = manager.match_event(ev_no_match)
    assert len(matches_clean) == 0
