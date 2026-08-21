"""Unit tests for MITRE ATT&CK technique catalog and detector registry."""

from bastion.attack.models import AttackTactic
from bastion.attack.registry import AttackRegistry


def test_attack_registry_technique_lookup() -> None:
    t1110 = AttackRegistry.get_technique("T1110.001")
    assert t1110 is not None
    assert t1110.name == "Brute Force: Password Guessing"
    assert t1110.tactic == AttackTactic.CREDENTIAL_ACCESS
    assert "https://attack.mitre.org/techniques/T1110/001/" in t1110.url


def test_attack_registry_detector_mappings() -> None:
    spray_mapping = AttackRegistry.get_mapping("password_spray")
    assert spray_mapping is not None
    assert spray_mapping.technique_id == "T1110.003"
    assert spray_mapping.tactic == AttackTactic.CREDENTIAL_ACCESS

    enum_mapping = AttackRegistry.get_mapping("username_enumeration")
    assert enum_mapping is not None
    assert enum_mapping.technique_id == "T1087.001"
    assert enum_mapping.tactic == AttackTactic.DISCOVERY

    burst_mapping = AttackRegistry.get_mapping("burst")
    assert burst_mapping is not None
    assert burst_mapping.technique_id == "T1499"


def test_attack_registry_multiple_techniques() -> None:
    detectors = ["brute_force", "password_spray", "unknown_detector"]
    techs = AttackRegistry.get_techniques_for_detectors(detectors)
    assert len(techs) == 2
    tech_ids = {t.technique_id for t in techs}
    assert "T1110.001" in tech_ids
    assert "T1110.003" in tech_ids
