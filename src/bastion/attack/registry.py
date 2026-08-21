from __future__ import annotations

from typing import Dict, List, Optional

from bastion.attack.models import AttackMapping, AttackTactic, AttackTechnique


class AttackRegistry:
    """Catalog of authentic MITRE ATT&CK techniques and detector mappings."""

    TECHNIQUES: Dict[str, AttackTechnique] = {
        "T1110.001": AttackTechnique(
            technique_id="T1110.001",
            name="Brute Force: Password Guessing",
            tactic=AttackTactic.CREDENTIAL_ACCESS,
            description="Adversaries may systematically guess passwords to gain access to accounts.",
            url="https://attack.mitre.org/techniques/T1110/001/",
        ),
        "T1110.003": AttackTechnique(
            technique_id="T1110.003",
            name="Brute Force: Password Spraying",
            tactic=AttackTactic.CREDENTIAL_ACCESS,
            description="Adversaries may iterate through passwords across many accounts to avoid account lockouts.",
            url="https://attack.mitre.org/techniques/T1110/003/",
        ),
        "T1087.001": AttackTechnique(
            technique_id="T1087.001",
            name="Account Discovery: Local Account",
            tactic=AttackTactic.DISCOVERY,
            description="Adversaries may attempt to get a listing of local system accounts through enumeration.",
            url="https://attack.mitre.org/techniques/T1087/001/",
        ),
        "T1499": AttackTechnique(
            technique_id="T1499",
            name="Endpoint Denial of Service",
            tactic=AttackTactic.IMPACT,
            description="Adversaries may target endpoints with high-volume requests to degrade or exhaust availability.",
            url="https://attack.mitre.org/techniques/T1499/",
        ),
        "T1078": AttackTechnique(
            technique_id="T1078",
            name="Valid Accounts",
            tactic=AttackTactic.DEFENSE_EVASION,
            description="Adversaries may obtain and abuse credentials of existing accounts.",
            url="https://attack.mitre.org/techniques/T1078/",
        ),
    }

    DETECTOR_MAPPINGS: Dict[str, AttackMapping] = {
        "brute_force": AttackMapping(
            detector_name="brute_force",
            technique_id="T1110.001",
            technique_name="Brute Force: Password Guessing",
            tactic=AttackTactic.CREDENTIAL_ACCESS,
            confidence=90,
        ),
        "password_spray": AttackMapping(
            detector_name="password_spray",
            technique_id="T1110.003",
            technique_name="Brute Force: Password Spraying",
            tactic=AttackTactic.CREDENTIAL_ACCESS,
            confidence=95,
        ),
        "username_enumeration": AttackMapping(
            detector_name="username_enumeration",
            technique_id="T1087.001",
            technique_name="Account Discovery: Local Account",
            tactic=AttackTactic.DISCOVERY,
            confidence=85,
        ),
        "burst": AttackMapping(
            detector_name="burst",
            technique_id="T1499",
            technique_name="Endpoint Denial of Service",
            tactic=AttackTactic.IMPACT,
            confidence=80,
        ),
    }

    @classmethod
    def get_technique(cls, technique_id: str) -> Optional[AttackTechnique]:
        """Lookup a technique by MITRE ID (e.g. 'T1110.001')."""
        return cls.TECHNIQUES.get(technique_id.strip().upper())

    @classmethod
    def list_techniques(cls) -> List[AttackTechnique]:
        """List all cataloged MITRE ATT&CK techniques."""
        return list(cls.TECHNIQUES.values())

    @classmethod
    def get_mapping(cls, detector_name: str) -> Optional[AttackMapping]:
        """Lookup ATT&CK mapping for a detector name."""
        return cls.DETECTOR_MAPPINGS.get(detector_name.strip().lower())

    @classmethod
    def get_techniques_for_detectors(cls, detector_names: List[str]) -> List[AttackTechnique]:
        """Return unique ATT&CK techniques corresponding to a list of detector names."""
        techniques: List[AttackTechnique] = []
        seen: set[str] = set()

        for name in detector_names:
            mapping = cls.get_mapping(name)
            if mapping and mapping.technique_id not in seen:
                technique = cls.get_technique(mapping.technique_id)
                if technique:
                    techniques.append(technique)
                    seen.add(mapping.technique_id)

        return techniques
