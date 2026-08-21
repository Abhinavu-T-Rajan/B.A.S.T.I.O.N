from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class AttackTactic(StrEnum):
    """MITRE ATT&CK Tactics."""

    CREDENTIAL_ACCESS = "Credential Access"
    DISCOVERY = "Discovery"
    DEFENSE_EVASION = "Defense Evasion"
    INITIAL_ACCESS = "Initial Access"
    IMPACT = "Impact"
    PERSISTENCE = "Persistence"


@dataclass(frozen=True)
class AttackTechnique:
    """MITRE ATT&CK Technique metadata."""

    technique_id: str
    name: str
    tactic: AttackTactic
    description: str
    url: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "name": self.name,
            "tactic": self.tactic.value,
            "description": self.description,
            "url": self.url,
        }


@dataclass
class AttackMapping:
    """Mapping between a detection/event type and a MITRE ATT&CK technique."""

    detector_name: str
    technique_id: str
    technique_name: str
    tactic: AttackTactic
    confidence: int = 80

    def to_dict(self) -> dict[str, Any]:
        return {
            "detector_name": self.detector_name,
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactic": self.tactic.value,
            "confidence": self.confidence,
        }
