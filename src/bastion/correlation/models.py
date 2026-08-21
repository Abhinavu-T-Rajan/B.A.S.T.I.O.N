from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, List, Optional

from bastion.attack.models import AttackTechnique
from bastion.detection.base import DetectionResult
from bastion.incidents.models import Incident
from bastion.intelligence.models import IOCRecord
from bastion.models.actors import ThreatActorProfile
from bastion.models.events import SecurityEvent


@dataclass
class CorrelationContext:
    """Aggregated correlation result linking an event across threat subsystems."""

    event: SecurityEvent
    detections: List[DetectionResult] = field(default_factory=list)
    matched_iocs: List[IOCRecord] = field(default_factory=list)
    attack_techniques: List[AttackTechnique] = field(default_factory=list)
    incident: Optional[Incident] = None
    is_duplicate_alert: bool = False
    actor: Optional[ThreatActorProfile] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_ip": self.event.source_ip,
            "detections": [d.detector_name for d in self.detections],
            "matched_iocs": [f"{ioc.ioc_type}:{ioc.value}" for ioc in self.matched_iocs],
            "attack_techniques": [t.technique_id for t in self.attack_techniques],
            "incident_id": self.incident.incident_id if self.incident else None,
            "is_duplicate_alert": self.is_duplicate_alert,
        }
