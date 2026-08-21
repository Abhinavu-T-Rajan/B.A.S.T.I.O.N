from __future__ import annotations

import collections
from datetime import datetime, timezone
from typing import TYPE_CHECKING, List, Optional

from bastion.attack.registry import AttackRegistry
from bastion.correlation.models import CorrelationContext
from bastion.detection.base import DetectionResult
from bastion.incidents.manager import IncidentManager
from bastion.incidents.models import Incident, IncidentStatus
from bastion.intelligence.manager import IOCManager
from bastion.intelligence.models import IOCRecord
from bastion.models.actors import Severity, ThreatActorProfile
from bastion.models.events import SecurityEvent

if TYPE_CHECKING:
    from bastion.storage.sqlite import SQLiteStorage


class CorrelationEngine:
    """Multi-signal correlation engine aggregating events, IOCs, detections, and incidents."""

    def __init__(
        self,
        storage: SQLiteStorage,
        ioc_manager: IOCManager,
        incident_manager: IncidentManager,
        dedup_window_seconds: int = 30,
    ) -> None:
        self.storage = storage
        self.ioc_manager = ioc_manager
        self.incident_manager = incident_manager
        self.dedup_window_seconds = dedup_window_seconds
        # Rolling cache for alert deduplication: (ip, detector_name) -> timestamp
        self._recent_alerts: dict[tuple[str, str], float] = {}

    def correlate(
        self,
        event: SecurityEvent,
        detections: List[DetectionResult],
        actor: ThreatActorProfile,
        event_id: Optional[int] = None,
    ) -> CorrelationContext:
        """Correlate a single security event with threat intelligence, ATT&CK, and incidents."""
        # 1. Match IOCs
        matched_iocs = self.ioc_manager.match_event(event)
        if matched_iocs:
            ioc_ids = [ioc.ioc_id for ioc in matched_iocs]
            actor.associated_iocs = list(set(actor.associated_iocs + ioc_ids))

        # 2. Extract MITRE ATT&CK Techniques
        detector_names = [d.detector_name for d in detections]
        attack_techniques = AttackRegistry.get_techniques_for_detectors(detector_names)

        # 3. Alert Deduplication Check (only for actively triggered detectors)
        now_ts = event.timestamp.timestamp()
        is_duplicate = False
        triggered_detections = [d for d in detections if d.detected]
        if triggered_detections:
            for d in triggered_detections:
                key = (event.source_ip, d.detector_name)
                last_time = self._recent_alerts.get(key)
                if last_time and (now_ts - last_time) < self.dedup_window_seconds:
                    is_duplicate = True
                else:
                    self._recent_alerts[key] = now_ts

        # Cleanup older alert cache entries
        self._clean_dedup_cache(now_ts)

        # 4. Incident Correlation & Aggregation
        incident = self._correlate_incident(
            event=event,
            detections=detections,
            matched_iocs=matched_iocs,
            attack_techniques=attack_techniques,
            actor=actor,
            event_id=event_id,
        )

        return CorrelationContext(
            event=event,
            detections=detections,
            matched_iocs=matched_iocs,
            attack_techniques=attack_techniques,
            incident=incident,
            is_duplicate_alert=is_duplicate,
            actor=actor,
        )

    def _correlate_incident(
        self,
        event: SecurityEvent,
        detections: List[DetectionResult],
        matched_iocs: List[IOCRecord],
        attack_techniques: list,
        actor: ThreatActorProfile,
        event_id: Optional[int],
    ) -> Optional[Incident]:
        """Correlate security activity into an active incident or create a new incident if threshold met."""
        # Find active incident involving this actor/IP
        incident = self.incident_manager.find_active_incident_for_actor(event.source_ip)

        # Determine if current activity warrants an incident
        should_create = (
            actor.threat_score >= 70
            or len(detections) >= 2
            or len(matched_iocs) > 0
        )

        if not incident and should_create:
            title = f"Attack Activity from {event.source_ip}"
            if matched_iocs:
                title = f"IOC Match & Attack Activity from {event.source_ip}"
            elif any(d.detector_name == "password_spray" for d in detections):
                title = f"Password Spraying Campaign from {event.source_ip}"
            elif any(d.detector_name == "burst" for d in detections):
                title = f"High-Velocity Brute Force from {event.source_ip}"

            tech_ids = [t.technique_id for t in attack_techniques]
            ioc_ids = [i.ioc_id for i in matched_iocs]
            event_list = [event_id] if event_id else []

            incident = self.incident_manager.create_incident(
                title=title,
                severity=actor.severity,
                risk_score=actor.threat_score,
                summary=f"Automated incident opened due to threat score {actor.threat_score}/100 and behavioral signals.",
                actors=[event.source_ip],
                events=event_list,
                iocs=ioc_ids,
                techniques=tech_ids,
            )
            if incident.incident_id not in actor.related_incidents:
                actor.related_incidents.append(incident.incident_id)

        elif incident:
            # Update existing active incident
            incident.last_seen = event.timestamp
            incident.risk_score = max(incident.risk_score, actor.threat_score)
            if actor.severity in (Severity.HIGH, Severity.CRITICAL):
                incident.severity = actor.severity

            # Merge techniques
            existing_techs = set(incident.attack_techniques)
            for t in attack_techniques:
                existing_techs.add(t.technique_id)
            incident.attack_techniques = sorted(existing_techs)

            # Merge IOCs
            existing_iocs = set(incident.related_iocs)
            for i in matched_iocs:
                existing_iocs.add(i.ioc_id)
            incident.related_iocs = sorted(existing_iocs)

            # Append event ID if provided
            if event_id and event_id not in incident.related_events:
                incident.related_events.append(event_id)

            self.incident_manager.update_incident(incident)
            if incident.incident_id not in actor.related_incidents:
                actor.related_incidents.append(incident.incident_id)

        return incident

    def _clean_dedup_cache(self, current_ts: float) -> None:
        """Evict stale deduplication keys."""
        cutoff = current_ts - (self.dedup_window_seconds * 2)
        stale = [k for k, v in self._recent_alerts.items() if v < cutoff]
        for k in stale:
            del self._recent_alerts[k]
