from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from typing import Any, List, Optional

from bastion.attack.models import AttackTechnique
from bastion.attack.registry import AttackRegistry
from bastion.collector.ssh import SSHLogParser
from bastion.correlation.engine import CorrelationEngine
from bastion.correlation.models import CorrelationContext
from bastion.detection.brute_force import DetectionResult
from bastion.detection.engine import DetectionEngine
from bastion.incidents.manager import IncidentManager
from bastion.incidents.models import Incident
from bastion.intelligence.manager import IOCManager
from bastion.intelligence.models import IOCRecord
from bastion.models.actors import Severity, ThreatActorProfile
from bastion.models.events import SecurityEvent
from bastion.response.engine import ResponseEngine
from bastion.response.models import BanRecord, BanStatus, ResponseAction, ResponseDecision, ResponseMode
from bastion.risk.scorer import RiskEngine
from bastion.storage.sqlite import SQLiteStorage


@dataclass(frozen=True, slots=True)
class PipelineResult:
    """Result of processing a single raw telemetry line through the full pipeline."""

    raw_line: str
    event: SecurityEvent | None
    detections: list[DetectionResult] = field(default_factory=list)
    profile: ThreatActorProfile | None = None
    decision: ResponseDecision | None = None
    ban: BanRecord | None = None
    matched_iocs: list[IOCRecord] = field(default_factory=list)
    attack_techniques: list[AttackTechnique] = field(default_factory=list)
    incident: Incident | None = None
    is_alert: bool = False
    alert_message: str | None = None


def format_explainable_alert(
    event: SecurityEvent,
    profile: ThreatActorProfile,
    detections: list[DetectionResult],
    decision: ResponseDecision | None = None,
    ban: BanRecord | None = None,
    matched_iocs: list[IOCRecord] | None = None,
    attack_techniques: list[AttackTechnique] | None = None,
    incident: Incident | None = None,
) -> str:
    """Render a structured, explainable threat alert with threat correlation and ATT&CK context."""
    lines = [
        "🚨 THREAT DETECTED",
        f"Source      : {event.source_ip}",
        f"Service     : {event.service.value.upper()}",
        f"Score       : {profile.threat_score} / 100",
        f"Severity    : {profile.severity.value.upper()}",
        f"State       : {profile.state.value.replace('_', ' ').upper()}",
    ]

    if incident:
        lines.append(f"Incident    : {incident.incident_id} [{incident.status.value.upper()}] - {incident.title}")

    if attack_techniques:
        tech_strs = [f"{t.technique_id} ({t.name})" for t in attack_techniques]
        lines.append(f"MITRE ATT&CK: {', '.join(tech_strs)}")

    if matched_iocs:
        ioc_strs = [f"{ioc.ioc_type.value}:{ioc.value} ({ioc.confidence}% conf)" for ioc in matched_iocs]
        lines.append(f"Matched IOCs: {', '.join(ioc_strs)}")

    lines.append("")
    lines.append("Contributing Factors:")

    if profile.factors:
        for f in profile.factors:
            lines.append(f"  • {f.description}")
    else:
        lines.append("  • None recorded")

    if profile.usernames_targeted:
        users_str = ", ".join(sorted(profile.usernames_targeted)[:8])
        lines.append(f"\nTargeted Users: {users_str}")

    # Defensive Action Summary
    if decision and decision.action in {ResponseAction.TEMPORARY_ISOLATION, ResponseAction.PERMANENT_BAN}:
        dur_str = f"{decision.duration_seconds // 60}m" if decision.duration_seconds else "Permanent"
        if decision.mode == ResponseMode.DRY_RUN:
            action_tag = f"WOULD BLOCK [DRY-RUN] ({dur_str})"
        elif decision.mode == ResponseMode.AUTOMATIC:
            action_tag = f"ISOLATED [ENFORCED] ({dur_str})"
        elif decision.mode == ResponseMode.MANUAL_APPROVAL:
            action_tag = f"PENDING APPROVAL ({dur_str})"
        else:
            action_tag = f"DISABLED"
        lines.append(f"Defense Action    : {action_tag}")
    else:
        lines.append(f"Recommended Action: {profile.recommended_action.value.replace('_', ' ').upper()} (ADVISORY)")

    return "\n".join(lines)


class SentinelPipeline:
    """Real-time event processing pipeline connecting telemetry, detection, threat intelligence, correlation, risk scoring, response, and storage."""

    def __init__(
        self,
        *,
        parser: SSHLogParser | None = None,
        engine: DetectionEngine | None = None,
        risk_engine: RiskEngine | None = None,
        response_engine: ResponseEngine | None = None,
        storage: SQLiteStorage | None = None,
        ioc_manager: IOCManager | None = None,
        incident_manager: IncidentManager | None = None,
        correlation_engine: CorrelationEngine | None = None,
        on_event: Callable[[SecurityEvent], None] | None = None,
        on_alert: Callable[[SecurityEvent, ThreatActorProfile, list[DetectionResult], ResponseDecision | None], None] | None = None,
        alert_min_score: int = 70,
    ) -> None:
        self.parser = parser or SSHLogParser()
        self.engine = engine or DetectionEngine()
        self.risk_engine = risk_engine or RiskEngine()
        self.response_engine = response_engine
        self.storage = storage
        self.ioc_manager = ioc_manager or (IOCManager(storage) if storage else None)
        self.incident_manager = incident_manager or (IncidentManager(storage) if storage else None)
        if correlation_engine:
            self.correlation_engine = correlation_engine
        elif storage and self.ioc_manager and self.incident_manager:
            self.correlation_engine = CorrelationEngine(
                storage=storage,
                ioc_manager=self.ioc_manager,
                incident_manager=self.incident_manager,
            )
        else:
            self.correlation_engine = None

        self.on_event = on_event
        self.on_alert = on_alert
        self.alert_min_score = alert_min_score
        self._actor_cache: dict[str, ThreatActorProfile] = {}

    def process_line(self, raw_line: str) -> PipelineResult:
        """Process a single raw log entry through parser, detection, intelligence correlation, risk scoring, response, and persistence."""
        event = self.parser.parse(raw_line)

        if event is None:
            return PipelineResult(
                raw_line=raw_line,
                event=None,
                detections=[],
                profile=None,
                decision=None,
                ban=None,
                matched_iocs=[],
                attack_techniques=[],
                incident=None,
                is_alert=False,
                alert_message=None,
            )

        # 1. Persist event
        event_id = None
        if self.storage:
            event_id = self.storage.save_event(event)

        if self.on_event:
            self.on_event(event)

        # 2. Evaluate behavioral detectors
        detections = self.engine.evaluate(event)

        # 3. Record triggered detections in storage
        if self.storage:
            for det in detections:
                if det.detected:
                    self.storage.save_detection(
                        source_ip=event.source_ip,
                        detector_name=det.detector_name,
                        reason=det.reason,
                        event_count=det.event_count,
                        threshold=det.threshold,
                        details=det.metadata,
                        timestamp=event.timestamp,
                    )

        # 4. Fetch existing actor profile
        existing_profile: ThreatActorProfile | None = None
        if self.storage:
            existing_profile = self.storage.get_threat_actor(event.source_ip)
        if not existing_profile:
            existing_profile = self._actor_cache.get(event.source_ip)

        # 5. Check IOC matches
        matched_iocs: list[IOCRecord] = []
        if self.ioc_manager:
            matched_iocs = self.ioc_manager.match_event(event)

        # 6. Calculate threat score and updated profile (with IOC factor)
        profile = self.risk_engine.evaluate(
            event=event,
            detections=detections,
            existing_profile=existing_profile,
            matched_iocs=matched_iocs,
        )

        # 7. Threat Correlation & Incidents
        attack_techniques: list[AttackTechnique] = []
        incident: Incident | None = None
        is_duplicate = False

        if self.correlation_engine:
            corr_ctx = self.correlation_engine.correlate(
                event=event,
                detections=detections,
                actor=profile,
                event_id=event_id,
            )
            matched_iocs = corr_ctx.matched_iocs
            attack_techniques = corr_ctx.attack_techniques
            incident = corr_ctx.incident
            is_duplicate = corr_ctx.is_duplicate_alert
        else:
            triggered_names = [d.detector_name for d in detections if d.detected]
            attack_techniques = AttackRegistry.get_techniques_for_detectors(triggered_names)

        # 8. Execute or simulate defensive response
        decision: ResponseDecision | None = None
        ban: BanRecord | None = None
        if self.response_engine:
            decision, ban = self.response_engine.process(profile)
            # Check for ban expiration maintenance
            self.response_engine.ban_manager.check_expirations()

        # 9. Persist updated profile & score history
        if self.storage:
            self.storage.save_threat_actor(profile)
            self.storage.save_score_history(
                source_ip=profile.source_ip,
                score=profile.threat_score,
                severity=profile.severity,
                factors=profile.factors,
                timestamp=event.timestamp,
            )
        self._actor_cache[event.source_ip] = profile

        # 10. Check alert conditions (respecting alert deduplication)
        is_alert = (
            (profile.threat_score >= self.alert_min_score
             or any(det.detected for det in detections)
             or len(matched_iocs) > 0
             or (decision is not None and decision.action in {ResponseAction.TEMPORARY_ISOLATION, ResponseAction.PERMANENT_BAN}))
            and not is_duplicate
        )
        alert_msg = None

        if is_alert:
            alert_msg = format_explainable_alert(
                event=event,
                profile=profile,
                detections=detections,
                decision=decision,
                ban=ban,
                matched_iocs=matched_iocs,
                attack_techniques=attack_techniques,
                incident=incident,
            )
            if self.on_alert:
                self.on_alert(event, profile, detections, decision)

        return PipelineResult(
            raw_line=raw_line,
            event=event,
            detections=detections,
            profile=profile,
            decision=decision,
            ban=ban,
            matched_iocs=matched_iocs,
            attack_techniques=attack_techniques,
            incident=incident,
            is_alert=is_alert,
            alert_message=alert_msg,
        )

    def process(self, lines: Iterable[str]) -> Iterator[PipelineResult]:
        """Process an iterable stream of log lines, yielding PipelineResults."""
        for line in lines:
            yield self.process_line(line)
