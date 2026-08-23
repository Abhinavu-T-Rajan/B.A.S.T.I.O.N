from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from typing import Any

from bastion.attack.models import AttackTechnique
from bastion.attack.registry import AttackRegistry
from bastion.core.contracts.collector import EventNormalizer
from bastion.core.contracts.storage import StorageProvider
from bastion.core.models.telemetry import RawTelemetry
from bastion.correlation.engine import CorrelationEngine
from bastion.detection.base import DetectionResult
from bastion.detection.engine import DetectionEngine
from bastion.incidents.manager import IncidentManager
from bastion.incidents.models import Incident
from bastion.infrastructure.telemetry.adapters.composite import CompositeEventNormalizer
from bastion.intelligence.manager import IOCManager
from bastion.intelligence.models import IOCRecord
from bastion.models.actors import Severity, ThreatActorProfile
from bastion.models.events import SecurityEvent
from bastion.response.engine import ResponseEngine
from bastion.response.models import BanRecord, ResponseAction, ResponseDecision, ResponseMode
from bastion.risk.scorer import RiskEngine


@dataclass(frozen=True, slots=True)
class PipelineResult:
    """Result of processing a single raw telemetry item through the full security pipeline."""

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

    box_width = max(len(l) for l in lines) + 4
    border = "═" * box_width
    inner = "\n".join(f"║  {l:<{box_width - 6}}  ║" for l in lines)

    return f"╔{border}╗\n{inner}\n╚{border}╝"


class SentinelPipeline:
    """Core security processing pipeline orchestrating Normalization, Detection, Risk, Correlation, Response, and Storage."""

    def __init__(
        self,
        *,
        normalizer: EventNormalizer | None = None,
        parser: Any = None,
        engine: DetectionEngine | None = None,
        risk_engine: RiskEngine | None = None,
        response_engine: ResponseEngine | None = None,
        storage: StorageProvider | None = None,
        ioc_manager: IOCManager | None = None,
        incident_manager: IncidentManager | None = None,
        correlation_engine: CorrelationEngine | None = None,
        on_event: Any = None,
        on_alert: Any = None,
        alert_min_score: int = 70,
    ) -> None:
        self.normalizer = normalizer or CompositeEventNormalizer()
        self.parser = parser
        self.engine = engine or DetectionEngine()
        self.risk_engine = risk_engine or RiskEngine()
        self.response_engine = response_engine
        self.storage = storage
        self.correlation_engine = correlation_engine
        self.on_event = on_event
        self.on_alert = on_alert
        self.alert_min_score = alert_min_score

        self._attack_registry = AttackRegistry.load_default()
        self._ioc_manager: IOCManager | None = (
            ioc_manager or (IOCManager(storage=self.storage) if self.storage else None)
        )
        self._incident_manager: IncidentManager | None = (
            incident_manager or (IncidentManager(storage=self.storage) if self.storage else None)
        )

    def process_raw(self, telemetry: RawTelemetry) -> PipelineResult:
        """Process a RawTelemetry record through the complete defense pipeline."""
        if self.parser is not None and hasattr(self.parser, "parse"):
            event = self.parser.parse(telemetry.raw_message)
        else:
            event = self.normalizer.normalize(telemetry)

        if event is None:
            return PipelineResult(
                raw_line=telemetry.raw_message,
                event=None,
            )

        if self.on_event:
            try:
                self.on_event(event)
            except Exception:
                pass

        # 1. Persist raw security event
        if self.storage:
            self.storage.save_event(event)

        # 2. Match against IOCs
        matched_iocs: list[IOCRecord] = []
        if self._ioc_manager:
            matched_iocs = self._ioc_manager.match_event(event)

        # 3. Evaluate Behavioral Detectors
        all_results = self.engine.evaluate(event)
        triggered_detections = [res for res in all_results if res.detected]

        # 4. Map to MITRE ATT&CK techniques
        attack_techniques: list[AttackTechnique] = []
        for det in triggered_detections:
            tech = self._attack_registry.get_technique_for_detector(det.detector_name)
            if tech and tech not in attack_techniques:
                attack_techniques.append(tech)

        # 5. Fetch existing profile & calculate risk
        existing_profile: ThreatActorProfile | None = None
        if self.storage:
            existing_profile = self.storage.get_threat_actor(event.source_ip)

        profile = self.risk_engine.evaluate(
            event=event,
            existing_profile=existing_profile,
            detections=triggered_detections,
            matched_iocs=matched_iocs,
        )

        # 6. Evaluate Defense Response Policy
        decision: ResponseDecision | None = None
        ban_record: BanRecord | None = None

        if self.response_engine:
            decision, ban_record = self.response_engine.process(profile)

        # 7. Persist updated ThreatActorProfile
        if self.storage:
            self.storage.upsert_threat_actor(profile)

        # 8. Threat Correlation & Incident Clustering
        incident: Incident | None = None
        if self.correlation_engine:
            if hasattr(self.correlation_engine, "correlate"):
                corr_ctx = self.correlation_engine.correlate(
                    event=event,
                    detections=triggered_detections,
                    actor=profile,
                )
                incident = corr_ctx.incident
                if corr_ctx.attack_techniques:
                    attack_techniques = corr_ctx.attack_techniques
                if corr_ctx.matched_iocs:
                    matched_iocs = corr_ctx.matched_iocs

        # 9. Format Alert
        is_alert = (
            profile.threat_score >= self.alert_min_score
            or len(triggered_detections) > 0
            or len(matched_iocs) > 0
            or (decision and decision.action in {ResponseAction.TEMPORARY_ISOLATION, ResponseAction.PERMANENT_BAN})
        )

        if is_alert and self.on_alert:
            try:
                self.on_alert(event, profile, triggered_detections, decision)
            except Exception:
                pass

        alert_msg: str | None = None
        if is_alert:
            alert_msg = format_explainable_alert(
                event=event,
                profile=profile,
                detections=triggered_detections,
                decision=decision,
                ban=ban_record,
                matched_iocs=matched_iocs,
                attack_techniques=attack_techniques,
                incident=incident,
            )

        return PipelineResult(
            raw_line=telemetry.raw_message,
            event=event,
            detections=triggered_detections,
            profile=profile,
            decision=decision,
            ban=ban_record,
            matched_iocs=matched_iocs,
            attack_techniques=attack_techniques,
            incident=incident,
            is_alert=is_alert,
            alert_message=alert_msg,
        )

    def process_line(self, raw_line: str) -> PipelineResult:
        """Process a single string line (backward compatibility)."""
        telemetry = RawTelemetry(raw_message=raw_line, source="string_input")
        return self.process_raw(telemetry)

    def process(self, stream: Iterable[RawTelemetry | str]) -> Iterator[PipelineResult]:
        """Stream processing generator."""
        for item in stream:
            if isinstance(item, RawTelemetry):
                yield self.process_raw(item)
            else:
                yield self.process_line(str(item))
