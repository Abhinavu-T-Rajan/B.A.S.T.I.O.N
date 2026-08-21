from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Sequence

from bastion.detection.brute_force import DetectionResult
from bastion.models.actors import (
    ActorState,
    RecommendedAction,
    ScoreFactor,
    Severity,
    ThreatActorProfile,
)
from bastion.models.events import EventType, SecurityEvent


@dataclass(slots=True)
class RiskScoringConfig:
    """Configurable scoring weights, thresholds, and allowlist rules."""

    failed_auth_weight: int = 5
    invalid_user_weight: int = 10
    burst_velocity_weight: int = 25
    brute_force_weight: int = 20
    password_spray_weight: int = 20
    enumeration_weight: int = 20
    max_attempts_weight: int = 20
    repeat_offender_weight: int = 15
    success_auth_weight: int = -10
    trusted_ip_discount: int = -100
    low_threshold: int = 0
    medium_threshold: int = 40
    high_threshold: int = 70
    critical_threshold: int = 85
    trusted_ips: set[str] = field(
        default_factory=lambda: {"127.0.0.1", "::1", "localhost"}
    )


class RiskEngine:
    """Calculates multi-signal explainable threat scores and maintains actor profiles."""

    def __init__(self, config: RiskScoringConfig | None = None) -> None:
        self.config = config or RiskScoringConfig()

    def evaluate(
        self,
        event: SecurityEvent,
        detections: Sequence[DetectionResult] = (),
        existing_profile: ThreatActorProfile | None = None,
        matched_iocs: Sequence[Any] = (),
    ) -> ThreatActorProfile:
        """Evaluate a security event and detector signals to produce an updated ThreatActorProfile."""
        source_ip = event.source_ip
        first_seen = existing_profile.first_seen if existing_profile else event.timestamp
        last_seen = event.timestamp

        # Check for trusted / allowlisted source
        if source_ip in self.config.trusted_ips:
            return ThreatActorProfile(
                source_ip=source_ip,
                first_seen=first_seen,
                last_seen=last_seen,
                total_events=(existing_profile.total_events + 1) if existing_profile else 1,
                auth_failures=existing_profile.auth_failures if existing_profile else 0,
                auth_successes=(existing_profile.auth_successes + 1) if (existing_profile and event.event_type == EventType.AUTH_SUCCESS) else 1,
                usernames_targeted=(existing_profile.usernames_targeted.copy() if existing_profile else set()),
                services_targeted=(existing_profile.services_targeted.copy() if existing_profile else {event.service.value}),
                threat_score=0,
                severity=Severity.LOW,
                state=ActorState.TRUSTED,
                factors=[
                    ScoreFactor(
                        name="trusted_source",
                        score_delta=self.config.trusted_ip_discount,
                        description="Trusted/allowlisted source IP",
                    )
                ],
                recommended_action=RecommendedAction.NONE,
            )

        # Initialize or update cumulative counters
        total_events = (existing_profile.total_events + 1) if existing_profile else 1
        auth_failures = existing_profile.auth_failures if existing_profile else 0
        auth_successes = existing_profile.auth_successes if existing_profile else 0
        usernames_targeted = (
            existing_profile.usernames_targeted.copy()
            if existing_profile
            else set()
        )
        services_targeted = (
            existing_profile.services_targeted.copy()
            if existing_profile
            else set()
        )

        services_targeted.add(event.service.value)
        if event.username:
            usernames_targeted.add(event.username)

        is_failure = event.event_type in {
            EventType.AUTH_FAILURE,
            EventType.INVALID_USER,
        }
        if is_failure:
            auth_failures += 1
        elif event.event_type == EventType.AUTH_SUCCESS:
            auth_successes += 1

        # Calculate contributing factors
        factors: list[ScoreFactor] = []
        raw_score = 0

        # 1. Base failure accumulation (capped at 30 points to avoid unbounded runaway without behavioral signals)
        if auth_failures > 0:
            failure_points = min(30, auth_failures * self.config.failed_auth_weight)
            factors.append(
                ScoreFactor(
                    name="auth_failures",
                    score_delta=failure_points,
                    description=f"+{failure_points} authentication failures ({auth_failures} total)",
                )
            )
            raw_score += failure_points

        # 2. Invalid username activity
        if (
            event.event_type == EventType.INVALID_USER
            or event.metadata.get("invalid_user") is True
        ):
            factors.append(
                ScoreFactor(
                    name="invalid_user",
                    score_delta=self.config.invalid_user_weight,
                    description=f"+{self.config.invalid_user_weight} invalid-user targeting",
                )
            )
            raw_score += self.config.invalid_user_weight

        # 3. Maximum attempts exceeded
        if event.metadata.get("reason") == "max_auth_attempts_exceeded":
            factors.append(
                ScoreFactor(
                    name="max_attempts_exceeded",
                    score_delta=self.config.max_attempts_weight,
                    description=f"+{self.config.max_attempts_weight} max authentication attempts exceeded",
                )
            )
            raw_score += self.config.max_attempts_weight

        # 4. Behavioral detector signals
        for det in detections:
            if not det.detected:
                continue

            if det.detector_name == "brute_force":
                delta = self.config.brute_force_weight
                factors.append(
                    ScoreFactor(
                        name="brute_force_detected",
                        score_delta=delta,
                        description=f"+{delta} brute-force threshold crossed ({det.event_count}/{det.threshold})",
                    )
                )
                raw_score += delta

            elif det.detector_name == "password_spray":
                delta = self.config.password_spray_weight
                user_cnt = len(usernames_targeted)
                factors.append(
                    ScoreFactor(
                        name="password_spray_detected",
                        score_delta=delta,
                        description=f"+{delta} password spraying across {user_cnt} accounts",
                    )
                )
                raw_score += delta

            elif det.detector_name == "username_enumeration":
                delta = self.config.enumeration_weight
                factors.append(
                    ScoreFactor(
                        name="username_enumeration_detected",
                        score_delta=delta,
                        description=f"+{delta} invalid username enumeration pattern",
                    )
                )
                raw_score += delta

            elif det.detector_name == "burst_velocity":
                delta = self.config.burst_velocity_weight
                factors.append(
                    ScoreFactor(
                        name="burst_velocity_detected",
                        score_delta=delta,
                        description=f"+{delta} high-frequency burst velocity detected",
                    )
                )
                raw_score += delta

        # 5. Repeat offender / Historical activity penalty
        if existing_profile and existing_profile.auth_failures >= 15:
            delta = self.config.repeat_offender_weight
            factors.append(
                ScoreFactor(
                    name="repeat_offender",
                    score_delta=delta,
                    description=f"+{delta} repeat offender historical activity",
                )
            )
            raw_score += delta

        # 6. Matched Threat Intelligence IOCs
        for ioc in matched_iocs:
            ioc_delta = max(15, min(30, int((ioc.confidence / 100.0) * 30)))
            factors.append(
                ScoreFactor(
                    name="ioc_match",
                    score_delta=ioc_delta,
                    description=f"+{ioc_delta} matched active IOC ({ioc.ioc_type.value}:{ioc.value}) [Confidence: {ioc.confidence}%]",
                )
            )
            raw_score += ioc_delta

        # 7. Successful authentication deduction
        if event.event_type == EventType.AUTH_SUCCESS:
            delta = self.config.success_auth_weight
            factors.append(
                ScoreFactor(
                    name="auth_success",
                    score_delta=delta,
                    description=f"{delta} legitimate authentication success",
                )
            )
            raw_score += delta

        # Normalize score between 0 and 100
        threat_score = max(0, min(100, raw_score))

        # Determine Severity
        severity = Severity.from_score(threat_score)

        # Determine Actor State
        if severity == Severity.CRITICAL or severity == Severity.HIGH:
            state = ActorState.ACTIVE_THREAT
        elif severity == Severity.MEDIUM:
            state = ActorState.PROBING if len(usernames_targeted) > 1 else ActorState.SUSPICIOUS
        elif auth_failures > 0:
            state = ActorState.PROBING
        else:
            state = ActorState.NEUTRAL

        # Determine Recommended Advisory Action
        if threat_score >= self.config.critical_threshold:
            recommended_action = (
                RecommendedAction.PERMANENT_BAN
                if (existing_profile and existing_profile.auth_failures >= 30)
                else RecommendedAction.TEMPORARY_ISOLATION
            )
        elif threat_score >= self.config.high_threshold:
            recommended_action = RecommendedAction.TEMPORARY_ISOLATION
        elif threat_score >= self.config.medium_threshold:
            recommended_action = RecommendedAction.RATE_LIMIT
        elif auth_failures > 0:
            recommended_action = RecommendedAction.MONITOR
        else:
            recommended_action = RecommendedAction.NONE

        return ThreatActorProfile(
            source_ip=source_ip,
            first_seen=first_seen,
            last_seen=last_seen,
            total_events=total_events,
            auth_failures=auth_failures,
            auth_successes=auth_successes,
            usernames_targeted=usernames_targeted,
            services_targeted=services_targeted,
            threat_score=threat_score,
            severity=severity,
            state=state,
            factors=factors,
            recommended_action=recommended_action,
        )
