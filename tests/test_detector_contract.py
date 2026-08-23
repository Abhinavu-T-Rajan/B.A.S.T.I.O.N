from __future__ import annotations

from datetime import datetime, timezone

from bastion.core.contracts.detector import Detector
from bastion.detection.base import DetectionResult
from bastion.detection.engine import DetectionEngine
from bastion.models.events import EventType, SecurityEvent, ServiceType


class CustomMockDetector(Detector):
    """Example custom pluggable behavioral detector."""

    def __init__(self, target_user: str = "special_target") -> None:
        super().__init__(
            name="custom_mock_detector",
            description="Detects access attempts targeting a high-value honeypot user",
            enabled=True,
        )
        self.target_user = target_user
        self.seen_count = 0

    def evaluate(self, event: SecurityEvent) -> DetectionResult | None:
        if not self.enabled:
            return None

        if event.username == self.target_user:
            self.seen_count += 1
            return DetectionResult(
                detected=True,
                source_ip=event.source_ip,
                event_count=self.seen_count,
                threshold=1,
                window_seconds=60,
                reason=f"Targeted high-value honeypot account '{self.target_user}'",
                detector_name=self.name,
            )

        return DetectionResult(
            detected=False,
            source_ip=event.source_ip,
            event_count=self.seen_count,
            threshold=1,
            window_seconds=60,
            detector_name=self.name,
        )

    def reset(self) -> None:
        self.seen_count = 0


def test_detector_contract_and_engine_registration() -> None:
    """Test registering arbitrary Detector providers in DetectionEngine without modifying engine code."""
    engine = DetectionEngine()
    custom_det = CustomMockDetector(target_user="honeypot_admin")
    engine.register(custom_det)

    now = datetime.now(timezone.utc)

    # 1. Normal event should not trigger custom detector
    ev1 = SecurityEvent(
        timestamp=now,
        source_ip="198.51.100.10",
        service=ServiceType.SSH,
        event_type=EventType.AUTH_FAILURE,
        username="standard_user",
    )
    triggered = engine.get_triggered(ev1)
    assert not any(t.detector_name == "custom_mock_detector" for t in triggered)

    # 2. Honeypot event triggers custom detector
    ev2 = SecurityEvent(
        timestamp=now,
        source_ip="198.51.100.10",
        service=ServiceType.SSH,
        event_type=EventType.AUTH_FAILURE,
        username="honeypot_admin",
    )
    triggered2 = engine.get_triggered(ev2)
    assert any(t.detector_name == "custom_mock_detector" and t.detected for t in triggered2)

    # 3. Disable detector toggle
    custom_det.enabled = False
    triggered3 = engine.get_triggered(ev2)
    assert not any(t.detector_name == "custom_mock_detector" for t in triggered3)

    # 4. Reset detector state
    custom_det.enabled = True
    custom_det.reset()
    assert custom_det.seen_count == 0
