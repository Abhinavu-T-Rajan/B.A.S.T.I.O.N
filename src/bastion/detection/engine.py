from __future__ import annotations

from collections.abc import Sequence

from bastion.detection.brute_force import BruteForceDetector, DetectionResult
from bastion.detection.burst import BurstDetector
from bastion.detection.enumeration import UsernameEnumerationDetector
from bastion.detection.password_spray import PasswordSprayDetector
from bastion.models.events import SecurityEvent


class DetectionEngine:
    """Unified coordinator managing multiple behavioral detectors."""

    def __init__(
        self,
        *,
        brute_force: BruteForceDetector | None = None,
        password_spray: PasswordSprayDetector | None = None,
        enumeration: UsernameEnumerationDetector | None = None,
        burst: BurstDetector | None = None,
    ) -> None:
        self.brute_force = brute_force or BruteForceDetector()
        self.password_spray = password_spray or PasswordSprayDetector()
        self.enumeration = enumeration or UsernameEnumerationDetector()
        self.burst = burst or BurstDetector()

    @property
    def detectors(self) -> Sequence[object]:
        return (self.brute_force, self.password_spray, self.enumeration, self.burst)

    def evaluate(self, event: SecurityEvent) -> list[DetectionResult]:
        """Run all behavioral detectors against the event and return all results."""
        results: list[DetectionResult] = [
            self.brute_force.evaluate(event),
            self.password_spray.evaluate(event),
            self.enumeration.evaluate(event),
            self.burst.evaluate(event),
        ]
        return results

    def get_triggered(self, event: SecurityEvent) -> list[DetectionResult]:
        """Run all detectors and return only those that triggered a detection."""
        return [res for res in self.evaluate(event) if res.detected]
