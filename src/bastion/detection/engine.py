from __future__ import annotations

from collections.abc import Sequence

from bastion.core.contracts.detector import Detector
from bastion.detection.brute_force import BruteForceDetector, DetectionResult
from bastion.detection.burst import BurstDetector
from bastion.detection.enumeration import UsernameEnumerationDetector
from bastion.detection.password_spray import PasswordSprayDetector
from bastion.models.events import SecurityEvent


class DetectionEngine:
    """Pluggable coordinator managing behavioral threat detection providers."""

    def __init__(
        self,
        *,
        detectors: Sequence[Detector] | None = None,
        brute_force: BruteForceDetector | None = None,
        password_spray: PasswordSprayDetector | None = None,
        enumeration: UsernameEnumerationDetector | None = None,
        burst: BurstDetector | None = None,
    ) -> None:
        self.brute_force = brute_force or BruteForceDetector()
        self.password_spray = password_spray or PasswordSprayDetector()
        self.enumeration = enumeration or UsernameEnumerationDetector()
        self.burst = burst or BurstDetector()

        if detectors is not None:
            self._detectors: list[Detector] = list(detectors)
        else:
            self._detectors = [
                self.brute_force,
                self.password_spray,
                self.enumeration,
                self.burst,
            ]

    @property
    def detectors(self) -> Sequence[Detector]:
        """Return registered detector providers."""
        return list(self._detectors)

    def register(self, detector: Detector) -> None:
        """Register a new behavioral detector provider."""
        self._detectors.append(detector)

    def evaluate(self, event: SecurityEvent) -> list[DetectionResult]:
        """Run all registered behavioral detectors against the event and return all results."""
        results: list[DetectionResult] = []
        for detector in self._detectors:
            if detector.enabled:
                res = detector.evaluate(event)
                if res is not None:
                    results.append(res)
        return results

    def get_triggered(self, event: SecurityEvent) -> list[DetectionResult]:
        """Run all detectors and return only those that triggered a detection."""
        return [res for res in self.evaluate(event) if res.detected]

    def reset_all(self) -> None:
        """Reset state across all registered detectors."""
        for detector in self._detectors:
            detector.reset()
