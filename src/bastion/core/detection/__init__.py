"""Detection contracts and engines for B.A.S.T.I.O.N."""

from bastion.core.contracts.detector import Detector, DetectorProvider
from bastion.detection.base import DetectionResult
from bastion.detection.brute_force import BruteForceDetector
from bastion.detection.burst import BurstDetector
from bastion.detection.engine import DetectionEngine
from bastion.detection.enumeration import UsernameEnumerationDetector
from bastion.detection.password_spray import PasswordSprayDetector

__all__ = [
    "Detector",
    "DetectorProvider",
    "DetectionResult",
    "DetectionEngine",
    "BruteForceDetector",
    "PasswordSprayDetector",
    "UsernameEnumerationDetector",
    "BurstDetector",
]
