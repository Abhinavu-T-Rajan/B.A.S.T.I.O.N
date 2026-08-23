from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Protocol, runtime_checkable

from bastion.models.actors import ThreatActorProfile
from bastion.response.models import BanRecord, ResponseDecision, ResponseMode


@runtime_checkable
class ResponseProvider(Protocol):
    """Protocol for response engine execution providers."""

    default_mode: ResponseMode

    def process(
        self,
        profile: ThreatActorProfile,
        mode_override: ResponseMode | None = None,
    ) -> tuple[ResponseDecision, BanRecord | None]:
        """Evaluate defense policy and execute or simulate response."""
        ...
