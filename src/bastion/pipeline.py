from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass

from bastion.collector.ssh import SSHLogParser
from bastion.detection.brute_force import BruteForceDetector, DetectionResult
from bastion.models.events import SecurityEvent


@dataclass(frozen=True, slots=True)
class PipelineResult:
    """Result of processing a single raw telemetry line through the pipeline."""

    raw_line: str
    event: SecurityEvent | None
    detection: DetectionResult | None


class SentinelPipeline:
    """Real-time event processing pipeline connecting collectors, parsers, and detectors."""

    def __init__(
        self,
        *,
        parser: SSHLogParser | None = None,
        detector: BruteForceDetector | None = None,
        on_event: Callable[[SecurityEvent], None] | None = None,
        on_alert: Callable[[SecurityEvent, DetectionResult], None] | None = None,
    ) -> None:
        self.parser = parser or SSHLogParser()
        self.detector = detector or BruteForceDetector()
        self.on_event = on_event
        self.on_alert = on_alert

    def process_line(self, raw_line: str) -> PipelineResult:
        """Process a single raw log entry through the parsing and detection pipeline."""
        event = self.parser.parse(raw_line)
        detection: DetectionResult | None = None

        if event is not None:
            if self.on_event:
                self.on_event(event)

            detection = self.detector.evaluate(event)

            if detection.detected and self.on_alert:
                self.on_alert(event, detection)

        return PipelineResult(
            raw_line=raw_line,
            event=event,
            detection=detection,
        )

    def process(self, lines: Iterable[str]) -> Iterator[PipelineResult]:
        """Process an iterable stream of log lines, yielding PipelineResults."""
        for line in lines:
            yield self.process_line(line)
