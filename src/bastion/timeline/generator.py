from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, List, Optional

from bastion.timeline.models import TimelineEntry, TimelineEntryType

if TYPE_CHECKING:
    from bastion.storage.sqlite import SQLiteStorage


class TimelineGenerator:
    """Reconstructs unified chronological investigation timelines from persisted evidence."""

    def __init__(self, storage: SQLiteStorage) -> None:
        self.storage = storage

    def generate(
        self,
        source_ip: str | None = None,
        incident_id: str | None = None,
        limit: int = 100,
    ) -> List[TimelineEntry]:
        """Generate investigation timeline for an IP or incident."""
        if incident_id:
            return self.generate_for_incident(incident_id, limit=limit)
        if source_ip:
            return self.generate_for_ip(source_ip, limit=limit)
        return []

    def generate_for_ip(self, source_ip: str, limit: int = 100) -> List[TimelineEntry]:
        """Build chronological investigation timeline for a specific IP address."""
        entries: List[TimelineEntry] = []

        # 1. Fetch raw events
        events = self.storage.get_events(source_ip=source_ip, limit=limit)
        for ev in events:
            user_str = f" user={ev.username}" if ev.username else ""
            summary = f"[{ev.service.value.upper()}] {ev.event_type.value.upper()}{user_str}"
            entries.append(
                TimelineEntry(
                    timestamp=ev.timestamp,
                    entry_type=TimelineEntryType.EVENT,
                    source=source_ip,
                    summary=summary,
                    details={"service": ev.service.value, "event_type": ev.event_type.value, "metadata": ev.metadata},
                    actor_id=f"actor-{source_ip}",
                )
            )

        # 2. Fetch detections
        detections = self.storage.get_detections_for_ip(source_ip, limit=limit)
        for det in detections:
            ts_str = det["timestamp"]
            ts = datetime.fromisoformat(ts_str) if isinstance(ts_str, str) else ts_str
            summary = f"Detector '{det['detector_name']}' triggered: {det.get('reason', '')}"
            entries.append(
                TimelineEntry(
                    timestamp=ts,
                    entry_type=TimelineEntryType.DETECTION,
                    source=source_ip,
                    summary=summary,
                    details=det,
                    actor_id=f"actor-{source_ip}",
                )
            )

        # 3. Fetch score history
        scores = self.storage.get_score_history(source_ip, limit=limit)
        for sc in scores:
            ts_str = sc["timestamp"]
            ts = datetime.fromisoformat(ts_str) if isinstance(ts_str, str) else ts_str
            summary = f"Threat score updated to {sc['score']}/100 ({sc['severity']})"
            entries.append(
                TimelineEntry(
                    timestamp=ts,
                    entry_type=TimelineEntryType.RISK_CHANGE,
                    source=source_ip,
                    summary=summary,
                    details=sc,
                    actor_id=f"actor-{source_ip}",
                )
            )

        # 4. Fetch bans
        ban = self.storage.get_ban_by_ip(source_ip)
        if ban:
            created_ts = ban.created_at
            summary = f"Host isolation ban ({ban.action.value.upper()}) status={ban.status.value}: {ban.reason}"
            entries.append(
                TimelineEntry(
                    timestamp=created_ts,
                    entry_type=TimelineEntryType.RESPONSE_ACTION,
                    source=source_ip,
                    summary=summary,
                    details=ban.to_dict(),
                    actor_id=f"actor-{source_ip}",
                )
            )

        # 5. Fetch response audits
        audits = self.storage.get_response_audits_for_target(source_ip, limit=limit)
        for aud in audits:
            ts_str = aud["timestamp"]
            ts = datetime.fromisoformat(ts_str) if isinstance(ts_str, str) else ts_str
            mode_str = "[DRY-RUN] " if aud.get("dry_run") else ""
            summary = f"{mode_str}Action '{aud['action']}' executed by {aud['executed_by']} (success={aud['success']})"
            entries.append(
                TimelineEntry(
                    timestamp=ts,
                    entry_type=TimelineEntryType.RESPONSE_ACTION,
                    source=source_ip,
                    summary=summary,
                    details=aud,
                    actor_id=f"actor-{source_ip}",
                )
            )

        # Sort chronologically
        entries.sort(key=lambda e: e.timestamp)
        return entries[-limit:]

    def generate_for_incident(self, incident_id: str, limit: int = 100) -> List[TimelineEntry]:
        """Build chronological investigation timeline for a security incident."""
        incident = self.storage.get_incident(incident_id)
        if not incident:
            return []

        entries: List[TimelineEntry] = []

        # Incident creation event
        entries.append(
            TimelineEntry(
                timestamp=incident.created_at,
                entry_type=TimelineEntryType.INCIDENT_UPDATE,
                source=incident_id,
                summary=f"Incident '{incident.title}' opened with severity {incident.severity.value} (Score: {incident.risk_score})",
                details=incident.to_dict(),
                incident_id=incident_id,
            )
        )

        # Aggregate timelines for all related actors
        for actor_id in incident.related_actors:
            ip = actor_id.replace("actor-", "")
            actor_entries = self.generate_for_ip(ip, limit=limit)
            for ae in actor_entries:
                ae.incident_id = incident_id
                entries.append(ae)

        # Sort and deduplicate
        entries.sort(key=lambda e: e.timestamp)
        return entries[-limit:]
