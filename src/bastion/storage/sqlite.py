from __future__ import annotations

import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, List, Optional

from bastion.incidents.models import Incident, IncidentStatus
from bastion.intelligence.models import IOCRecord, IOCStatus, IOCType, Provenance
from bastion.models.actors import (
    ActorState,
    RecommendedAction,
    ScoreFactor,
    Severity,
    ThreatActorProfile,
)
from bastion.models.events import EventType, SecurityEvent, ServiceType
from bastion.response.audit import ResponseAuditRecord
from bastion.response.models import BanRecord, BanStatus, ResponseAction
from bastion.storage.migrations import MigrationRunner
from bastion.timeline.models import TimelineEntry, TimelineEntryType


class SQLiteStorage:
    """Persistent SQLite storage engine for events, detections, threat profiles, bans, IOCs, and incidents."""

    def __init__(self, db_path: str = ":memory:") -> None:
        self.db_path = db_path
        self._lock = threading.RLock()

        if self.db_path != ":memory:":
            expanded_path = Path(os.path.expanduser(self.db_path)).resolve()
            expanded_path.parent.mkdir(parents=True, exist_ok=True)
            self._connection = sqlite3.connect(
                str(expanded_path), check_same_thread=False
            )
        else:
            self._connection = sqlite3.connect(
                ":memory:", check_same_thread=False
            )

        self._connection.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        """Create database tables and run migrations."""
        with self._lock:
            if self.db_path != ":memory:":
                cur = self._connection.cursor()
                cur.execute("PRAGMA journal_mode=WAL;")
                self._connection.commit()
            MigrationRunner.apply_migrations(self._connection)

    # ---------------------------------------------------------
    # Events & Detections
    # ---------------------------------------------------------

    def save_event(self, event: SecurityEvent) -> int:
        """Persist a single security event."""
        with self._lock, self._connection:
            cur = self._connection.cursor()
            cur.execute(
                """
                INSERT INTO events (timestamp, source_ip, service, event_type, username, metadata)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    event.timestamp.isoformat(),
                    event.source_ip,
                    event.service.value,
                    event.event_type.value,
                    event.username,
                    json.dumps(event.metadata) if event.metadata else None,
                ),
            )
            return cur.lastrowid or 0

    def get_events(
        self,
        source_ip: str | None = None,
        event_type: EventType | None = None,
        limit: int = 100,
    ) -> list[SecurityEvent]:
        """Query security events with optional filtering."""
        with self._lock:
            cur = self._connection.cursor()
            query = "SELECT timestamp, source_ip, service, event_type, username, metadata FROM events"
            params: list[Any] = []
            clauses: list[str] = []

            if source_ip:
                clauses.append("source_ip = ?")
                params.append(source_ip)
            if event_type:
                clauses.append("event_type = ?")
                params.append(event_type.value)

            if clauses:
                query += " WHERE " + " AND ".join(clauses)

            query += " ORDER BY id DESC LIMIT ?"
            params.append(limit)

            cur.execute(query, params)
            rows = cur.fetchall()

            events: list[SecurityEvent] = []
            for row in rows:
                meta = json.loads(row["metadata"]) if row["metadata"] else {}
                ts = datetime.fromisoformat(row["timestamp"])
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)

                events.append(
                    SecurityEvent(
                        timestamp=ts,
                        source_ip=row["source_ip"],
                        service=ServiceType(row["service"]),
                        event_type=EventType(row["event_type"]),
                        username=row["username"],
                        metadata=meta,
                    )
                )
            return events

    def save_detection(
        self,
        source_ip: str,
        detector_name: str,
        reason: str,
        event_count: int,
        threshold: int,
        details: dict[str, Any] | None = None,
        timestamp: datetime | None = None,
    ) -> int:
        """Persist a behavioral detection record."""
        ts = timestamp or datetime.now(timezone.utc)
        with self._lock, self._connection:
            cur = self._connection.cursor()
            cur.execute(
                """
                INSERT INTO detections (timestamp, source_ip, detector_name, reason, event_count, threshold, details)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ts.isoformat(),
                    source_ip,
                    detector_name,
                    reason,
                    event_count,
                    threshold,
                    json.dumps(details) if details else None,
                ),
            )
            return cur.lastrowid or 0

    def get_detections_for_ip(self, source_ip: str, limit: int = 50) -> list[dict[str, Any]]:
        """Retrieve recent detection records for a specific IP."""
        with self._lock:
            cur = self._connection.cursor()
            cur.execute(
                """
                SELECT id, timestamp, source_ip, detector_name, reason, event_count, threshold, details
                FROM detections
                WHERE source_ip = ?
                ORDER BY id DESC LIMIT ?
                """,
                (source_ip, limit),
            )
            rows = cur.fetchall()
            results = []
            for r in rows:
                det = dict(r)
                if det.get("details"):
                    try:
                        det["details"] = json.loads(det["details"])
                    except Exception:
                        pass
                results.append(det)
            return results

    # ---------------------------------------------------------
    # Threat Actors & Scores
    # ---------------------------------------------------------

    def save_threat_actor(self, profile: ThreatActorProfile) -> None:
        """Upsert a ThreatActorProfile record."""
        with self._lock, self._connection:
            cur = self._connection.cursor()
            factors_json = json.dumps([f.to_dict() for f in profile.factors])
            usernames_json = json.dumps(sorted(profile.usernames_targeted))
            services_json = json.dumps(sorted(profile.services_targeted))

            cur.execute(
                """
                INSERT INTO threat_actors (
                    source_ip, first_seen, last_seen, total_events, auth_failures,
                    auth_successes, usernames, services, threat_score, severity,
                    state, factors, recommended_action
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(source_ip) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    total_events = excluded.total_events,
                    auth_failures = excluded.auth_failures,
                    auth_successes = excluded.auth_successes,
                    usernames = excluded.usernames,
                    services = excluded.services,
                    threat_score = excluded.threat_score,
                    severity = excluded.severity,
                    state = excluded.state,
                    factors = excluded.factors,
                    recommended_action = excluded.recommended_action
                """,
                (
                    profile.source_ip,
                    profile.first_seen.isoformat(),
                    profile.last_seen.isoformat(),
                    profile.total_events,
                    profile.auth_failures,
                    profile.auth_successes,
                    usernames_json,
                    services_json,
                    profile.threat_score,
                    profile.severity.value,
                    profile.state.value,
                    factors_json,
                    profile.recommended_action.value,
                ),
            )

    def upsert_threat_actor(self, profile: ThreatActorProfile) -> None:
        """Alias for save_threat_actor for backward compatibility."""
        self.save_threat_actor(profile)

    def get_threat_actor(self, source_ip: str) -> ThreatActorProfile | None:
        """Retrieve a threat actor profile by IP."""
        with self._lock:
            cur = self._connection.cursor()
            cur.execute(
                """
                SELECT source_ip, first_seen, last_seen, total_events, auth_failures,
                       auth_successes, usernames, services, threat_score, severity,
                       state, factors, recommended_action
                FROM threat_actors
                WHERE source_ip = ?
                """,
                (source_ip,),
            )
            row = cur.fetchone()
            if not row:
                return None
            return self._row_to_threat_actor(row)

    def list_threat_actors(
        self,
        min_score: int = 0,
        severity: Severity | None = None,
        limit: int = 50,
    ) -> list[ThreatActorProfile]:
        """List threat actor profiles ranked by score."""
        with self._lock:
            cur = self._connection.cursor()
            query = "SELECT * FROM threat_actors WHERE threat_score >= ?"
            params: list[Any] = [min_score]

            if severity:
                query += " AND severity = ?"
                params.append(severity.value)

            query += " ORDER BY threat_score DESC, auth_failures DESC LIMIT ?"
            params.append(limit)

            cur.execute(query, params)
            rows = cur.fetchall()
            return [self._row_to_threat_actor(r) for r in rows]

    def save_score_history(
        self,
        source_ip: str,
        score: int,
        severity: Severity,
        factors: list[ScoreFactor],
        timestamp: datetime | None = None,
    ) -> int:
        """Persist a score history snapshot."""
        ts = timestamp or datetime.now(timezone.utc)
        with self._lock, self._connection:
            cur = self._connection.cursor()
            cur.execute(
                """
                INSERT INTO score_history (timestamp, source_ip, score, severity, factors)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    ts.isoformat(),
                    source_ip,
                    score,
                    severity.value,
                    json.dumps([f.to_dict() for f in factors]),
                ),
            )
            return cur.lastrowid or 0

    def get_score_history(self, source_ip: str, limit: int = 20) -> list[dict[str, Any]]:
        """Retrieve recent risk score history for an IP."""
        with self._lock:
            cur = self._connection.cursor()
            cur.execute(
                """
                SELECT timestamp, source_ip, score, severity, factors
                FROM score_history
                WHERE source_ip = ?
                ORDER BY id DESC LIMIT ?
                """,
                (source_ip, limit),
            )
            rows = cur.fetchall()
            history = []
            for r in rows:
                factors = json.loads(r["factors"]) if r["factors"] else []
                history.append(
                    {
                        "timestamp": r["timestamp"],
                        "source_ip": r["source_ip"],
                        "score": r["score"],
                        "severity": r["severity"],
                        "factors": factors,
                    }
                )
            return history

    # ---------------------------------------------------------
    # Bans
    # ---------------------------------------------------------

    def save_ban(self, ban: BanRecord) -> None:
        """Upsert a BanRecord into the database."""
        with self._lock, self._connection:
            cur = self._connection.cursor()
            meta_json = json.dumps(ban.metadata) if ban.metadata else None
            expires_at_str = ban.expires_at.isoformat() if ban.expires_at else None

            cur.execute(
                """
                INSERT INTO bans (
                    ban_id, source_ip, reason, threat_score, created_at, expires_at, action, status, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ban_id) DO UPDATE SET
                    status = excluded.status,
                    expires_at = excluded.expires_at,
                    metadata = excluded.metadata
                """,
                (
                    ban.ban_id,
                    ban.source_ip,
                    ban.reason,
                    ban.threat_score,
                    ban.created_at.isoformat(),
                    expires_at_str,
                    ban.action.value,
                    ban.status.value,
                    meta_json,
                ),
            )

    def update_ban_status(self, ban_id: str, status: BanStatus) -> bool:
        """Update the lifecycle status of an existing ban."""
        with self._lock, self._connection:
            cur = self._connection.cursor()
            cur.execute(
                "UPDATE bans SET status = ? WHERE ban_id = ?",
                (status.value, ban_id),
            )
            return cur.rowcount > 0

    def get_active_bans(self) -> list[BanRecord]:
        """Retrieve all currently active bans."""
        with self._lock:
            cur = self._connection.cursor()
            cur.execute(
                "SELECT * FROM bans WHERE status = ? ORDER BY created_at DESC",
                (BanStatus.ACTIVE.value,),
            )
            rows = cur.fetchall()
            return [self._row_to_ban(r) for r in rows]

    def get_ban_by_ip(self, source_ip: str) -> BanRecord | None:
        """Retrieve the most recent active or unexpired ban record for an IP."""
        with self._lock:
            cur = self._connection.cursor()
            cur.execute(
                """
                SELECT * FROM bans
                WHERE source_ip = ? AND status = ?
                ORDER BY created_at DESC LIMIT 1
                """,
                (source_ip, BanStatus.ACTIVE.value),
            )
            row = cur.fetchone()
            if not row:
                return None
            return self._row_to_ban(row)

    def get_ban(self, ban_id: str) -> BanRecord | None:
        """Retrieve a ban record by its unique ban_id."""
        with self._lock:
            cur = self._connection.cursor()
            cur.execute("SELECT * FROM bans WHERE ban_id = ? LIMIT 1", (ban_id,))
            row = cur.fetchone()
            if not row:
                return None
            return self._row_to_ban(row)

    def list_bans(
        self,
        status: BanStatus | None = None,
        limit: int = 50,
    ) -> list[BanRecord]:
        """List bans with optional status filtering."""
        with self._lock:
            cur = self._connection.cursor()
            if status:
                cur.execute(
                    "SELECT * FROM bans WHERE status = ? ORDER BY created_at DESC LIMIT ?",
                    (status.value, limit),
                )
            else:
                cur.execute(
                    "SELECT * FROM bans ORDER BY created_at DESC LIMIT ?",
                    (limit,),
                )
            rows = cur.fetchall()
            return [self._row_to_ban(r) for r in rows]

    # ---------------------------------------------------------
    # Threat Intelligence / IOCs (Oracle v0.2.0-alpha)
    # ---------------------------------------------------------

    def save_ioc(self, ioc: IOCRecord) -> None:
        """Persist or update an Indicator of Compromise."""
        with self._lock, self._connection:
            cur = self._connection.cursor()
            tags_str = ",".join(ioc.tags) if ioc.tags else ""
            meta_json = json.dumps(ioc.metadata) if ioc.metadata else None

            cur.execute(
                """
                INSERT INTO iocs (
                    ioc_id, ioc_type, value, confidence, source, first_seen,
                    last_seen, status, provenance, tags, notes, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ioc_id) DO UPDATE SET
                    confidence = excluded.confidence,
                    last_seen = excluded.last_seen,
                    status = excluded.status,
                    tags = excluded.tags,
                    notes = excluded.notes,
                    metadata = excluded.metadata
                """,
                (
                    ioc.ioc_id,
                    ioc.ioc_type.value,
                    ioc.value,
                    ioc.confidence,
                    ioc.source,
                    ioc.first_seen.isoformat(),
                    ioc.last_seen.isoformat(),
                    ioc.status.value,
                    ioc.provenance.value,
                    tags_str,
                    ioc.notes,
                    meta_json,
                ),
            )

    def get_ioc(self, ioc_id: str) -> Optional[IOCRecord]:
        """Retrieve an IOC by its ID."""
        with self._lock:
            cur = self._connection.cursor()
            cur.execute("SELECT * FROM iocs WHERE ioc_id = ?", (ioc_id,))
            row = cur.fetchone()
            if not row:
                return None
            return self._row_to_ioc(row)

    def get_ioc_by_type_value(self, ioc_type: IOCType, value: str) -> Optional[IOCRecord]:
        """Lookup an IOC by exact type and value."""
        with self._lock:
            cur = self._connection.cursor()
            cur.execute(
                "SELECT * FROM iocs WHERE ioc_type = ? AND value = ? LIMIT 1",
                (ioc_type.value, value),
            )
            row = cur.fetchone()
            if not row:
                return None
            return self._row_to_ioc(row)

    def lookup_active_iocs(self, ioc_type: IOCType, value: str) -> list[IOCRecord]:
        """Lookup active IOCs matching a type and value."""
        with self._lock:
            cur = self._connection.cursor()
            cur.execute(
                "SELECT * FROM iocs WHERE ioc_type = ? AND value = ? AND status = ?",
                (ioc_type.value, value, IOCStatus.ACTIVE.value),
            )
            rows = cur.fetchall()
            return [self._row_to_ioc(r) for r in rows]

    def list_iocs(
        self,
        ioc_type: Optional[IOCType] = None,
        status: Optional[IOCStatus] = None,
        limit: int = 100,
    ) -> list[IOCRecord]:
        """List IOCs with optional filters."""
        with self._lock:
            cur = self._connection.cursor()
            query = "SELECT * FROM iocs"
            params: list[Any] = []
            clauses: list[str] = []

            if ioc_type:
                clauses.append("ioc_type = ?")
                params.append(ioc_type.value)
            if status:
                clauses.append("status = ?")
                params.append(status.value)

            if clauses:
                query += " WHERE " + " AND ".join(clauses)

            query += " ORDER BY last_seen DESC LIMIT ?"
            params.append(limit)

            cur.execute(query, params)
            rows = cur.fetchall()
            return [self._row_to_ioc(r) for r in rows]

    def search_iocs(self, query: str, limit: int = 50) -> list[IOCRecord]:
        """Search IOCs by value, tag, or notes matching a search term."""
        with self._lock:
            cur = self._connection.cursor()
            pattern = f"%{query}%"
            cur.execute(
                """
                SELECT * FROM iocs
                WHERE value LIKE ? OR tags LIKE ? OR notes LIKE ?
                ORDER BY last_seen DESC LIMIT ?
                """,
                (pattern, pattern, pattern, limit),
            )
            rows = cur.fetchall()
            return [self._row_to_ioc(r) for r in rows]

    def delete_ioc(self, ioc_id: str) -> bool:
        """Delete an IOC record by ID."""
        with self._lock, self._connection:
            cur = self._connection.cursor()
            cur.execute("DELETE FROM iocs WHERE ioc_id = ?", (ioc_id,))
            return cur.rowcount > 0

    # ---------------------------------------------------------
    # Incidents (Oracle v0.2.0-alpha)
    # ---------------------------------------------------------

    def save_incident(self, incident: Incident) -> None:
        """Persist or update an incident and its relations."""
        with self._lock, self._connection:
            cur = self._connection.cursor()
            attack_json = json.dumps(incident.attack_techniques)
            meta_json = json.dumps(incident.metadata) if incident.metadata else None

            cur.execute(
                """
                INSERT INTO incidents (
                    incident_id, title, status, severity, risk_score, first_seen,
                    last_seen, attack_techniques, summary, created_at, updated_at, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(incident_id) DO UPDATE SET
                    title = excluded.title,
                    status = excluded.status,
                    severity = excluded.severity,
                    risk_score = excluded.risk_score,
                    last_seen = excluded.last_seen,
                    attack_techniques = excluded.attack_techniques,
                    summary = excluded.summary,
                    updated_at = excluded.updated_at,
                    metadata = excluded.metadata
                """,
                (
                    incident.incident_id,
                    incident.title,
                    incident.status.value,
                    incident.severity.value,
                    incident.risk_score,
                    incident.first_seen.isoformat(),
                    incident.last_seen.isoformat(),
                    attack_json,
                    incident.summary,
                    incident.created_at.isoformat(),
                    incident.updated_at.isoformat(),
                    meta_json,
                ),
            )

            # Update event join table
            for eid in incident.related_events:
                cur.execute(
                    "INSERT OR IGNORE INTO incident_events (incident_id, event_id) VALUES (?, ?)",
                    (incident.incident_id, eid),
                )

            # Update actor join table
            for aid in incident.related_actors:
                cur.execute(
                    "INSERT OR IGNORE INTO incident_actors (incident_id, actor_id) VALUES (?, ?)",
                    (incident.incident_id, aid),
                )

            # Update IOC join table
            for ioc_id in incident.related_iocs:
                cur.execute(
                    "INSERT OR IGNORE INTO incident_iocs (incident_id, ioc_id) VALUES (?, ?)",
                    (incident.incident_id, ioc_id),
                )

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        """Retrieve an incident with all related IDs."""
        with self._lock:
            cur = self._connection.cursor()
            cur.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,))
            row = cur.fetchone()
            if not row:
                return None

            incident = self._row_to_incident(row)

            # Fetch related event IDs
            cur.execute("SELECT event_id FROM incident_events WHERE incident_id = ?", (incident_id,))
            incident.related_events = [r[0] for r in cur.fetchall()]

            # Fetch related actors
            cur.execute("SELECT actor_id FROM incident_actors WHERE incident_id = ?", (incident_id,))
            incident.related_actors = [r[0] for r in cur.fetchall()]

            # Fetch related IOCs
            cur.execute("SELECT ioc_id FROM incident_iocs WHERE incident_id = ?", (incident_id,))
            incident.related_iocs = [r[0] for r in cur.fetchall()]

            return incident

    def list_incidents(
        self,
        status: Optional[IncidentStatus] = None,
        limit: int = 50,
    ) -> list[Incident]:
        """List incidents ordered by last_seen desc."""
        with self._lock:
            cur = self._connection.cursor()
            if status:
                cur.execute(
                    "SELECT * FROM incidents WHERE status = ? ORDER BY last_seen DESC LIMIT ?",
                    (status.value, limit),
                )
            else:
                cur.execute(
                    "SELECT * FROM incidents ORDER BY last_seen DESC LIMIT ?",
                    (limit,),
                )
            rows = cur.fetchall()
            return [self._row_to_incident(r) for r in rows]

    def find_active_incident_for_actor(self, actor_id: str) -> Optional[Incident]:
        """Find an open or investigating incident involving an actor."""
        with self._lock:
            cur = self._connection.cursor()
            cur.execute(
                """
                SELECT i.* FROM incidents i
                JOIN incident_actors ia ON i.incident_id = ia.incident_id
                WHERE (ia.actor_id = ? OR ia.actor_id = ?)
                  AND i.status IN ('open', 'investigating')
                ORDER BY i.last_seen DESC LIMIT 1
                """,
                (actor_id, f"actor-{actor_id}"),
            )
            row = cur.fetchone()
            if not row:
                return None
            return self.get_incident(row["incident_id"])

    # ---------------------------------------------------------
    # Timeline & Audits (Oracle v0.2.0-alpha)
    # ---------------------------------------------------------

    def save_timeline_entry(self, entry: TimelineEntry) -> None:
        """Persist a timeline entry."""
        with self._lock, self._connection:
            cur = self._connection.cursor()
            details_json = json.dumps(entry.details) if entry.details else None
            cur.execute(
                """
                INSERT OR IGNORE INTO timeline_entries (
                    entry_id, timestamp, entry_type, source, summary, details, incident_id, actor_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entry.entry_id,
                    entry.timestamp.isoformat(),
                    entry.entry_type.value,
                    entry.source,
                    entry.summary,
                    details_json,
                    entry.incident_id,
                    entry.actor_id,
                ),
            )

    def save_response_audit(self, audit: ResponseAuditRecord) -> None:
        """Persist a defensive action execution audit record."""
        with self._lock, self._connection:
            cur = self._connection.cursor()
            details_json = json.dumps(audit.details) if audit.details else None
            cur.execute(
                """
                INSERT INTO response_audits (
                    audit_id, timestamp, action, target, actor_id, incident_id, executed_by, dry_run, success, details
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    audit.audit_id,
                    audit.timestamp.isoformat(),
                    audit.action,
                    audit.target,
                    audit.actor_id,
                    audit.incident_id,
                    audit.executed_by,
                    1 if audit.dry_run else 0,
                    1 if audit.success else 0,
                    details_json,
                ),
            )

    def get_response_audits_for_target(self, target: str, limit: int = 50) -> list[dict[str, Any]]:
        """Retrieve recent response audit entries for a target."""
        with self._lock:
            cur = self._connection.cursor()
            cur.execute(
                """
                SELECT * FROM response_audits
                WHERE target = ?
                ORDER BY timestamp DESC LIMIT ?
                """,
                (target, limit),
            )
            rows = cur.fetchall()
            results = []
            for r in rows:
                d = dict(r)
                if d.get("details"):
                    try:
                        d["details"] = json.loads(d["details"])
                    except Exception:
                        pass
                results.append(d)
            return results

    def list_response_audits(self, limit: int = 50) -> list[ResponseAuditRecord]:
        """List recent response action audit logs."""
        with self._lock:
            cur = self._connection.cursor()
            cur.execute(
                "SELECT * FROM response_audits ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            )
            rows = cur.fetchall()
            audits: list[ResponseAuditRecord] = []
            for r in rows:
                details = json.loads(r["details"]) if r["details"] else {}
                ts = datetime.fromisoformat(r["timestamp"])
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                audits.append(
                    ResponseAuditRecord(
                        audit_id=r["audit_id"],
                        timestamp=ts,
                        action=r["action"],
                        target=r["target"],
                        actor_id=r["actor_id"],
                        incident_id=r["incident_id"],
                        executed_by=r["executed_by"],
                        dry_run=bool(r["dry_run"]),
                        success=bool(r["success"]),
                        details=details,
                    )
                )
            return audits

    # ---------------------------------------------------------
    # Global System Stats
    # ---------------------------------------------------------

    def get_stats(self) -> dict[str, Any]:
        """Retrieve aggregated system intelligence and threat metrics."""
        with self._lock:
            cur = self._connection.cursor()

            cur.execute("SELECT COUNT(*) FROM events")
            total_events = cur.fetchone()[0]

            cur.execute("SELECT COUNT(*) FROM detections")
            total_detections = cur.fetchone()[0]

            cur.execute("SELECT COUNT(*) FROM threat_actors")
            total_actors = cur.fetchone()[0]

            cur.execute(
                "SELECT COUNT(*) FROM threat_actors WHERE severity IN ('high', 'critical')"
            )
            active_threats = cur.fetchone()[0]

            cur.execute(
                "SELECT COUNT(*) FROM bans WHERE status = ?",
                (BanStatus.ACTIVE.value,),
            )
            active_bans = cur.fetchone()[0]

            cur.execute(
                "SELECT COUNT(*) FROM iocs WHERE status = ?",
                (IOCStatus.ACTIVE.value,),
            )
            active_iocs = cur.fetchone()[0]

            cur.execute(
                "SELECT COUNT(*) FROM incidents WHERE status IN ('open', 'investigating')"
            )
            open_incidents = cur.fetchone()[0]

            cur.execute("SELECT COUNT(*) FROM response_audits")
            total_audits = cur.fetchone()[0]

            cur.execute(
                """
                SELECT username, COUNT(*) as cnt
                FROM events
                WHERE username IS NOT NULL AND username != ''
                GROUP BY username
                ORDER BY cnt DESC
                LIMIT 5
                """
            )
            top_usernames = [{"username": r[0], "count": r[1]} for r in cur.fetchall()]

            cur.execute(
                """
                SELECT source_ip, threat_score, severity, auth_failures
                FROM threat_actors
                ORDER BY threat_score DESC, auth_failures DESC
                LIMIT 5
                """
            )
            top_threats = [
                {
                    "source_ip": r[0],
                    "threat_score": r[1],
                    "severity": r[2],
                    "auth_failures": r[3],
                }
                for r in cur.fetchall()
            ]

            return {
                "total_events": total_events,
                "total_detections": total_detections,
                "total_actors": total_actors,
                "total_threat_actors": total_actors,
                "active_threats": active_threats,
                "active_bans": active_bans,
                "active_iocs": active_iocs,
                "open_incidents": open_incidents,
                "total_response_audits": total_audits,
                "top_usernames": top_usernames,
                "top_targeted_usernames": top_usernames,
                "top_threats": top_threats,
                "top_threat_actors": top_threats,
            }

    # ---------------------------------------------------------
    # Helper Deserializers
    # ---------------------------------------------------------

    def _row_to_threat_actor(self, row: sqlite3.Row) -> ThreatActorProfile:
        factors = [ScoreFactor.from_dict(f) for f in json.loads(row["factors"])] if row["factors"] else []
        usernames = set(json.loads(row["usernames"])) if row["usernames"] else set()
        services = set(json.loads(row["services"])) if row["services"] else set()

        first_seen = datetime.fromisoformat(row["first_seen"])
        if first_seen.tzinfo is None:
            first_seen = first_seen.replace(tzinfo=timezone.utc)

        last_seen = datetime.fromisoformat(row["last_seen"])
        if last_seen.tzinfo is None:
            last_seen = last_seen.replace(tzinfo=timezone.utc)

        return ThreatActorProfile(
            source_ip=row["source_ip"],
            first_seen=first_seen,
            last_seen=last_seen,
            total_events=row["total_events"],
            auth_failures=row["auth_failures"],
            auth_successes=row["auth_successes"],
            usernames_targeted=usernames,
            services_targeted=services,
            threat_score=row["threat_score"],
            severity=Severity(row["severity"]),
            state=ActorState(row["state"]),
            factors=factors,
            recommended_action=RecommendedAction(row["recommended_action"]),
            actor_id=f"actor-{row['source_ip']}",
            observed_ips={row["source_ip"]},
        )

    def _row_to_ban(self, row: sqlite3.Row) -> BanRecord:
        created_at = datetime.fromisoformat(row["created_at"])
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)

        expires_at = (
            datetime.fromisoformat(row["expires_at"])
            if row["expires_at"]
            else None
        )
        if expires_at and expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        meta = json.loads(row["metadata"]) if row["metadata"] else {}

        return BanRecord(
            ban_id=row["ban_id"],
            source_ip=row["source_ip"],
            reason=row["reason"],
            threat_score=row["threat_score"],
            created_at=created_at,
            expires_at=expires_at,
            action=ResponseAction(row["action"]),
            status=BanStatus(row["status"]),
            metadata=meta,
        )

    def _row_to_ioc(self, row: sqlite3.Row) -> IOCRecord:
        first_seen = datetime.fromisoformat(row["first_seen"])
        if first_seen.tzinfo is None:
            first_seen = first_seen.replace(tzinfo=timezone.utc)
        last_seen = datetime.fromisoformat(row["last_seen"])
        if last_seen.tzinfo is None:
            last_seen = last_seen.replace(tzinfo=timezone.utc)

        tags = [t.strip() for t in row["tags"].split(",") if t.strip()] if row["tags"] else []
        meta = json.loads(row["metadata"]) if row["metadata"] else {}

        return IOCRecord(
            ioc_id=row["ioc_id"],
            ioc_type=IOCType(row["ioc_type"]),
            value=row["value"],
            confidence=row["confidence"],
            source=row["source"],
            first_seen=first_seen,
            last_seen=last_seen,
            status=IOCStatus(row["status"]),
            provenance=Provenance(row["provenance"]),
            tags=tags,
            notes=row["notes"] or "",
            metadata=meta,
        )

    def _row_to_incident(self, row: sqlite3.Row) -> Incident:
        first_seen = datetime.fromisoformat(row["first_seen"])
        if first_seen.tzinfo is None:
            first_seen = first_seen.replace(tzinfo=timezone.utc)
        last_seen = datetime.fromisoformat(row["last_seen"])
        if last_seen.tzinfo is None:
            last_seen = last_seen.replace(tzinfo=timezone.utc)
        created_at = datetime.fromisoformat(row["created_at"])
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)
        updated_at = datetime.fromisoformat(row["updated_at"])
        if updated_at.tzinfo is None:
            updated_at = updated_at.replace(tzinfo=timezone.utc)

        techs = json.loads(row["attack_techniques"]) if row["attack_techniques"] else []
        meta = json.loads(row["metadata"]) if row["metadata"] else {}

        return Incident(
            incident_id=row["incident_id"],
            title=row["title"],
            status=IncidentStatus(row["status"]),
            severity=Severity(row["severity"]),
            risk_score=row["risk_score"],
            first_seen=first_seen,
            last_seen=last_seen,
            attack_techniques=techs,
            summary=row["summary"] or "",
            created_at=created_at,
            updated_at=updated_at,
            metadata=meta,
        )

    def close(self) -> None:
        """Close SQLite database connection."""
        with self._lock:
            self._connection.close()
