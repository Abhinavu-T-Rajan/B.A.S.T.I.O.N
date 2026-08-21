from __future__ import annotations

import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from bastion.models.actors import (
    ActorState,
    RecommendedAction,
    ScoreFactor,
    Severity,
    ThreatActorProfile,
)
from bastion.models.events import EventType, SecurityEvent, ServiceType
from bastion.response.models import BanRecord, BanStatus, ResponseAction


class SQLiteStorage:
    """Persistent SQLite storage engine for events, detections, threat profiles, and bans."""

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
        """Create database tables and indices if they do not exist."""
        with self._lock, self._connection:
            cur = self._connection.cursor()
            if self.db_path != ":memory:":
                cur.execute("PRAGMA journal_mode=WAL;")

            cur.executescript(
                """
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    service TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    username TEXT,
                    metadata TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_events_ip ON events (source_ip);
                CREATE INDEX IF NOT EXISTS idx_events_ts ON events (timestamp);
                CREATE INDEX IF NOT EXISTS idx_events_type ON events (event_type);

                CREATE TABLE IF NOT EXISTS detections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    detector_name TEXT NOT NULL,
                    reason TEXT,
                    event_count INTEGER DEFAULT 0,
                    threshold INTEGER DEFAULT 0,
                    details TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_det_ip ON detections (source_ip);
                CREATE INDEX IF NOT EXISTS idx_det_ts ON detections (timestamp);

                CREATE TABLE IF NOT EXISTS threat_actors (
                    source_ip TEXT PRIMARY KEY,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    total_events INTEGER DEFAULT 0,
                    auth_failures INTEGER DEFAULT 0,
                    auth_successes INTEGER DEFAULT 0,
                    usernames TEXT,
                    services TEXT,
                    threat_score INTEGER DEFAULT 0,
                    severity TEXT NOT NULL,
                    state TEXT NOT NULL,
                    factors TEXT,
                    recommended_action TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_actors_score ON threat_actors (threat_score DESC);
                CREATE INDEX IF NOT EXISTS idx_actors_severity ON threat_actors (severity);
                CREATE INDEX IF NOT EXISTS idx_actors_last_seen ON threat_actors (last_seen);

                CREATE TABLE IF NOT EXISTS score_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    score INTEGER NOT NULL,
                    severity TEXT NOT NULL,
                    factors TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_score_hist_ip ON score_history (source_ip);

                CREATE TABLE IF NOT EXISTS bans (
                    ban_id TEXT PRIMARY KEY,
                    source_ip TEXT NOT NULL,
                    reason TEXT,
                    threat_score INTEGER DEFAULT 0,
                    created_at TEXT NOT NULL,
                    expires_at TEXT,
                    action TEXT NOT NULL,
                    status TEXT NOT NULL,
                    metadata TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_bans_ip ON bans (source_ip);
                CREATE INDEX IF NOT EXISTS idx_bans_status ON bans (status);
                CREATE INDEX IF NOT EXISTS idx_bans_expires ON bans (expires_at);
                """
            )

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
                    json.dumps(event.metadata),
                ),
            )
            return cur.lastrowid or 0

    def save_detection(
        self,
        *,
        source_ip: str,
        detector_name: str,
        reason: str | None = None,
        event_count: int = 0,
        threshold: int = 0,
        details: dict[str, Any] | None = None,
        timestamp: datetime | None = None,
    ) -> int:
        """Record a triggered behavioral detection."""
        ts = (timestamp or datetime.now(timezone.utc)).isoformat()
        with self._lock, self._connection:
            cur = self._connection.cursor()
            cur.execute(
                """
                INSERT INTO detections (timestamp, source_ip, detector_name, reason, event_count, threshold, details)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ts,
                    source_ip,
                    detector_name,
                    reason,
                    event_count,
                    threshold,
                    json.dumps(details or {}),
                ),
            )
            return cur.lastrowid or 0

    def upsert_threat_actor(self, profile: ThreatActorProfile) -> None:
        """Insert or update a threat actor profile and log score history."""
        factors_json = json.dumps([f.to_dict() for f in profile.factors])
        usernames_json = json.dumps(sorted(profile.usernames_targeted))
        services_json = json.dumps(sorted(profile.services_targeted))

        with self._lock, self._connection:
            cur = self._connection.cursor()
            cur.execute(
                """
                INSERT INTO threat_actors (
                    source_ip, first_seen, last_seen, total_events,
                    auth_failures, auth_successes, usernames, services,
                    threat_score, severity, state, factors, recommended_action
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(source_ip) DO UPDATE SET
                    first_seen = excluded.first_seen,
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

            # Record score history
            cur.execute(
                """
                INSERT INTO score_history (timestamp, source_ip, score, severity, factors)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    profile.last_seen.isoformat(),
                    profile.source_ip,
                    profile.threat_score,
                    profile.severity.value,
                    factors_json,
                ),
            )

    def get_threat_actor(self, source_ip: str) -> ThreatActorProfile | None:
        """Retrieve a threat actor profile by IP address."""
        with self._lock:
            cur = self._connection.cursor()
            cur.execute(
                "SELECT * FROM threat_actors WHERE source_ip = ?", (source_ip,)
            )
            row = cur.fetchone()
            if not row:
                return None

            return self._row_to_profile(row)

    def list_threat_actors(
        self,
        min_score: int = 0,
        limit: int = 50,
    ) -> list[ThreatActorProfile]:
        """List threat actor profiles ordered by threat score descending."""
        with self._lock:
            cur = self._connection.cursor()
            cur.execute(
                """
                SELECT * FROM threat_actors
                WHERE threat_score >= ?
                ORDER BY threat_score DESC, last_seen DESC
                LIMIT ?
                """,
                (min_score, limit),
            )
            return [self._row_to_profile(row) for row in cur.fetchall()]

    def get_events(
        self,
        source_ip: str | None = None,
        since: datetime | None = None,
        limit: int = 100,
    ) -> list[SecurityEvent]:
        """Query security events with optional IP and timeframe filters."""
        query = "SELECT * FROM events WHERE 1=1"
        params: list[Any] = []

        if source_ip:
            query += " AND source_ip = ?"
            params.append(source_ip)
        if since:
            query += " AND timestamp >= ?"
            params.append(since.isoformat())

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        with self._lock:
            cur = self._connection.cursor()
            cur.execute(query, params)
            events = []
            for row in cur.fetchall():
                ts = datetime.fromisoformat(row["timestamp"])
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                meta = json.loads(row["metadata"]) if row["metadata"] else {}
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

    def save_ban(self, ban: BanRecord) -> None:
        """Persist or update a ban record."""
        meta_json = json.dumps(ban.metadata)
        with self._lock, self._connection:
            cur = self._connection.cursor()
            cur.execute(
                """
                INSERT INTO bans (
                    ban_id, source_ip, reason, threat_score,
                    created_at, expires_at, action, status, metadata
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
                    ban.expires_at.isoformat() if ban.expires_at else None,
                    ban.action.value,
                    ban.status.value,
                    meta_json,
                ),
            )

    def update_ban_status(self, ban_id: str, status: BanStatus) -> None:
        """Update lifecycle status of an existing ban."""
        with self._lock, self._connection:
            cur = self._connection.cursor()
            cur.execute(
                "UPDATE bans SET status = ? WHERE ban_id = ?",
                (status.value, ban_id),
            )

    def get_active_bans(self) -> list[BanRecord]:
        """Fetch all currently active ban records."""
        with self._lock:
            cur = self._connection.cursor()
            cur.execute(
                "SELECT * FROM bans WHERE status = ? ORDER BY created_at DESC",
                (BanStatus.ACTIVE.value,),
            )
            return [self._row_to_ban(r) for r in cur.fetchall()]

    def get_ban_by_ip(self, source_ip: str) -> BanRecord | None:
        """Fetch the most recent active ban record for a given IP."""
        with self._lock:
            cur = self._connection.cursor()
            cur.execute(
                "SELECT * FROM bans WHERE source_ip = ? AND status = ? ORDER BY created_at DESC LIMIT 1",
                (source_ip, BanStatus.ACTIVE.value),
            )
            row = cur.fetchone()
            if not row:
                return None
            return self._row_to_ban(row)

    def list_bans(
        self,
        status: BanStatus | None = None,
        limit: int = 50,
    ) -> list[BanRecord]:
        """List ban records with optional status filtering."""
        query = "SELECT * FROM bans"
        params: list[Any] = []
        if status:
            query += " WHERE status = ?"
            params.append(status.value)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        with self._lock:
            cur = self._connection.cursor()
            cur.execute(query, params)
            return [self._row_to_ban(r) for r in cur.fetchall()]

    def get_stats(self) -> dict[str, Any]:
        """Compute aggregated intelligence and operational metrics."""
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
                    "failures": r[3],
                }
                for r in cur.fetchall()
            ]

            return {
                "total_events": total_events,
                "total_detections": total_detections,
                "total_actors": total_actors,
                "active_threats": active_threats,
                "active_bans": active_bans,
                "top_targeted_usernames": top_usernames,
                "top_threats": top_threats,
            }

    def _row_to_profile(self, row: sqlite3.Row) -> ThreatActorProfile:
        factors_raw = json.loads(row["factors"]) if row["factors"] else []
        factors = [ScoreFactor.from_dict(f) for f in factors_raw]
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

    def close(self) -> None:
        """Close SQLite database connection."""
        with self._lock:
            self._connection.close()
