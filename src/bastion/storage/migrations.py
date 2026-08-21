from __future__ import annotations

import sqlite3
from datetime import datetime, timezone


class MigrationRunner:
    """Database schema migration manager for B.A.S.T.I.O.N. SQLite storage."""

    CURRENT_VERSION = 2

    @classmethod
    def apply_migrations(cls, conn: sqlite3.Connection) -> int:
        """Apply all pending migrations to the SQLite connection."""
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL,
                description TEXT
            );
            """
        )
        conn.commit()

        cur.execute("SELECT MAX(version) FROM schema_version;")
        row = cur.fetchone()
        current_db_version = row[0] if row and row[0] is not None else 0

        if current_db_version < 1:
            cls._apply_v1_baseline(conn)
            current_db_version = 1

        if current_db_version < 2:
            cls._apply_v2_oracle(conn)
            current_db_version = 2

        return current_db_version

    @classmethod
    def _apply_v1_baseline(cls, conn: sqlite3.Connection) -> None:
        """Initial baseline tables (v0.1.3 Guardian)."""
        cur = conn.cursor()
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

            INSERT OR IGNORE INTO schema_version (version, applied_at, description)
            VALUES (1, datetime('now'), 'v0.1.3 Guardian baseline schema');
            """
        )
        conn.commit()

    @classmethod
    def _apply_v2_oracle(cls, conn: sqlite3.Connection) -> None:
        """Oracle tables (v0.2.0-alpha: IOCs, Incidents, Timelines, Audits)."""
        cur = conn.cursor()
        cur.executescript(
            """
            CREATE TABLE IF NOT EXISTS iocs (
                ioc_id TEXT PRIMARY KEY,
                ioc_type TEXT NOT NULL,
                value TEXT NOT NULL,
                confidence INTEGER DEFAULT 50,
                source TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                status TEXT NOT NULL,
                provenance TEXT NOT NULL,
                tags TEXT,
                notes TEXT,
                metadata TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_iocs_val ON iocs (value);
            CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs (ioc_type);
            CREATE INDEX IF NOT EXISTS idx_iocs_status ON iocs (status);

            CREATE TABLE IF NOT EXISTS incidents (
                incident_id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                status TEXT NOT NULL,
                severity TEXT NOT NULL,
                risk_score INTEGER DEFAULT 0,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                attack_techniques TEXT,
                summary TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                metadata TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_inc_status ON incidents (status);
            CREATE INDEX IF NOT EXISTS idx_inc_sev ON incidents (severity);
            CREATE INDEX IF NOT EXISTS idx_inc_score ON incidents (risk_score DESC);

            CREATE TABLE IF NOT EXISTS incident_events (
                incident_id TEXT NOT NULL,
                event_id INTEGER NOT NULL,
                PRIMARY KEY (incident_id, event_id),
                FOREIGN KEY (incident_id) REFERENCES incidents (incident_id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_inc_events_eid ON incident_events (event_id);

            CREATE TABLE IF NOT EXISTS incident_actors (
                incident_id TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                PRIMARY KEY (incident_id, actor_id),
                FOREIGN KEY (incident_id) REFERENCES incidents (incident_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS incident_iocs (
                incident_id TEXT NOT NULL,
                ioc_id TEXT NOT NULL,
                PRIMARY KEY (incident_id, ioc_id),
                FOREIGN KEY (incident_id) REFERENCES incidents (incident_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS timeline_entries (
                entry_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                entry_type TEXT NOT NULL,
                source TEXT NOT NULL,
                summary TEXT NOT NULL,
                details TEXT,
                incident_id TEXT,
                actor_id TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_timeline_ts ON timeline_entries (timestamp);
            CREATE INDEX IF NOT EXISTS idx_timeline_inc ON timeline_entries (incident_id);
            CREATE INDEX IF NOT EXISTS idx_timeline_act ON timeline_entries (actor_id);
            CREATE INDEX IF NOT EXISTS idx_timeline_type ON timeline_entries (entry_type);

            CREATE TABLE IF NOT EXISTS response_audits (
                audit_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT NOT NULL,
                actor_id TEXT,
                incident_id TEXT,
                executed_by TEXT NOT NULL,
                dry_run INTEGER NOT NULL,
                success INTEGER NOT NULL,
                details TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_resp_audit_ts ON response_audits (timestamp);
            CREATE INDEX IF NOT EXISTS idx_resp_audit_target ON response_audits (target);

            INSERT OR IGNORE INTO schema_version (version, applied_at, description)
            VALUES (2, datetime('now'), 'v0.2.0-alpha Oracle threat intelligence and investigation schema');
            """
        )
        conn.commit()
