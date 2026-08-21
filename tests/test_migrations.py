"""Unit tests for SQLite schema migration runner."""

import sqlite3
from datetime import datetime, timezone

from bastion.storage.migrations import MigrationRunner
from bastion.storage.sqlite import SQLiteStorage


def test_migration_runner_applies_v1_and_v2() -> None:
    conn = sqlite3.connect(":memory:")
    version = MigrationRunner.apply_migrations(conn)
    assert version == 2

    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = {r[0] for r in cur.fetchall()}

    # Baseline tables
    assert "schema_version" in tables
    assert "events" in tables
    assert "detections" in tables
    assert "threat_actors" in tables
    assert "score_history" in tables
    assert "bans" in tables

    # Oracle tables
    assert "iocs" in tables
    assert "incidents" in tables
    assert "incident_events" in tables
    assert "incident_actors" in tables
    assert "incident_iocs" in tables
    assert "timeline_entries" in tables
    assert "response_audits" in tables


def test_migration_runner_idempotence() -> None:
    conn = sqlite3.connect(":memory:")
    v1 = MigrationRunner.apply_migrations(conn)
    assert v1 == 2

    # Running a second time should safely return current version without error
    v2 = MigrationRunner.apply_migrations(conn)
    assert v2 == 2


def test_sqlite_storage_initializes_with_migrations() -> None:
    storage = SQLiteStorage(":memory:")
    stats = storage.get_stats()
    assert "active_iocs" in stats
    assert "open_incidents" in stats
    assert "total_response_audits" in stats
