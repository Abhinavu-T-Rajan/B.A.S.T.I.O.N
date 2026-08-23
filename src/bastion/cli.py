from __future__ import annotations

import argparse
import sys
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from bastion.config import (
    BastionConfig,
    ConfigValidationError,
    load_config,
    validate_config,
)
from bastion.core.contracts.collector import CollectorProvider
from bastion.core.contracts.firewall import FirewallProvider
from bastion.core.contracts.storage import StorageProvider
from bastion.daemon.runner import BastionDaemon
from bastion.daemon.state import (
    DaemonHealthSnapshot,
    HealthStatus,
    HealthTracker,
    ServiceState,
    Subsystem,
    SubsystemHealth,
)
from bastion.detection.base import DetectionResult
from bastion.detection.brute_force import BruteForceDetector
from bastion.detection.burst import BurstDetector
from bastion.detection.engine import DetectionEngine
from bastion.detection.enumeration import UsernameEnumerationDetector
from bastion.detection.password_spray import PasswordSprayDetector
from bastion.firewall.mock import MockFirewallBackend
from bastion.firewall.nftables import NFTablesBackend
from bastion.infrastructure.telemetry.file import FileCollector
from bastion.infrastructure.telemetry.journald import JournaldCollector
from bastion.infrastructure.telemetry.stdin import StdinCollector
from bastion.models.actors import (
    ActorState,
    RecommendedAction,
    Severity,
    ThreatActorProfile,
)
from bastion.models.events import EventType, SecurityEvent, ServiceType
from bastion.response.ban_manager import BanManager
from bastion.response.engine import ResponseEngine
from bastion.response.models import (
    BanRecord,
    BanStatus,
    ResponseAction,
    ResponseDecision,
    ResponseMode,
)
from bastion.response.policy import PolicyConfig, PolicyEngine
from bastion.risk.scorer import RiskEngine
from bastion.services.defense import DefenseAppService
from bastion.services.health import HealthAppService
from bastion.services.incidents import IncidentAppService
from bastion.services.intelligence import IntelligenceAppService
from bastion.services.pipeline import SentinelPipeline
from bastion.storage.migrations import MigrationRunner
from bastion.storage.sqlite import SQLiteStorage
from bastion.version import __version__


def build_parser() -> argparse.ArgumentParser:
    """Build the B.A.S.T.I.O.N. CLI parser."""
    common_parent = argparse.ArgumentParser(add_help=False)
    common_parent.add_argument(
        "--config",
        "-c",
        type=str,
        default=argparse.SUPPRESS,
        help="Path to custom bastion.toml configuration file.",
    )
    common_parent.add_argument(
        "--db",
        type=str,
        default=argparse.SUPPRESS,
        help="Override SQLite database path.",
    )
    common_parent.add_argument(
        "--backend",
        choices=["nftables", "mock"],
        default=argparse.SUPPRESS,
        help="Firewall backend override.",
    )

    parser = argparse.ArgumentParser(
        prog="bastion",
        parents=[common_parent],
        description=(
            "Behavioral Attack Surveillance & Threat Isolation Operating Network (Sentinel Core)"
        ),
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"B.A.S.T.I.O.N. v{__version__} (Sentinel Core)",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    # 1. status
    status_parser = subparsers.add_parser(
        "status",
        parents=[common_parent],
        help="Show operational status and subsystem health.",
    )
    status_parser.set_defaults(handler=command_status)

    # 2. health
    health_parser = subparsers.add_parser(
        "health",
        parents=[common_parent],
        help="Display operational health diagnostics across all subsystems.",
    )
    health_parser.add_argument(
        "--json",
        action="store_true",
        help="Output health report in JSON format.",
    )
    health_parser.set_defaults(handler=command_health)

    # 3. daemon / service
    daemon_parser = subparsers.add_parser(
        "daemon",
        aliases=["service", "run"],
        parents=[common_parent],
        help="Start the persistent B.A.S.T.I.O.N. Sentinel Core defense service.",
    )
    daemon_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Force defense response into dry-run mode.",
    )
    daemon_parser.add_argument(
        "--enforce",
        action="store_true",
        help="Force defense response into automatic enforcement mode.",
    )
    daemon_parser.add_argument(
        "--mode",
        choices=["dry_run", "manual", "automatic", "disabled"],
        help="Explicit response mode override.",
    )
    daemon_parser.add_argument(
        "--source",
        choices=["journald", "stdin", "file"],
        help="Telemetry ingestion source override.",
    )
    daemon_parser.add_argument(
        "--file",
        type=str,
        help="Log file path when source is file.",
    )
    daemon_parser.set_defaults(handler=command_daemon)

    # 4. threats / actors
    threats_parser = subparsers.add_parser(
        "threats",
        aliases=["actors"],
        parents=[common_parent],
        help="List tracked threat actors and risk scores.",
    )
    threats_parser.add_argument(
        "--min-score",
        type=int,
        default=0,
        help="Filter actors with threat score >= min_score (default: 0).",
    )
    threats_parser.add_argument(
        "--severity",
        choices=["low", "medium", "high", "critical"],
        help="Filter by severity level.",
    )
    threats_parser.add_argument(
        "--limit",
        type=int,
        default=25,
        help="Maximum number of actors to display (default: 25).",
    )
    threats_parser.set_defaults(handler=command_threats)

    # 5. inspect
    inspect_parser = subparsers.add_parser(
        "inspect",
        parents=[common_parent],
        help="Inspect forensic details and score factors for a specific IP.",
    )
    inspect_parser.add_argument(
        "source_ip",
        type=str,
        help="The IP address to inspect.",
    )
    inspect_parser.set_defaults(handler=command_inspect)

    # 6. bans
    bans_parser = subparsers.add_parser(
        "bans",
        parents=[common_parent],
        help="List active or historical host isolation bans.",
    )
    bans_parser.add_argument(
        "--all",
        action="store_true",
        help="Include expired and revoked bans.",
    )
    bans_parser.add_argument(
        "--limit",
        type=int,
        default=50,
        help="Maximum bans to display (default: 50).",
    )
    bans_parser.set_defaults(handler=command_bans)

    # 7. ban
    ban_parser = subparsers.add_parser(
        "ban",
        parents=[common_parent],
        help="Manually isolate an IP address via the response engine.",
    )
    ban_parser.add_argument(
        "ip",
        type=str,
        help="IP address to isolate.",
    )
    ban_parser.add_argument(
        "--duration",
        type=int,
        default=900,
        help="Ban duration in seconds (default: 900 / 15m).",
    )
    ban_parser.add_argument(
        "--permanent",
        action="store_true",
        help="Apply a permanent isolation ban.",
    )
    ban_parser.add_argument(
        "--reason",
        type=str,
        default="Manual operator ban",
        help="Reason for manual isolation.",
    )
    ban_parser.set_defaults(handler=command_ban)

    # 8. unban
    unban_parser = subparsers.add_parser(
        "unban",
        parents=[common_parent],
        help="Release an active ban and unblock IP in firewall backend.",
    )
    unban_parser.add_argument(
        "ip",
        type=str,
        help="IP address to unblock.",
    )
    unban_parser.set_defaults(handler=command_unban)

    # 9. firewall
    firewall_parser = subparsers.add_parser(
        "firewall",
        parents=[common_parent],
        help="Inspect or flush firewall tables and sets.",
    )
    firewall_sub = firewall_parser.add_subparsers(
        dest="firewall_action",
        required=True,
    )
    fw_status = firewall_sub.add_parser(
        "status",
        parents=[common_parent],
        help="Show firewall table rules and active blacklist sets.",
    )
    fw_status.set_defaults(handler=command_firewall_status)

    fw_flush = firewall_sub.add_parser(
        "flush",
        parents=[common_parent],
        help="Flush all B.A.S.T.I.O.N. firewall blacklist entries.",
    )
    fw_flush.set_defaults(handler=command_firewall_flush)

    # 10. incident / incidents
    incident_parser = subparsers.add_parser(
        "incident",
        aliases=["incidents"],
        parents=[common_parent],
        help="Manage and inspect security incidents.",
    )
    inc_sub = incident_parser.add_subparsers(dest="incident_action", required=True)

    inc_list = inc_sub.add_parser("list", parents=[common_parent], help="List security incidents.")
    inc_list.add_argument("--status", choices=["open", "investigating", "contained", "resolved", "closed"])
    inc_list.add_argument("--limit", type=int, default=25)
    inc_list.set_defaults(handler=command_incident_list)

    inc_inspect = inc_sub.add_parser("inspect", parents=[common_parent], help="Inspect an incident in detail.")
    inc_inspect.add_argument("incident_id", type=str)
    inc_inspect.set_defaults(handler=command_incident_inspect)

    inc_update = inc_sub.add_parser("update", parents=[common_parent], help="Update incident status.")
    inc_update.add_argument("incident_id", type=str)
    inc_update.add_argument("--status", choices=["open", "investigating", "contained", "resolved", "closed"], required=True)
    inc_update.add_argument("--notes", type=str, default="")
    inc_update.set_defaults(handler=command_incident_update)

    inc_create = inc_sub.add_parser("create", parents=[common_parent], help="Create a manual incident.")
    inc_create.add_argument("--title", type=str, required=True)
    inc_create.add_argument("--severity", choices=["low", "medium", "high", "critical"], default="medium")
    inc_create.add_argument("--risk", type=int, default=50)
    inc_create.add_argument("--actors", type=str, help="Comma-separated IP addresses.")
    inc_create.add_argument("--summary", type=str, default="")
    inc_create.set_defaults(handler=command_incident_create)

    # 11. ioc
    ioc_parser = subparsers.add_parser(
        "ioc",
        parents=[common_parent],
        help="Manage local threat intelligence IOCs.",
    )
    ioc_sub = ioc_parser.add_subparsers(dest="ioc_action", required=True)

    ioc_add = ioc_sub.add_parser("add", parents=[common_parent], help="Add a new IOC record.")
    ioc_add.add_argument("--type", choices=["ip", "domain", "hash_md5", "hash_sha1", "hash_sha256", "username"], required=True)
    ioc_add.add_argument("--value", type=str, required=True)
    ioc_add.add_argument("--confidence", type=int, default=70)
    ioc_add.add_argument("--source", type=str, default="operator")
    ioc_add.add_argument("--tags", type=str, help="Comma-separated tags (e.g. ssh,bruteforce).")
    ioc_add.add_argument("--notes", type=str, default="")
    ioc_add.set_defaults(handler=command_ioc_add)

    ioc_list = ioc_sub.add_parser("list", parents=[common_parent], help="List IOC records.")
    ioc_list.add_argument("--type", choices=["ip", "domain", "hash_md5", "hash_sha1", "hash_sha256", "username"])
    ioc_list.add_argument("--status", choices=["active", "revoked", "expired"])
    ioc_list.add_argument("--limit", type=int, default=50)
    ioc_list.set_defaults(handler=command_ioc_list)

    ioc_search = ioc_sub.add_parser("search", parents=[common_parent], help="Search IOCs by value, tag, or notes.")
    ioc_search.add_argument("query", type=str)
    ioc_search.add_argument("--limit", type=int, default=50)
    ioc_search.set_defaults(handler=command_ioc_search)

    ioc_delete = ioc_sub.add_parser("delete", parents=[common_parent], help="Delete an IOC record.")
    ioc_delete.add_argument("ioc_id", type=str)
    ioc_delete.set_defaults(handler=command_ioc_delete)

    # 12. timeline
    timeline_parser = subparsers.add_parser(
        "timeline",
        parents=[common_parent],
        help="Reconstruct chronological investigation timeline for an IP or incident.",
    )
    timeline_parser.add_argument("--ip", type=str, help="Source IP to generate timeline for.")
    timeline_parser.add_argument("--incident", type=str, help="Incident ID to generate timeline for.")
    timeline_parser.add_argument("--limit", type=int, default=50, help="Max entries to show.")
    timeline_parser.set_defaults(handler=command_timeline)

    # 13. attack / mitre
    attack_parser = subparsers.add_parser(
        "attack",
        aliases=["mitre"],
        parents=[common_parent],
        help="View MITRE ATT&CK technique catalog and detector mappings.",
    )
    attack_parser.add_argument("technique_id", nargs="?", help="Optional technique ID to inspect (e.g. T1110.001).")
    attack_parser.set_defaults(handler=command_attack)

    # 14. events
    events_parser = subparsers.add_parser(
        "events",
        parents=[common_parent],
        help="List raw normalized security events.",
    )
    events_parser.add_argument("--ip", type=str, help="Filter by source IP.")
    events_parser.add_argument(
        "--type",
        choices=["auth_failure", "auth_success", "invalid_user", "max_attempts_exceeded", "connection", "unknown"],
        help="Filter by event type.",
    )
    events_parser.add_argument("--limit", type=int, default=50, help="Maximum events to display.")
    events_parser.set_defaults(handler=command_events)

    # 15. stats
    stats_parser = subparsers.add_parser(
        "stats",
        parents=[common_parent],
        help="Display aggregated threat intelligence metrics.",
    )
    stats_parser.set_defaults(handler=command_stats)

    # 16. config
    config_parser = subparsers.add_parser(
        "config",
        parents=[common_parent],
        help="Configuration inspection and validation tools.",
    )
    config_sub = config_parser.add_subparsers(dest="config_action", required=True)
    cfg_show = config_sub.add_parser("show", parents=[common_parent], help="Show active configuration.")
    cfg_show.set_defaults(handler=command_config_show)

    cfg_val = config_sub.add_parser("validate", parents=[common_parent], help="Validate configuration constraints.")
    cfg_val.set_defaults(handler=command_config_validate)

    # 17. parse
    parse_parser = subparsers.add_parser(
        "parse",
        parents=[common_parent],
        help="Parse and inspect a raw log line.",
    )
    parse_parser.add_argument("line", type=str, help="Log line to parse.")
    parse_parser.set_defaults(handler=command_parse)

    # 18. test-detection
    test_det_parser = subparsers.add_parser(
        "test-detection",
        parents=[common_parent],
        help="Run local deterministic brute-force simulation.",
    )
    test_det_parser.add_argument("--attempts", type=int, default=12, help="Number of simulated attempts.")
    test_det_parser.add_argument("--threshold", type=int, default=10, help="Detection threshold.")
    test_det_parser.set_defaults(handler=command_test_detection)

    # 19. monitor
    monitor_parser = subparsers.add_parser(
        "monitor",
        parents=[common_parent],
        help="Monitor live journald logs or stdin with real-time IPS defense.",
    )
    monitor_parser.add_argument("--follow", "-f", action="store_true", help="Continuously follow live journal logs.")
    monitor_parser.add_argument("--lines", "-n", type=int, default=100, help="Number of existing lines to process.")
    monitor_parser.add_argument("--stdin", action="store_true", help="Read log lines from standard input.")
    monitor_parser.add_argument("--file", type=str, help="Read log lines from a file.")
    monitor_parser.add_argument("--min-score", type=int, default=70, help="Minimum threat score to trigger alert display.")
    monitor_parser.add_argument("--dry-run", action="store_true", help="Force response engine into dry-run mode.")
    monitor_parser.add_argument("--enforce", action="store_true", help="Force response engine into automatic enforcement mode.")
    monitor_parser.add_argument("--mode", choices=["dry_run", "manual", "automatic", "disabled"], help="Explicit response mode override.")
    monitor_parser.set_defaults(handler=command_monitor)

    # 20. db
    db_parser = subparsers.add_parser(
        "db",
        parents=[common_parent],
        help="Database management and migration commands.",
    )
    db_sub = db_parser.add_subparsers(dest="db_action", required=True)
    db_init_p = db_sub.add_parser("init", parents=[common_parent], help="Initialize database schema and apply migrations.")
    db_init_p.set_defaults(handler=command_db_init)

    db_stat_p = db_sub.add_parser("status", parents=[common_parent], help="Check database schema and statistics.")
    db_stat_p.set_defaults(handler=command_db_status)

    return parser


def _get_firewall_backend(cfg: BastionConfig, backend_override: str | None = None) -> FirewallProvider:
    """Instantiate appropriate firewall backend based on CLI flag or config."""
    choice = backend_override or cfg.response.backend
    if choice == "mock":
        return MockFirewallBackend()
    import shutil
    if shutil.which("nft") is None:
        return MockFirewallBackend()
    try:
        return NFTablesBackend(table_name=cfg.response.table_name)
    except Exception:
        return MockFirewallBackend()


def _get_config_from_args(args: argparse.Namespace) -> BastionConfig:
    """Load configuration with CLI override flags applied safely."""
    cfg_path = getattr(args, "config", None)
    cfg = load_config(cfg_path)
    db_val = getattr(args, "db", None)
    if db_val:
        cfg.storage.db_path = db_val
    backend_val = getattr(args, "backend", None)
    if backend_val:
        cfg.response.backend = backend_val
    return cfg


# =====================================================================
# CLI Command Handlers (Thin Delegates to Application Services)
# =====================================================================

def command_daemon(args: argparse.Namespace) -> int:
    """Run the persistent B.A.S.T.I.O.N. Sentinel Core service."""
    cfg_path = getattr(args, "config", None)
    cfg = _get_config_from_args(args)

    # Apply daemon CLI overrides
    if getattr(args, "dry_run", False):
        cfg.response.mode = "dry_run"
    elif getattr(args, "enforce", False):
        cfg.response.mode = "automatic"
    elif getattr(args, "mode", None):
        cfg.response.mode = args.mode
    if getattr(args, "source", None):
        cfg.telemetry.source = args.source
    if getattr(args, "file", None):
        cfg.telemetry.log_file_path = args.file

    daemon = BastionDaemon(config=cfg, config_path=cfg_path)
    return daemon.run()


def command_health(args: argparse.Namespace) -> int:
    """Display operational health diagnostics across all subsystems."""
    cfg = _get_config_from_args(args)
    snapshot = HealthAppService.load_snapshot(cfg.daemon.health_state_path)

    if snapshot is None:
        storage = SQLiteStorage(cfg.storage.db_path)
        fw = _get_firewall_backend(cfg, getattr(args, "backend", None))
        snapshot = HealthAppService.probe_live_health(cfg, storage, fw)
        storage.close()

    if getattr(args, "json", False):
        import json
        print(json.dumps(snapshot.to_dict(), indent=2))
    else:
        print(HealthAppService.format_report(snapshot))

    return 0 if snapshot.overall_health != HealthStatus.FAILED else 1


def command_config_validate(args: argparse.Namespace) -> int:
    """Validate configuration syntax and parameter constraints."""
    try:
        cfg = _get_config_from_args(args)
        errors = validate_config(cfg)
        if errors:
            print("❌ Configuration validation failed:")
            for err in errors:
                print(f"  • {err}")
            return 1
        print("✓ Configuration is valid and all parameter constraints are satisfied.")
        return 0
    except ConfigValidationError as exc:
        print(f"❌ Configuration error: {exc}")
        return 1
    except Exception as exc:
        print(f"❌ Failed to load configuration: {exc}")
        return 1


def command_db_init(args: argparse.Namespace) -> int:
    """Initialize database schemas and apply pending migrations."""
    cfg = _get_config_from_args(args)
    db_path = cfg.storage.db_path
    try:
        storage = SQLiteStorage(db_path)
        print("✓ SQLite database schema initialized and migrated successfully.")
        print(f"  Database Path  : {db_path}")
        print(f"  Schema Version : {MigrationRunner.CURRENT_VERSION}")
        storage.close()
        return 0
    except Exception as exc:
        print(f"❌ Failed to initialize database: {exc}")
        return 1


def command_db_status(args: argparse.Namespace) -> int:
    """Inspect database schema migration version and table record counts."""
    cfg = _get_config_from_args(args)
    db_path = cfg.storage.db_path
    try:
        storage = SQLiteStorage(db_path)
        stats = storage.get_stats()
        print("=" * 64)
        print(" B.A.S.T.I.O.N. Database Status")
        print("=" * 64)
        print(f" Database Path  : {db_path}")
        print(f" Schema Version : {MigrationRunner.CURRENT_VERSION}")
        print(f" Total Events   : {stats['total_events']}")
        print(f" Threat Actors  : {stats['total_threat_actors']}")
        print(f" Active Bans      : {stats['active_bans']}")
        print(f" Active IOCs      : {stats['active_iocs']}")
        print(f" Open Incidents : {stats['open_incidents']}")
        print("=" * 64)
        storage.close()
        return 0
    except Exception as exc:
        print(f"❌ Failed to inspect database: {exc}")
        return 1


def command_status(args: argparse.Namespace) -> int:
    """Show operational status and subsystem health."""
    cfg = _get_config_from_args(args)
    storage = SQLiteStorage(cfg.storage.db_path)
    fw = _get_firewall_backend(cfg, getattr(args, "backend", None))
    defense_svc = DefenseAppService(storage=storage, firewall=fw)
    overview = defense_svc.get_status_overview(response_mode=cfg.response.mode)

    snapshot = HealthAppService.load_snapshot(cfg.daemon.health_state_path)
    if snapshot and snapshot.service_state == ServiceState.RUNNING:
        if snapshot.overall_health == HealthStatus.DEGRADED:
            status_line = f"DEGRADED (Sentinel Core v{__version__})"
        elif snapshot.overall_health == HealthStatus.FAILED:
            status_line = f"FAILED (Sentinel Core v{__version__})"
        else:
            status_line = f"RUNNING (Sentinel Core v{__version__})"
    else:
        if cfg.response.mode.lower() == "automatic" and not overview["firewall_available"]:
            status_line = f"DEGRADED (Sentinel Core v{__version__}) - Firewall unavailable"
        else:
            status_line = f"DEVELOPMENT (Sentinel Core v{__version__})"

    print("=" * 64)
    print(f" B.A.S.T.I.O.N. Host Defense Engine v{__version__} (Sentinel Core)")
    print(f" Status      : {status_line}")
    print(f" Mode        : INTRUSION PREVENTION & THREAT ISOLATION")
    print("=" * 64)
    print(f" Database         : {cfg.storage.db_path}")
    print(f" Response Mode    : {overview['response_mode']}")
    print(f" Firewall Backend : {overview['firewall_backend']} ({'Available' if overview['firewall_available'] else 'Unavailable'})")
    print(f" Total Events     : {overview['total_events']}")
    print(f" Detections       : {overview['total_detections']}")
    print(f" Threat Actors    : {overview['total_threat_actors']} ({overview['active_threats']} active high/critical)")
    print(f" Active Bans      : {overview['active_bans']}")
    print(f" Active IOCs      : {overview['active_iocs']}")
    print(f" Open Incidents   : {overview['open_incidents']}")
    print("=" * 64)
    storage.close()
    return 0


def command_threats(args: argparse.Namespace) -> int:
    """List tracked threat actors and risk scores."""
    cfg = _get_config_from_args(args)
    storage = SQLiteStorage(cfg.storage.db_path)
    fw = _get_firewall_backend(cfg, getattr(args, "backend", None))
    defense_svc = DefenseAppService(storage=storage, firewall=fw)

    actors = defense_svc.list_threats(
        min_score=getattr(args, "min_score", 0),
        limit=getattr(args, "limit", 25),
        severity=getattr(args, "severity", None),
    )

    if not actors:
        print("No threat actors matching criteria.")
        storage.close()
        return 0

    print(f"{'SOURCE IP':<18} {'SCORE':<7} {'SEVERITY':<10} {'STATE':<14} {'FAILURES':<10} {'ACTION':<20} {'LAST SEEN'}")
    print("-" * 105)
    for a in actors:
        last_str = a.last_seen.strftime("%Y-%m-%d %H:%M:%S")
        print(f"{a.source_ip:<18} {a.threat_score:<7} {a.severity.value.upper():<10} {a.state.value:<14} {a.auth_failures:<10} {a.recommended_action.value:<20} {last_str}")
    storage.close()
    return 0


def command_inspect(args: argparse.Namespace) -> int:
    """Inspect forensic details and score factors for a specific IP."""
    cfg = _get_config_from_args(args)
    storage = SQLiteStorage(cfg.storage.db_path)
    fw = _get_firewall_backend(cfg, getattr(args, "backend", None))
    defense_svc = DefenseAppService(storage=storage, firewall=fw)

    data = defense_svc.inspect_ip(args.source_ip)
    actor = data["profile"]
    if not actor:
        print(f"No threat actor record found for IP: {args.source_ip}")
        storage.close()
        return 1

    ban = data["active_ban"]
    print("=" * 64)
    print(f" Threat Actor Forensic Profile: {actor.source_ip}")
    print("=" * 64)
    print(f" Threat Score      : {actor.threat_score} / 100")
    print(f" Severity          : {actor.severity.value.upper()}")
    print(f" Lifecycle State   : {actor.state.value.upper()}")
    print(f" Recommended Action: {actor.recommended_action.value.upper()}")
    print(f" Auth Failures     : {actor.auth_failures}")
    print(f" Auth Successes    : {actor.auth_successes}")
    print(f" First Seen        : {actor.first_seen.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f" Last Seen         : {actor.last_seen.strftime('%Y-%m-%d %H:%M:%S UTC')}")

    if ban:
        exp_str = ban.expires_at.strftime('%Y-%m-%d %H:%M:%S UTC') if ban.expires_at else "Permanent"
        print(f" Active Ban ID     : {ban.ban_id} (Expires: {exp_str})")

    if actor.usernames_targeted:
        print(f" Targeted Users    : {', '.join(sorted(actor.usernames_targeted))}")

    print("\n Contributing Risk Factors:")
    if actor.factors:
        for f in actor.factors:
            sign = "+" if f.score_delta > 0 else ""
            print(f"   • [{f.factor_type}] ({sign}{f.score_delta}) {f.description}")
    else:
        print("   • No active risk factors recorded.")
    print("=" * 64)
    storage.close()
    return 0


def command_bans(args: argparse.Namespace) -> int:
    """List active or historical host isolation bans."""
    cfg = _get_config_from_args(args)
    storage = SQLiteStorage(cfg.storage.db_path)
    fw = _get_firewall_backend(cfg, getattr(args, "backend", None))
    defense_svc = DefenseAppService(storage=storage, firewall=fw)

    bans = defense_svc.list_bans(active_only=not getattr(args, "all", False), limit=getattr(args, "limit", 50))
    if not bans:
        print("No ban records found.")
        storage.close()
        return 0

    print(f"{'BAN ID':<14} {'SOURCE IP':<18} {'STATUS':<10} {'SCORE':<7} {'ACTION':<20} {'EXPIRES AT'}")
    print("-" * 90)
    for b in bans:
        exp_str = b.expires_at.strftime("%Y-%m-%d %H:%M:%S") if b.expires_at else "Permanent"
        print(f"{b.ban_id:<14} {b.source_ip:<18} {b.status.value.upper():<10} {b.threat_score:<7} {b.action.value:<20} {exp_str}")
    storage.close()
    return 0


def command_ban(args: argparse.Namespace) -> int:
    """Manually isolate an IP address."""
    cfg = _get_config_from_args(args)
    storage = SQLiteStorage(cfg.storage.db_path)
    fw = _get_firewall_backend(cfg, getattr(args, "backend", None))
    defense_svc = DefenseAppService(storage=storage, firewall=fw)

    success, msg, record = defense_svc.ban_ip(
        source_ip=args.ip,
        duration_seconds=getattr(args, "duration", 900),
        permanent=getattr(args, "permanent", False),
        reason=getattr(args, "reason", "Manual operator ban"),
    )
    if success and record:
        exp_str = f"for {args.duration}s" if record.duration_seconds else "permanently"
        print(f"✓ {args.ip} successfully isolated {exp_str} (Ban ID: {record.ban_id})")
        storage.close()
        return 0
    else:
        print(f"❌ Failed to ban {args.ip}: {msg}")
        storage.close()
        return 1


def command_unban(args: argparse.Namespace) -> int:
    """Release an active ban and unblock IP."""
    cfg = _get_config_from_args(args)
    storage = SQLiteStorage(cfg.storage.db_path)
    fw = _get_firewall_backend(cfg, getattr(args, "backend", None))
    defense_svc = DefenseAppService(storage=storage, firewall=fw)

    success, msg = defense_svc.unban_ip(args.ip, reason="Manual operator unban")
    if success:
        print(f"✓ {args.ip} successfully released from isolation.")
        storage.close()
        return 0
    else:
        print(f"No active ban record found for IP: {args.ip}")
        storage.close()
        return 1


def command_firewall_status(args: argparse.Namespace) -> int:
    """Show firewall table rules and active blacklist sets."""
    cfg = _get_config_from_args(args)
    storage = SQLiteStorage(cfg.storage.db_path)
    fw = _get_firewall_backend(cfg, getattr(args, "backend", None))
    defense_svc = DefenseAppService(storage=storage, firewall=fw)

    st = defense_svc.get_firewall_status()
    print("=" * 64)
    print(" B.A.S.T.I.O.N. Firewall Status")
    print("=" * 64)
    print(f" Backend Name : {st['backend_name'].upper()}")
    print(f" Available    : {'Yes' if st['available'] else 'No'}")

    blocked = st["blocked_ips"]
    print(f" Blocked IPs  : {len(blocked)}")
    if blocked:
        for ip in blocked:
            print(f"   • {ip}")
    print("=" * 64)
    storage.close()
    return 0


def command_firewall_flush(args: argparse.Namespace) -> int:
    """Flush all B.A.S.T.I.O.N. firewall blacklist entries."""
    cfg = _get_config_from_args(args)
    storage = SQLiteStorage(cfg.storage.db_path)
    fw = _get_firewall_backend(cfg, getattr(args, "backend", None))
    defense_svc = DefenseAppService(storage=storage, firewall=fw)

    success, msg = defense_svc.flush_firewall()
    if success:
        print(f"✓ B.A.S.T.I.O.N. firewall blacklist rules successfully flushed ({fw.name.upper()}).")
        storage.close()
        return 0
    else:
        print(f"❌ {msg}")
        storage.close()
        return 1


def command_incident_list(args: argparse.Namespace) -> int:
    """List security incidents."""
    cfg = _get_config_from_args(args)
    storage = SQLiteStorage(cfg.storage.db_path)
    inc_svc = IncidentAppService(storage)

    incidents = inc_svc.list_incidents(status=getattr(args, "status", None), limit=getattr(args, "limit", 25))

    if not incidents:
        print("No incidents found.")
        storage.close()
        return 0

    print(f"{'INCIDENT ID':<14} {'STATUS':<14} {'SEVERITY':<10} {'RISK':<6} {'TITLE'}")
    print("-" * 80)
    for inc in incidents:
        print(f"{inc.incident_id:<14} {inc.status.value.upper():<14} {inc.severity.value.upper():<10} {inc.risk_score:<6} {inc.title}")
    storage.close()
    return 0


def command_incident_inspect(args: argparse.Namespace) -> int:
    """Inspect an incident in detail."""
    cfg = _get_config_from_args(args)
    storage = SQLiteStorage(cfg.storage.db_path)
    inc_svc = IncidentAppService(storage)

    inc = inc_svc.get_incident(args.incident_id)
    if not inc:
        print(f"Incident '{args.incident_id}' not found.")
        storage.close()
        return 1

    print("=" * 64)
    print(f" Incident: {inc.incident_id} [{inc.status.value.upper()}]")
    print("=" * 64)
    print(f" Title       : {inc.title}")
    print(f" Severity    : {inc.severity.value.upper()} (Risk Score: {inc.risk_score})")
    print(f" Created At  : {inc.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f" Summary     : {inc.summary}")

    if inc.attack_techniques:
        print(f" ATT&CK Tech : {', '.join(inc.attack_techniques)}")
    if inc.actor_ids:
        print(f" Threat Actor: {', '.join(inc.actor_ids)}")
    if inc.ioc_ids:
        print(f" Associated IOCs: {', '.join(inc.ioc_ids)}")
    print("=" * 64)
    storage.close()
    return 0


def command_incident_update(args: argparse.Namespace) -> int:
    """Update incident status."""
    cfg = _get_config_from_args(args)
    storage = SQLiteStorage(cfg.storage.db_path)
    inc_svc = IncidentAppService(storage)

    success, msg = inc_svc.update_status(args.incident_id, args.status, resolution_notes=getattr(args, "notes", None))
    if not success:
        print(f"❌ {msg}")
        storage.close()
        return 1
    print(f"✓ {msg}")
    storage.close()
    return 0


def command_incident_create(args: argparse.Namespace) -> int:
    """Create a manual incident."""
    cfg = _get_config_from_args(args)
    storage = SQLiteStorage(cfg.storage.db_path)
    inc_svc = IncidentAppService(storage)

    actors = [a.strip() for a in args.actors.split(",")] if getattr(args, "actors", None) else []
    inc = inc_svc.create_incident(
        title=args.title,
        severity=args.severity,
        description=getattr(args, "summary", ""),
        actor_ips=actors,
    )
    print(f"✓ Created incident {inc.incident_id}: {inc.title}")
    storage.close()
    return 0


def command_ioc_add(args: argparse.Namespace) -> int:
    """Add a new IOC record."""
    cfg = _get_config_from_args(args)
    storage = SQLiteStorage(cfg.storage.db_path)
    intel_svc = IntelligenceAppService(storage)

    tags = [t.strip() for t in args.tags.split(",")] if getattr(args, "tags", None) else []
    success, msg, record = intel_svc.add_ioc(
        ioc_type=args.type,
        value=args.value,
        description=getattr(args, "notes", ""),
        confidence=args.confidence,
        tags=tags,
    )
    if success and record:
        print(f"✓ Added IOC [{record.ioc_type.value}:{record.value}] (ID: {record.ioc_id})")
        storage.close()
        return 0
    else:
        print(f"Error adding IOC: {msg}")
        storage.close()
        return 1


def command_ioc_list(args: argparse.Namespace) -> int:
    """List IOC records."""
    cfg = _get_config_from_args(args)
    storage = SQLiteStorage(cfg.storage.db_path)
    intel_svc = IntelligenceAppService(storage)

    iocs = intel_svc.list_iocs(active_only=not getattr(args, "all", False), limit=getattr(args, "limit", 50))
    if not iocs:
        print("No IOCs found.")
        storage.close()
        return 0

    print(f"{'IOC ID':<14} {'TYPE':<12} {'CONF':<5} {'VALUE':<30} {'STATUS':<10} {'TAGS'}")
    print("-" * 85)
    for i in iocs:
        print(f"{i.ioc_id:<14} {i.ioc_type.value:<12} {i.confidence:<5} {i.value:<30} {i.status.value:<10} {','.join(i.tags)}")
    storage.close()
    return 0


def command_ioc_search(args: argparse.Namespace) -> int:
    """Search IOCs."""
    cfg = _get_config_from_args(args)
    storage = SQLiteStorage(cfg.storage.db_path)
    intel_svc = IntelligenceAppService(storage)

    iocs = intel_svc.search_iocs(args.query)
    if not iocs:
        print(f"No IOCs found matching '{args.query}'.")
        storage.close()
        return 0

    print(f"{'IOC ID':<14} {'TYPE':<12} {'CONF':<5} {'VALUE':<30} {'STATUS':<10}")
    print("-" * 75)
    for i in iocs:
        print(f"{i.ioc_id:<14} {i.ioc_type.value:<12} {i.confidence:<5} {i.value:<30} {i.status.value:<10}")
    storage.close()
    return 0


def command_ioc_delete(args: argparse.Namespace) -> int:
    """Delete an IOC."""
    cfg = _get_config_from_args(args)
    storage = SQLiteStorage(cfg.storage.db_path)
    intel_svc = IntelligenceAppService(storage)

    success, msg = intel_svc.delete_ioc(args.ioc_id)
    if success:
        print(f"✓ IOC '{args.ioc_id}' deleted.")
        storage.close()
        return 0
    else:
        print(f"IOC '{args.ioc_id}' not found.")
        storage.close()
        return 1


def command_timeline(args: argparse.Namespace) -> int:
    """Reconstruct investigation timeline."""
    cfg = _get_config_from_args(args)
    storage = SQLiteStorage(cfg.storage.db_path)
    inc_svc = IncidentAppService(storage)

    ip = getattr(args, "ip", None)
    if not ip:
        print("Please specify an IP with --ip")
        storage.close()
        return 1

    entries = inc_svc.generate_timeline(ip)
    if not entries:
        print("No timeline entries found.")
        storage.close()
        return 0

    print(f"{'TIMESTAMP':<20} {'TYPE':<18} {'SUMMARY'}")
    print("-" * 80)
    for e in entries:
        ts_str = e.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        print(f"{ts_str:<20} {e.entry_type.value:<18} {e.summary}")
    storage.close()
    return 0


def command_attack(args: argparse.Namespace) -> int:
    """View MITRE ATT&CK catalog."""
    cfg = _get_config_from_args(args)
    storage = SQLiteStorage(cfg.storage.db_path)
    intel_svc = IntelligenceAppService(storage)

    if getattr(args, "technique_id", None):
        tech = intel_svc.inspect_technique(args.technique_id)
        if not tech:
            print(f"Technique ID '{args.technique_id}' not found in catalog.")
            storage.close()
            return 1
        print("=" * 64)
        print(f" MITRE ATT&CK Technique: {tech['technique_id']}")
        print("=" * 64)
        print(f" Name        : {tech['name']}")
        print(f" Tactic      : {tech['tactic'].upper()}")
        print(f" Description : {tech['description']}")
        print(f" URL         : {tech['mitre_url']}")
        print("=" * 64)
        storage.close()
        return 0

    catalog = intel_svc.get_attack_catalog()
    print("=" * 64)
    print(" MITRE ATT&CK Technique Catalog")
    print("=" * 64)
    print(f"{'ID':<12} {'TACTIC':<18} {'NAME'}")
    print("-" * 64)
    for t in catalog:
        print(f"{t['technique_id']:<12} {t['tactic']:<18} {t['name']}")
    print("=" * 64)
    storage.close()
    return 0


def command_events(args: argparse.Namespace) -> int:
    """List raw security events."""
    cfg = _get_config_from_args(args)
    storage = SQLiteStorage(cfg.storage.db_path)

    ev_type = EventType(args.type.lower()) if getattr(args, "type", None) else None
    events = storage.get_events(source_ip=getattr(args, "ip", None), event_type=ev_type, limit=getattr(args, "limit", 50))

    if not events:
        print("No events found matching criteria.")
        storage.close()
        return 0

    print(f"{'TIMESTAMP':<20} {'SOURCE IP':<18} {'TYPE':<22} {'USER'}")
    print("-" * 75)
    for e in events:
        ts_str = e.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        user_str = e.username or "-"
        print(f"{ts_str:<20} {e.source_ip:<18} {e.event_type.value:<22} {user_str}")
    storage.close()
    return 0


def command_stats(args: argparse.Namespace) -> int:
    """Display aggregated threat intelligence metrics."""
    cfg = _get_config_from_args(args)
    storage = SQLiteStorage(cfg.storage.db_path)
    stats = storage.get_stats()

    print("=" * 64)
    print(f" B.A.S.T.I.O.N. Host Defense Statistics (v{__version__})")
    print("=" * 64)
    print(f" Total Log Events        : {stats['total_events']}")
    print(f" Behavioral Detections   : {stats['total_detections']}")
    print(f" Tracked Threat Actors   : {stats['total_threat_actors']}")
    print(f" High/Critical Threats   : {stats['active_threats']}")
    print(f" Active Bans             : {stats['active_bans']}")
    print(f" Total Historical Bans   : {stats['total_bans']}")
    print(f" Active IOCs             : {stats['active_iocs']}")
    print(f" Open Incidents          : {stats['open_incidents']}")
    print(f" Audited Response Actions: {stats['total_response_audits']}")

    if stats["top_targeted_usernames"]:
        print("\n Top Targeted Usernames:")
        for u in stats["top_targeted_usernames"]:
            print(f"   • {u['username']:<16} ({u['count']} attempts)")

    if stats["top_threat_actors"]:
        print("\n Top Threat Actors by Score:")
        for a in stats["top_threat_actors"]:
            print(f"   • {a['source_ip']:<18} Score: {a['threat_score']:<3} ({a['severity'].upper()}) - {a['auth_failures']} failures")
    print("=" * 64)
    storage.close()
    return 0


def command_config_show(args: argparse.Namespace) -> int:
    """Show configuration."""
    cfg = _get_config_from_args(args)
    print(f"config_version = {cfg.config_version}")
    print("\n[storage]")
    print(f"db_path = \"{cfg.storage.db_path}\"")
    print("\n[detectors.brute_force]")
    print(f"enabled = {str(cfg.detectors.brute_force.enabled).lower()}")
    print(f"threshold = {cfg.detectors.brute_force.threshold}")
    print(f"window_seconds = {cfg.detectors.brute_force.window_seconds}")
    print("\n[response]")
    print(f"mode = \"{cfg.response.mode}\"")
    print(f"backend = \"{cfg.response.backend}\"")
    print(f"isolation_threshold = {cfg.response.isolation_threshold}")
    print(f"rate_limit_threshold = {cfg.response.rate_limit_threshold}")
    print(f"default_ban_duration_seconds = {cfg.response.default_ban_duration_seconds}")
    print(f"repeat_offender_ban_duration_seconds = {cfg.response.repeat_offender_ban_duration_seconds}")
    print(f"max_ban_duration_seconds = {cfg.response.max_ban_duration_seconds}")
    print(f"allowlist_cidrs = {cfg.response.allowlist_cidrs}")
    print(f"table_name = \"{cfg.response.table_name}\"")
    print("\n[daemon]")
    print(f"health_check_interval_seconds = {cfg.daemon.health_check_interval_seconds}")
    print(f"reconciliation_interval_seconds = {cfg.daemon.reconciliation_interval_seconds}")
    print(f"health_state_path = \"{cfg.daemon.health_state_path}\"")
    return 0


def command_parse(args: argparse.Namespace) -> int:
    """Parse log line."""
    from bastion.infrastructure.telemetry.adapters.ssh import SSHLogAdapter
    adapter = SSHLogAdapter()
    from bastion.core.models.telemetry import RawTelemetry
    raw = RawTelemetry(raw_message=args.line, source="cli_test")
    event = adapter.normalize(raw)
    if not event:
        print("Unrecognized log format.")
        return 1
    print(f"Parsed Event: {event}")
    return 0


def command_test_detection(args: argparse.Namespace) -> int:
    """Run local brute-force simulation."""
    detector = BruteForceDetector(threshold=args.threshold, window_seconds=60)
    print(f"Simulating {args.attempts} failed logins against threshold {args.threshold}...")
    now = datetime.now(timezone.utc)
    for i in range(1, args.attempts + 1):
        ev = SecurityEvent(
            timestamp=now,
            source_ip="198.51.100.23",
            service=ServiceType.SSH,
            event_type=EventType.AUTH_FAILURE,
            username="root",
        )
        res = detector.evaluate(ev)
        status_str = "🚨 DETECTED!" if res.detected else "OK"
        print(f"Attempt {i:>2}/{args.attempts}: count={res.event_count} threshold={res.threshold} -> {status_str}")
    return 0


def command_monitor(args: argparse.Namespace) -> int:
    """Monitor telemetry stream via the Telemetry Gateway."""
    cfg = _get_config_from_args(args)
    storage = SQLiteStorage(cfg.storage.db_path)
    fw = _get_firewall_backend(cfg, getattr(args, "backend", None))

    # Determine response mode
    if getattr(args, "dry_run", False):
        mode = ResponseMode.DRY_RUN
    elif getattr(args, "enforce", False):
        mode = ResponseMode.AUTOMATIC
    elif getattr(args, "mode", None):
        mode = ResponseMode(args.mode.lower())
    else:
        mode = ResponseMode(cfg.response.mode.lower())

    policy_cfg = PolicyConfig(
        isolation_threshold=cfg.response.isolation_threshold,
        rate_limit_threshold=cfg.response.rate_limit_threshold,
        default_ban_duration_seconds=cfg.response.default_ban_duration_seconds,
        repeat_offender_ban_duration_seconds=cfg.response.repeat_offender_ban_duration_seconds,
        max_ban_duration_seconds=cfg.response.max_ban_duration_seconds,
        allowlist_cidrs=cfg.response.allowlist_cidrs,
    )
    policy_engine = PolicyEngine(policy_cfg)
    ban_manager = BanManager(storage=storage, firewall=fw)
    response_engine = ResponseEngine(policy=policy_engine, ban_manager=ban_manager, default_mode=mode)

    det_engine = DetectionEngine()
    risk_engine = RiskEngine()

    pipeline = SentinelPipeline(
        engine=det_engine,
        risk_engine=risk_engine,
        response_engine=response_engine,
        storage=storage,
        alert_min_score=getattr(args, "min_score", 70),
    )

    print(f"Starting B.A.S.T.I.O.N. Guardian IPS Monitor...")
    print(f"Response    : {mode.value.upper()}")
    print(f"Backend     : {fw.name.upper()}")

    collector: CollectorProvider
    if getattr(args, "stdin", False):
        collector = StdinCollector()
    elif getattr(args, "file", None):
        collector = FileCollector(args.file)
    else:
        collector = JournaldCollector()

    for result in pipeline.process(
        collector.stream()
        if getattr(args, "follow", False) or getattr(args, "stdin", False) or getattr(args, "file", None)
        else collector.read(limit=getattr(args, "lines", 100))
    ):
        if result.event:
            ts_str = result.event.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            user_part = f" (user: {result.event.username})" if result.event.username else ""
            score_part = f" | Threat Score: {result.profile.threat_score}/100" if result.profile else ""
            print(f"[{ts_str}] {result.event.event_type.value.upper()} from {result.event.source_ip}{user_part}{score_part}")

        if result.is_alert and result.alert_message:
            print("-" * 64)
            print(result.alert_message)
            print("-" * 64)

    storage.close()
    return 0


def main(argv: list[str] | None = None) -> int:
    """Main CLI entrypoint."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if hasattr(args, "handler"):
        return args.handler(args)
    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())