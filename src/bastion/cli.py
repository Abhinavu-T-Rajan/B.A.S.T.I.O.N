from __future__ import annotations

import argparse
import sys
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from bastion import __version__
from bastion.attack.registry import AttackRegistry
from bastion.collector.journal import JournalCollector, JournalError
from bastion.collector.ssh import SSHLogParser
from bastion.config import BastionConfig, load_config
from bastion.detection.brute_force import BruteForceDetector, DetectionResult
from bastion.detection.burst import BurstDetector
from bastion.detection.engine import DetectionEngine
from bastion.detection.enumeration import UsernameEnumerationDetector
from bastion.detection.password_spray import PasswordSprayDetector
from bastion.firewall.base import FirewallBackend
from bastion.firewall.mock import MockFirewallBackend
from bastion.firewall.nftables import NFTablesBackend
from bastion.incidents.manager import IncidentManager
from bastion.incidents.models import Incident, IncidentStatus
from bastion.intelligence.manager import IOCManager
from bastion.intelligence.models import IOCRecord, IOCStatus, IOCType, Provenance
from bastion.models.actors import (
    ActorState,
    RecommendedAction,
    Severity,
    ThreatActorProfile,
)
from bastion.models.events import EventType, SecurityEvent, ServiceType
from bastion.pipeline import SentinelPipeline
from bastion.response.audit import ResponseAuditRecord
from bastion.response.ban_manager import BanManager
from bastion.response.engine import ResponseEngine
from bastion.response.experimental import ExperimentalResponseCoordinator
from bastion.response.models import (
    BanRecord,
    BanStatus,
    ResponseAction,
    ResponseDecision,
    ResponseMode,
)
from bastion.response.policy import PolicyConfig, PolicyEngine
from bastion.risk.scorer import RiskEngine, RiskScoringConfig
from bastion.storage.sqlite import SQLiteStorage
from bastion.timeline.generator import TimelineGenerator


def build_parser() -> argparse.ArgumentParser:
    """Build the B.A.S.T.I.O.N. CLI parser."""
    common_parent = argparse.ArgumentParser(add_help=False)
    common_parent.add_argument(
        "--config",
        "-c",
        type=str,
        help="Path to custom bastion.toml configuration file.",
    )
    common_parent.add_argument(
        "--db",
        type=str,
        help="Override SQLite database path.",
    )
    common_parent.add_argument(
        "--backend",
        choices=["nftables", "mock"],
        help="Firewall backend override.",
    )

    parser = argparse.ArgumentParser(
        prog="bastion",
        parents=[common_parent],
        description=(
            "Behavioral Attack Surveillance & Threat Isolation Operating Network"
        ),
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"B.A.S.T.I.O.N. v{__version__} (Oracle)",
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

    # 2. threats / actors
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

    # 3. inspect
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

    # 4. bans
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

    # 5. ban
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

    # 6. unban
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

    # 7. firewall
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

    # 8. incident (Oracle v0.2.0-alpha)
    incident_parser = subparsers.add_parser(
        "incident",
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

    # 9. ioc (Oracle v0.2.0-alpha)
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

    # 10. timeline (Oracle v0.2.0-alpha)
    timeline_parser = subparsers.add_parser(
        "timeline",
        parents=[common_parent],
        help="Reconstruct chronological investigation timeline for an IP or incident.",
    )
    timeline_parser.add_argument("--ip", type=str, help="Source IP to generate timeline for.")
    timeline_parser.add_argument("--incident", type=str, help="Incident ID to generate timeline for.")
    timeline_parser.add_argument("--limit", type=int, default=50, help="Max entries to show.")
    timeline_parser.set_defaults(handler=command_timeline)

    # 11. attack / mitre (Oracle v0.2.0-alpha)
    attack_parser = subparsers.add_parser(
        "attack",
        aliases=["mitre"],
        parents=[common_parent],
        help="View MITRE ATT&CK technique catalog and detector mappings.",
    )
    attack_parser.add_argument("technique_id", nargs="?", help="Optional technique ID to inspect (e.g. T1110.001).")
    attack_parser.set_defaults(handler=command_attack)

    # 12. events
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

    # 13. stats
    stats_parser = subparsers.add_parser(
        "stats",
        parents=[common_parent],
        help="Display aggregated threat intelligence metrics.",
    )
    stats_parser.set_defaults(handler=command_stats)

    # 14. config
    config_parser = subparsers.add_parser(
        "config",
        parents=[common_parent],
        help="Configuration inspection tools.",
    )
    config_sub = config_parser.add_subparsers(dest="config_action", required=True)
    cfg_show = config_sub.add_parser("show", parents=[common_parent], help="Show active configuration.")
    cfg_show.set_defaults(handler=command_config_show)

    # 15. parse
    parse_parser = subparsers.add_parser(
        "parse",
        parents=[common_parent],
        help="Parse and inspect a raw log line.",
    )
    parse_parser.add_argument("line", type=str, help="Log line to parse.")
    parse_parser.set_defaults(handler=command_parse)

    # 16. test-detection
    test_det_parser = subparsers.add_parser(
        "test-detection",
        parents=[common_parent],
        help="Run local deterministic brute-force simulation.",
    )
    test_det_parser.add_argument("--attempts", type=int, default=12, help="Number of simulated attempts.")
    test_det_parser.add_argument("--threshold", type=int, default=10, help="Detection threshold.")
    test_det_parser.set_defaults(handler=command_test_detection)

    # 17. monitor
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

    return parser


def _get_firewall_backend(cfg: BastionConfig, backend_override: str | None = None) -> FirewallBackend:
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


# =====================================================================
# CLI Command Handlers
# =====================================================================

def command_status(args: argparse.Namespace) -> int:
    """Show operational status and subsystem health."""
    cfg = load_config(args.config)
    db_path = args.db or cfg.storage.db_path
    storage = SQLiteStorage(db_path)
    fw = _get_firewall_backend(cfg, args.backend)
    stats = storage.get_stats()

    print("=" * 64)
    print(f" B.A.S.T.I.O.N. Host Defense Engine v{__version__} (Oracle)")
    print(f" Status      : DEVELOPMENT (Oracle v{__version__})")
    print(f" Mode        : INTRUSION PREVENTION & THREAT ISOLATION")
    print("=" * 64)
    print(f" Database         : {db_path}")
    print(f" Response Mode    : {cfg.response.mode.upper()}")
    print(f" Firewall Backend : {fw.name} ({'Available' if fw.is_available() else 'Unavailable'})")
    print(f" Total Events     : {stats['total_events']}")
    print(f" Detections       : {stats['total_detections']}")
    print(f" Threat Actors    : {stats['total_threat_actors']} ({stats['active_threats']} active high/critical)")
    print(f" Active Bans      : {stats['active_bans']}")
    print(f" Active IOCs      : {stats['active_iocs']}")
    print(f" Open Incidents   : {stats['open_incidents']}")
    print("=" * 64)
    return 0


def command_threats(args: argparse.Namespace) -> int:
    """List tracked threat actors and risk scores."""
    cfg = load_config(args.config)
    db_path = args.db or cfg.storage.db_path
    storage = SQLiteStorage(db_path)

    sev_enum = Severity(args.severity.lower()) if args.severity else None
    actors = storage.list_threat_actors(min_score=args.min_score, severity=sev_enum, limit=args.limit)

    if not actors:
        print("No threat actors matching criteria.")
        return 0

    print(f"{'SOURCE IP':<18} {'SCORE':<7} {'SEVERITY':<10} {'STATE':<14} {'FAILURES':<10} {'ACTION':<20} {'LAST SEEN'}")
    print("-" * 105)
    for a in actors:
        last_str = a.last_seen.strftime("%Y-%m-%d %H:%M:%S")
        print(f"{a.source_ip:<18} {a.threat_score:<7} {a.severity.value.upper():<10} {a.state.value:<14} {a.auth_failures:<10} {a.recommended_action.value:<20} {last_str}")
    return 0


def command_inspect(args: argparse.Namespace) -> int:
    """Inspect forensic details and score factors for a specific IP."""
    cfg = load_config(args.config)
    db_path = args.db or cfg.storage.db_path
    storage = SQLiteStorage(db_path)

    actor = storage.get_threat_actor(args.source_ip)
    if not actor:
        print(f"No forensic record found for IP: {args.source_ip}")
        return 1

    ban = storage.get_ban_by_ip(args.source_ip)
    matched_iocs = storage.lookup_active_iocs(IOCType.IP, args.source_ip)

    print("=" * 64)
    print(f" FORENSIC PROFILE: {actor.source_ip}")
    print("=" * 64)
    print(f" Actor ID         : {actor.actor_id}")
    print(f" Threat Score     : {actor.threat_score} / 100")
    print(f" Severity         : {actor.severity.value.upper()}")
    print(f" State            : {actor.state.value.upper()}")
    print(f" Recommended      : {actor.recommended_action.value.upper()}")
    print(f" First Seen       : {actor.first_seen.isoformat()}")
    print(f" Last Seen        : {actor.last_seen.isoformat()}")
    print(f" Total Events     : {actor.total_events} ({actor.auth_failures} failures, {actor.auth_successes} successes)")
    print(f" Targeted Users   : {', '.join(sorted(actor.usernames_targeted)) if actor.usernames_targeted else 'None'}")

    if matched_iocs:
        print("\n Matched Threat Intelligence IOCs:")
        for ioc in matched_iocs:
            print(f"   • [{ioc.ioc_id}] {ioc.ioc_type.value}:{ioc.value} ({ioc.confidence}% confidence, {ioc.source})")

    if ban:
        exp_str = ban.expires_at.isoformat() if ban.expires_at else "Permanent"
        print(f"\n Active Ban ID    : {ban.ban_id} ({ban.action.value.upper()}, Status: {ban.status.value.upper()}, Expires: {exp_str})")

    print("\n Contributing Score Factors:")
    for f in actor.factors:
        print(f"   • {f.description} (Delta: {f.score_delta})")
    print("=" * 64)
    return 0


def command_bans(args: argparse.Namespace) -> int:
    """List bans."""
    cfg = load_config(args.config)
    storage = SQLiteStorage(args.db or cfg.storage.db_path)
    status_filter = None if args.all else BanStatus.ACTIVE
    bans = storage.list_bans(status=status_filter, limit=args.limit)

    if not bans:
        print("No ban records found.")
        return 0

    print(f"{'BAN ID':<16} {'IP':<18} {'ACTION':<20} {'STATUS':<12} {'SCORE':<7} {'EXPIRES AT'}")
    print("-" * 90)
    for b in bans:
        exp_str = b.expires_at.strftime("%Y-%m-%d %H:%M:%S") if b.expires_at else "PERMANENT"
        print(f"{b.ban_id:<16} {b.source_ip:<18} {b.action.value:<20} {b.status.value:<12} {b.threat_score:<7} {exp_str}")
    return 0


def command_ban(args: argparse.Namespace) -> int:
    """Manually isolate an IP."""
    cfg = load_config(args.config)
    storage = SQLiteStorage(args.db or cfg.storage.db_path)
    fw = _get_firewall_backend(cfg, args.backend)
    bm = BanManager(storage=storage, firewall=fw)

    duration = None if args.permanent else args.duration
    ban = bm.create_ban(
        source_ip=args.ip,
        reason=args.reason,
        threat_score=100 if args.permanent else 85,
        duration_seconds=duration,
        action=ResponseAction.PERMANENT_BAN if args.permanent else ResponseAction.TEMPORARY_ISOLATION,
    )
    print(f"IP {ban.source_ip} successfully isolated (Ban ID: {ban.ban_id}, Status: {ban.status.value.upper()})")
    return 0


def command_unban(args: argparse.Namespace) -> int:
    """Release an active ban."""
    cfg = load_config(args.config)
    storage = SQLiteStorage(args.db or cfg.storage.db_path)
    fw = _get_firewall_backend(cfg, args.backend)
    bm = BanManager(storage=storage, firewall=fw)

    success = bm.unban(args.ip)
    if success:
        print(f"IP {args.ip} successfully released from isolation.")
        return 0
    print(f"No active ban found for IP: {args.ip}")
    return 1


def command_firewall_status(args: argparse.Namespace) -> int:
    """Show firewall status."""
    cfg = load_config(args.config)
    fw = _get_firewall_backend(cfg, args.backend)
    print("=" * 64)
    print(" B.A.S.T.I.O.N. Firewall Status")
    print("=" * 64)
    print(f"Backend Name : {fw.name.upper()}")
    print(f"Available    : {fw.is_available()}")
    ips = fw.list_blocked_ips()
    print(f"Blocked IPs ({len(ips)}):")
    for ip in ips:
        print(f"  • {ip}")
    print("=" * 64)
    return 0


def command_firewall_flush(args: argparse.Namespace) -> int:
    """Flush firewall blacklist."""
    cfg = load_config(args.config)
    fw = _get_firewall_backend(cfg, args.backend)
    fw.flush()
    print(f"B.A.S.T.I.O.N. firewall blacklist rules successfully flushed for backend: {fw.name.upper()}")
    return 0


def command_incident_list(args: argparse.Namespace) -> int:
    """List security incidents."""
    cfg = load_config(args.config)
    storage = SQLiteStorage(args.db or cfg.storage.db_path)
    mgr = IncidentManager(storage)
    incidents = mgr.list_incidents(status=args.status, limit=args.limit)

    if not incidents:
        print("No incidents found.")
        return 0

    print(f"{'INCIDENT ID':<24} {'STATUS':<14} {'SEVERITY':<10} {'RISK':<6} {'TITLE':<32} {'LAST SEEN'}")
    print("-" * 105)
    for inc in incidents:
        last_str = inc.last_seen.strftime("%Y-%m-%d %H:%M:%S")
        print(f"{inc.incident_id:<24} {inc.status.value.upper():<14} {inc.severity.value.upper():<10} {inc.risk_score:<6} {inc.title:<32} {last_str}")
    return 0


def command_incident_inspect(args: argparse.Namespace) -> int:
    """Inspect an incident."""
    cfg = load_config(args.config)
    storage = SQLiteStorage(args.db or cfg.storage.db_path)
    mgr = IncidentManager(storage)
    inc = mgr.get_incident(args.incident_id)

    if not inc:
        print(f"Incident '{args.incident_id}' not found.")
        return 1

    print("=" * 64)
    print(f" INCIDENT: {inc.incident_id} [{inc.status.value.upper()}]")
    print("=" * 64)
    print(f" Title            : {inc.title}")
    print(f" Severity         : {inc.severity.value.upper()}")
    print(f" Risk Score       : {inc.risk_score} / 100")
    print(f" First Seen       : {inc.first_seen.isoformat()}")
    print(f" Last Seen        : {inc.last_seen.isoformat()}")
    print(f" Related Actors   : {', '.join(inc.related_actors) if inc.related_actors else 'None'}")
    print(f" Related Events   : {len(inc.related_events)} events linked")
    print(f" Related IOCs     : {', '.join(inc.related_iocs) if inc.related_iocs else 'None'}")
    print(f" ATT&CK Techniques: {', '.join(inc.attack_techniques) if inc.attack_techniques else 'None'}")
    print(f" Summary          : {inc.summary}")
    print("=" * 64)
    return 0


def command_incident_update(args: argparse.Namespace) -> int:
    """Update incident status."""
    cfg = load_config(args.config)
    storage = SQLiteStorage(args.db or cfg.storage.db_path)
    mgr = IncidentManager(storage)
    inc = mgr.update_status(args.incident_id, status=args.status, notes=args.notes)
    if not inc:
        print(f"Incident '{args.incident_id}' not found.")
        return 1
    print(f"Updated incident {inc.incident_id} status to {inc.status.value.upper()}")
    return 0


def command_incident_create(args: argparse.Namespace) -> int:
    """Create a manual incident."""
    cfg = load_config(args.config)
    storage = SQLiteStorage(args.db or cfg.storage.db_path)
    mgr = IncidentManager(storage)
    actors = [a.strip() for a in args.actors.split(",") if a.strip()] if args.actors else []

    inc = mgr.create_incident(
        title=args.title,
        severity=Severity(args.severity.lower()),
        risk_score=args.risk,
        actors=actors,
        summary=args.summary,
    )
    print(f"Created incident {inc.incident_id} ({inc.title})")
    return 0


def command_ioc_add(args: argparse.Namespace) -> int:
    """Add an IOC record."""
    cfg = load_config(args.config)
    storage = SQLiteStorage(args.db or cfg.storage.db_path)
    mgr = IOCManager(storage)
    tags = [t.strip() for t in args.tags.split(",") if t.strip()] if args.tags else []

    try:
        ioc = mgr.add_ioc(
            ioc_type=args.type,
            value=args.value,
            confidence=args.confidence,
            source=args.source,
            tags=tags,
            notes=args.notes,
        )
        print(f"Added IOC [{ioc.ioc_id}] {ioc.ioc_type.value}:{ioc.value} (Confidence: {ioc.confidence}%)")
        return 0
    except ValueError as e:
        print(f"Error adding IOC: {e}")
        return 1


def command_ioc_list(args: argparse.Namespace) -> int:
    """List IOC records."""
    cfg = load_config(args.config)
    storage = SQLiteStorage(args.db or cfg.storage.db_path)
    mgr = IOCManager(storage)
    iocs = mgr.list_iocs(ioc_type=args.type, status=args.status, limit=args.limit)

    if not iocs:
        print("No IOC records found.")
        return 0

    print(f"{'IOC ID':<18} {'TYPE':<12} {'CONF':<6} {'STATUS':<8} {'VALUE':<32} {'TAGS'}")
    print("-" * 90)
    for ioc in iocs:
        tags_str = ", ".join(ioc.tags) if ioc.tags else ""
        print(f"{ioc.ioc_id:<18} {ioc.ioc_type.value:<12} {ioc.confidence:<6} {ioc.status.value:<8} {ioc.value:<32} {tags_str}")
    return 0


def command_ioc_search(args: argparse.Namespace) -> int:
    """Search IOC records."""
    cfg = load_config(args.config)
    storage = SQLiteStorage(args.db or cfg.storage.db_path)
    mgr = IOCManager(storage)
    iocs = mgr.search(args.query, limit=args.limit)

    if not iocs:
        print(f"No IOC records matching '{args.query}'.")
        return 0

    print(f"Found {len(iocs)} matching IOCs:")
    for ioc in iocs:
        print(f"  • [{ioc.ioc_id}] {ioc.ioc_type.value}:{ioc.value} ({ioc.confidence}%) tags={ioc.tags}")
    return 0


def command_ioc_delete(args: argparse.Namespace) -> int:
    """Delete an IOC record."""
    cfg = load_config(args.config)
    storage = SQLiteStorage(args.db or cfg.storage.db_path)
    mgr = IOCManager(storage)
    if mgr.delete_ioc(args.ioc_id):
        print(f"Deleted IOC {args.ioc_id}")
        return 0
    print(f"IOC {args.ioc_id} not found.")
    return 1


def command_timeline(args: argparse.Namespace) -> int:
    """Reconstruct investigation timeline."""
    cfg = load_config(args.config)
    storage = SQLiteStorage(args.db or cfg.storage.db_path)
    gen = TimelineGenerator(storage)

    if args.incident:
        entries = gen.generate_for_incident(args.incident, limit=args.limit)
    elif args.ip:
        entries = gen.generate_for_ip(args.ip, limit=args.limit)
    else:
        print("Please specify either --ip <IP> or --incident <ID>")
        return 1

    if not entries:
        print("No timeline entries found.")
        return 0

    print(f"{'TIMESTAMP':<22} {'TYPE':<16} {'SOURCE':<18} {'SUMMARY'}")
    print("-" * 90)
    for e in entries:
        ts_str = e.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        print(f"{ts_str:<22} {e.entry_type.value.upper():<16} {e.source:<18} {e.summary}")
    return 0


def command_attack(args: argparse.Namespace) -> int:
    """View MITRE ATT&CK techniques."""
    if args.technique_id:
        tech = AttackRegistry.get_technique(args.technique_id)
        if not tech:
            print(f"Technique '{args.technique_id}' not found in registry.")
            return 1
        print("=" * 64)
        print(f" MITRE ATT&CK: {tech.technique_id} - {tech.name}")
        print("=" * 64)
        print(f" Tactic      : {tech.tactic.value}")
        print(f" URL         : {tech.url}")
        print(f" Description : {tech.description}")
        print("=" * 64)
        return 0

    print("=" * 64)
    print(" MITRE ATT&CK Technique Catalog")
    print("=" * 64)
    print(f"{'TECHNIQUE ID':<16} {'TACTIC':<22} {'NAME'}")
    print("-" * 75)
    for t in AttackRegistry.list_techniques():
        print(f"{t.technique_id:<16} {t.tactic.value:<22} {t.name}")
    print("=" * 64)
    return 0


def command_events(args: argparse.Namespace) -> int:
    """List raw events."""
    cfg = load_config(args.config)
    storage = SQLiteStorage(args.db or cfg.storage.db_path)
    ev_type = EventType(args.type) if args.type else None
    events = storage.get_events(source_ip=args.ip, event_type=ev_type, limit=args.limit)

    if not events:
        print("No events found.")
        return 0

    print(f"{'TIMESTAMP':<22} {'SOURCE IP':<18} {'SERVICE':<8} {'TYPE':<22} {'USER'}")
    print("-" * 80)
    for ev in events:
        ts_str = ev.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        print(f"{ts_str:<22} {ev.source_ip:<18} {ev.service.value:<8} {ev.event_type.value:<22} {ev.username or ''}")
    return 0


def command_stats(args: argparse.Namespace) -> int:
    """Display system statistics."""
    cfg = load_config(args.config)
    storage = SQLiteStorage(args.db or cfg.storage.db_path)
    stats = storage.get_stats()

    print("=" * 64)
    print(" B.A.S.T.I.O.N. System Intelligence Summary")
    print("=" * 64)
    print(f" Total Events Recorded   : {stats['total_events']}")
    print(f" Triggered Detections    : {stats['total_detections']}")
    print(f" Tracked Threat Actors   : {stats['total_threat_actors']} ({stats['active_threats']} active high/critical)")
    print(f" Active Bans             : {stats['active_bans']}")
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
    return 0


def command_config_show(args: argparse.Namespace) -> int:
    """Show configuration."""
    cfg = load_config(args.config)
    print("[storage]")
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
    return 0


def command_parse(args: argparse.Namespace) -> int:
    """Parse log line."""
    parser = SSHLogParser()
    event = parser.parse(args.line)
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
        res = detector.process(ev)
        status_str = "🚨 DETECTED!" if res.detected else "OK"
        print(f"Attempt {i:>2}/{args.attempts}: count={res.event_count} threshold={res.threshold} -> {status_str}")
    return 0


def command_monitor(args: argparse.Namespace) -> int:
    """Monitor telemetry stream."""
    cfg = load_config(args.config)
    db_path = args.db or cfg.storage.db_path
    storage = SQLiteStorage(db_path)
    fw = _get_firewall_backend(cfg, args.backend)

    # Determine response mode
    if args.dry_run:
        mode = ResponseMode.DRY_RUN
    elif args.enforce:
        mode = ResponseMode.AUTOMATIC
    elif args.mode:
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
        alert_min_score=args.min_score,
    )

    print(f"Starting B.A.S.T.I.O.N. Guardian IPS Monitor...")
    print(f"Response    : {mode.value.upper()}")
    print(f"Backend     : {fw.name.upper()}")

    def line_stream() -> Iterator[str]:
        if args.stdin:
            for line in sys.stdin:
                yield line.strip()
        elif args.file:
            with open(args.file, "r") as f:
                for line in f:
                    yield line.strip()
        else:
            collector = JournalCollector()
            if args.follow:
                for line in collector.follow():
                    yield line
            else:
                for line in collector.read_lines(lines=args.lines):
                    yield line

    for result in pipeline.process(line_stream()):
        if result.is_alert and result.alert_message:
            print("-" * 64)
            print(result.alert_message)
            print("-" * 64)

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