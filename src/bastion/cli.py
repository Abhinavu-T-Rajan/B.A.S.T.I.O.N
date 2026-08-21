from __future__ import annotations

import argparse
import sys
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path

from bastion import __version__
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
from bastion.models.actors import (
    ActorState,
    RecommendedAction,
    Severity,
    ThreatActorProfile,
)
from bastion.models.events import EventType, SecurityEvent, ServiceType
from bastion.pipeline import SentinelPipeline
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
from bastion.risk.scorer import RiskEngine, RiskScoringConfig
from bastion.storage.sqlite import SQLiteStorage


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
        version=f"B.A.S.T.I.O.N. v{__version__} (Guardian)",
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
        help="Minimum threat score to display (default: 0).",
    )
    threats_parser.add_argument(
        "--limit",
        "-n",
        type=int,
        default=25,
        help="Maximum number of actors to show (default: 25).",
    )
    threats_parser.set_defaults(handler=command_threats)

    # 3. inspect
    inspect_parser = subparsers.add_parser(
        "inspect",
        parents=[common_parent],
        help="Inspect full threat profile, forensic history, and ban status for an IP.",
    )
    inspect_parser.add_argument(
        "source_ip",
        help="The IP address to inspect.",
    )
    inspect_parser.set_defaults(handler=command_inspect)

    # 4. bans
    bans_parser = subparsers.add_parser(
        "bans",
        parents=[common_parent],
        help="List active or historical ban records.",
    )
    bans_parser.add_argument(
        "--all",
        "-a",
        action="store_true",
        help="Show all bans (including expired/unbanned/dry-run).",
    )
    bans_parser.add_argument(
        "--limit",
        "-n",
        type=int,
        default=50,
        help="Maximum number of records to display (default: 50).",
    )
    bans_parser.set_defaults(handler=command_bans)

    # 5. ban (manual)
    ban_parser = subparsers.add_parser(
        "ban",
        parents=[common_parent],
        help="Manually isolate/block an IP address.",
    )
    ban_parser.add_argument(
        "source_ip",
        help="IP address to isolate.",
    )
    ban_parser.add_argument(
        "--duration",
        "-d",
        type=int,
        default=900,
        help="Ban duration in seconds (default: 900s = 15m).",
    )
    ban_parser.add_argument(
        "--permanent",
        "-p",
        action="store_true",
        help="Apply a permanent ban without expiration.",
    )
    ban_parser.add_argument(
        "--reason",
        "-r",
        type=str,
        default="Manual operator ban",
        help="Reason for manual isolation.",
    )
    ban_parser.set_defaults(handler=command_manual_ban)

    # 6. unban (manual)
    unban_parser = subparsers.add_parser(
        "unban",
        parents=[common_parent],
        help="Release an active ban on an IP address.",
    )
    unban_parser.add_argument(
        "source_ip",
        help="IP address to unban.",
    )
    unban_parser.set_defaults(handler=command_manual_unban)

    # 7. firewall
    fw_parser = subparsers.add_parser(
        "firewall",
        parents=[common_parent],
        help="Firewall subsystem management.",
    )
    fw_sub = fw_parser.add_subparsers(dest="firewall_action", required=True)
    fw_status = fw_sub.add_parser(
        "status",
        parents=[common_parent],
        help="Show firewall table status and active blocked set.",
    )
    fw_status.set_defaults(handler=command_firewall_status)
    fw_flush = fw_sub.add_parser(
        "flush",
        parents=[common_parent],
        help="Flush all bastion firewall rules and clear blacklists.",
    )
    fw_flush.set_defaults(handler=command_firewall_flush)

    # 8. events
    events_parser = subparsers.add_parser(
        "events",
        parents=[common_parent],
        help="Query persisted security telemetry events.",
    )
    events_parser.add_argument(
        "--ip",
        type=str,
        help="Filter events by source IP address.",
    )
    events_parser.add_argument(
        "--limit",
        "-n",
        type=int,
        default=50,
        help="Maximum events to return (default: 50).",
    )
    events_parser.set_defaults(handler=command_events)

    # 9. stats
    stats_parser = subparsers.add_parser(
        "stats",
        parents=[common_parent],
        help="Display aggregated system intelligence metrics.",
    )
    stats_parser.set_defaults(handler=command_stats)

    # 10. config
    config_parser = subparsers.add_parser(
        "config",
        parents=[common_parent],
        help="Configuration inspection.",
    )
    config_sub = config_parser.add_subparsers(dest="config_action", required=True)
    config_show = config_sub.add_parser(
        "show",
        parents=[common_parent],
        help="Show active configuration.",
    )
    config_show.set_defaults(handler=command_config_show)

    # 11. parse
    parse_parser = subparsers.add_parser(
        "parse",
        parents=[common_parent],
        help="Inspect and parse raw log lines into SecurityEvents.",
    )
    parse_parser.add_argument(
        "log_text",
        nargs="?",
        help="A raw log string to parse.",
    )
    parse_parser.add_argument(
        "--file",
        "-f",
        type=str,
        help="Path to a log file to parse.",
    )
    parse_parser.set_defaults(handler=command_parse)

    # 12. test-detection
    test_parser = subparsers.add_parser(
        "test-detection",
        parents=[common_parent],
        help="Run a local brute-force detector simulation.",
    )
    test_parser.add_argument(
        "--attempts",
        type=int,
        default=12,
        help="Number of simulated failed attempts (default: 12).",
    )
    test_parser.add_argument(
        "--threshold",
        type=int,
        default=10,
        help="Number of failures required for detection (default: 10).",
    )
    test_parser.add_argument(
        "--window",
        type=int,
        default=60,
        help="Detection window in seconds (default: 60).",
    )
    test_parser.set_defaults(handler=command_test_detection)

    # 13. monitor (sentinel/guardian)
    monitor_parser = subparsers.add_parser(
        "monitor",
        aliases=["sentinel", "watch", "guardian"],
        parents=[common_parent],
        help="Monitor SSH logs in real-time with threat scoring & active response.",
    )
    monitor_parser.add_argument(
        "--units",
        "-u",
        nargs="+",
        default=["ssh.service", "sshd.service"],
        help="Systemd unit(s) to monitor (default: ssh.service sshd.service).",
    )
    monitor_parser.add_argument(
        "--identifier",
        type=str,
        default="sshd",
        help="Syslog identifier to filter (default: sshd).",
    )
    monitor_parser.add_argument(
        "--follow",
        "-F",
        action="store_true",
        help="Continuously stream live journal entries.",
    )
    monitor_parser.add_argument(
        "--lines",
        "-n",
        type=int,
        default=50,
        help="Number of recent lines to inspect (default: 50).",
    )
    monitor_parser.add_argument(
        "--since",
        type=str,
        help="Show entries since timestamp/relative time (e.g. '10m ago').",
    )
    monitor_parser.add_argument(
        "--file",
        type=str,
        help="Read from a file instead of systemd-journald.",
    )
    monitor_parser.add_argument(
        "--stdin",
        action="store_true",
        help="Read log lines directly from standard input.",
    )
    monitor_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Force dry-run defense simulation (no firewall rules modified).",
    )
    monitor_parser.add_argument(
        "--enforce",
        action="store_true",
        help="Enable active firewall enforcement (automatic isolation).",
    )
    monitor_parser.add_argument(
        "--mode",
        choices=["dry_run", "manual", "automatic", "disabled"],
        help="Explicit response mode override.",
    )
    monitor_parser.add_argument(
        "--no-db",
        action="store_true",
        help="Disable database persistence during monitoring.",
    )
    monitor_parser.set_defaults(handler=command_monitor)

    return parser


def _get_storage(args: argparse.Namespace, cfg: BastionConfig) -> SQLiteStorage:
    """Resolve and initialize SQLite storage based on flags and config."""
    db_path = getattr(args, "db", None) or cfg.storage.db_path
    return SQLiteStorage(db_path=db_path)


def _get_firewall_backend(args: argparse.Namespace, cfg: BastionConfig) -> FirewallBackend:
    """Instantiate appropriate firewall backend."""
    backend_name = getattr(args, "backend", None) or cfg.response.backend
    if backend_name == "mock":
        return MockFirewallBackend()

    nft = NFTablesBackend(table_name=cfg.response.table_name)
    if not nft.is_available():
        # If nft is requested but unavailable, fall back to mock with warning
        return MockFirewallBackend()
    return nft


def command_status(args: argparse.Namespace) -> int:
    """Display current project status, storage statistics, and active detectors."""
    cfg = load_config(args.config)
    journal_avail = JournalCollector.is_available()
    fw = _get_firewall_backend(args, cfg)

    print(f"B.A.S.T.I.O.N. v{__version__} (Guardian)")
    print("Behavioral Attack Surveillance & Threat Isolation Operating Network")
    print("=" * 65)
    print("Status      : DEVELOPMENT (Guardian)")
    print("Mode        : INTRUSION PREVENTION & THREAT ISOLATION")
    print("Engine      : ONLINE")
    print(f"Response    : {cfg.response.mode.upper()} (Threshold: {cfg.response.isolation_threshold}/100, Duration: {cfg.response.default_ban_duration_seconds}s)")
    print(f"Firewall    : {fw.name.upper()} ({'AVAILABLE' if fw.is_available() else 'UNAVAILABLE'})")
    print(f"Journald    : {'AVAILABLE' if journal_avail else 'UNAVAILABLE'}")
    print(f"Config File : {cfg.loaded_from or 'Default in-memory'}")
    print(f"Storage DB  : {args.db or cfg.storage.db_path}")

    # Query DB stats if accessible
    try:
        storage = _get_storage(args, cfg)
        stats = storage.get_stats()
        print(f"Database    : ONLINE ({stats['total_events']} events, {stats['total_actors']} actors, {stats.get('active_bans', 0)} active bans)")
        storage.close()
    except Exception as exc:
        print(f"Database    : ERROR ({exc})")

    print(f"Detectors   : Brute-Force, Password Spray, Username Enumeration, Burst Velocity")
    print(f"Protected   : {', '.join(cfg.response.allowlist_cidrs)}")
    print("=" * 65)

    return 0


def command_bans(args: argparse.Namespace) -> int:
    """List active or historical ban records."""
    cfg = load_config(args.config)
    storage = _get_storage(args, cfg)

    status_filter = None if args.all else BanStatus.ACTIVE
    bans = storage.list_bans(status=status_filter, limit=args.limit)
    storage.close()

    status_desc = "All Bans" if args.all else "Active Bans"
    print(f"🛡️  B.A.S.T.I.O.N. Tracked Bans ({status_desc})")
    print("=" * 95)

    if not bans:
        print("No ban records found.")
        print("=" * 95)
        return 0

    header = f"{'BAN ID':<14} {'SOURCE IP':<18} {'SCORE':<7} {'STATUS':<12} {'ACTION':<20} {'EXPIRES (UTC)'}"
    print(header)
    print("-" * 95)

    for b in bans:
        exp_str = b.expires_at.strftime('%Y-%m-%d %H:%M:%S') if b.expires_at else "Permanent"
        action_str = b.action.value.replace("_", " ").upper()
        print(
            f"{b.ban_id:<14} "
            f"{b.source_ip:<18} "
            f"{b.threat_score:>3}/100 "
            f"[{b.status.value.upper():<10}] "
            f"{action_str:<20} "
            f"{exp_str}"
        )

    print("=" * 95)
    print(f"Total: {len(bans)} ban record(s) displayed.")
    return 0


def command_manual_ban(args: argparse.Namespace) -> int:
    """Manually apply a ban to an IP address."""
    cfg = load_config(args.config)
    storage = _get_storage(args, cfg)
    fw = _get_firewall_backend(args, cfg)
    ban_mgr = BanManager(storage=storage, firewall=fw)

    duration = None if args.permanent else args.duration
    record = ban_mgr.create_ban(
        source_ip=args.source_ip,
        reason=args.reason,
        threat_score=100,
        duration_seconds=duration,
        action=ResponseAction.PERMANENT_BAN if args.permanent else ResponseAction.TEMPORARY_ISOLATION,
        status=BanStatus.ACTIVE,
        metadata={"manual": True},
    )
    storage.close()

    dur_desc = "Permanent" if args.permanent else f"{args.duration}s"
    print(f"🛡️  IP {args.source_ip} successfully isolated [{dur_desc}]. Ban ID: {record.ban_id}")
    return 0


def command_manual_unban(args: argparse.Namespace) -> int:
    """Manually release a ban on an IP address."""
    cfg = load_config(args.config)
    storage = _get_storage(args, cfg)
    fw = _get_firewall_backend(args, cfg)
    ban_mgr = BanManager(storage=storage, firewall=fw)

    success = ban_mgr.unban(args.source_ip)
    storage.close()

    if success:
        print(f"✅ IP {args.source_ip} successfully released from isolation.")
    else:
        print(f"⚠️  No active ban found for IP {args.source_ip}, but firewall unblock command was issued.")
    return 0


def command_firewall_status(args: argparse.Namespace) -> int:
    """Display firewall table and blocked set contents."""
    cfg = load_config(args.config)
    fw = _get_firewall_backend(args, cfg)

    print("🛡️  B.A.S.T.I.O.N. Firewall Status")
    print("=" * 60)
    print(f"Backend Name : {fw.name.upper()}")
    print(f"Available    : {'YES' if fw.is_available() else 'NO'}")
    if isinstance(fw, NFTablesBackend):
        print(f"Table Name   : inet {fw.table_name}")

    blocked = fw.list_blocked_ips()
    print(f"Blocked IPs  : {len(blocked)}")
    print("-" * 60)
    if blocked:
        for ip in blocked:
            print(f"  • {ip}")
    else:
        print("  • None currently in firewall blacklist set")
    print("=" * 60)
    return 0


def command_firewall_flush(args: argparse.Namespace) -> int:
    """Flush all firewall blacklist rules."""
    cfg = load_config(args.config)
    fw = _get_firewall_backend(args, cfg)
    fw.flush()
    print("✅ B.A.S.T.I.O.N. firewall blacklist rules successfully flushed.")
    return 0


def command_threats(args: argparse.Namespace) -> int:
    """List tracked threat actors and risk scores."""
    cfg = load_config(args.config)
    storage = _get_storage(args, cfg)

    actors = storage.list_threat_actors(min_score=args.min_score, limit=args.limit)
    storage.close()

    print(f"🛡️  B.A.S.T.I.O.N. Tracked Threat Actors (min score: {args.min_score})")
    print("=" * 90)

    if not actors:
        print("No threat actors recorded in database.")
        print("=" * 90)
        return 0

    header = f"{'SOURCE IP':<18} {'SCORE':<7} {'SEVERITY':<10} {'STATE':<14} {'FAILURES':<10} {'ACTION':<20}"
    print(header)
    print("-" * 90)

    for a in actors:
        action_str = a.recommended_action.value.replace("_", " ").upper()
        print(
            f"{a.source_ip:<18} "
            f"{a.threat_score:>3}/100 "
            f"[{a.severity.value.upper():<8}] "
            f"{a.state.value:<14} "
            f"{a.auth_failures:<10} "
            f"{action_str:<20}"
        )

    print("=" * 90)
    print(f"Total: {len(actors)} threat actor(s) displayed.")
    return 0


def command_inspect(args: argparse.Namespace) -> int:
    """Display forensic threat actor profile, ban status, and contributing factors."""
    cfg = load_config(args.config)
    storage = _get_storage(args, cfg)

    profile = storage.get_threat_actor(args.source_ip)
    active_ban = storage.get_ban_by_ip(args.source_ip)
    events = storage.get_events(source_ip=args.source_ip, limit=10)
    storage.close()

    if not profile:
        print(f"No profile found for IP address: {args.source_ip}", file=sys.stderr)
        return 1

    print("=" * 65)
    print(f"THREAT PROFILE: {profile.source_ip}")
    print("=" * 65)
    print(f"First Seen        : {profile.first_seen.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"Last Seen         : {profile.last_seen.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"Total Events      : {profile.total_events}")
    print(f"Auth Failures     : {profile.auth_failures}")
    print(f"Auth Successes    : {profile.auth_successes}")
    print(f"Services Targeted : {', '.join(sorted(profile.services_targeted)) or 'None'}")
    print(f"Users Targeted    : {', '.join(sorted(profile.usernames_targeted)) or 'None'}")
    print("-" * 65)
    print(f"Threat Score      : {profile.threat_score} / 100")
    print(f"Severity          : {profile.severity.value.upper()}")
    print(f"State             : {profile.state.value.replace('_', ' ').upper()}")
    print(f"Recommended Action: {profile.recommended_action.value.replace('_', ' ').upper()}")

    if active_ban:
        exp_str = active_ban.expires_at.strftime('%Y-%m-%d %H:%M:%S UTC') if active_ban.expires_at else "Permanent"
        print(f"Active Ban ID     : {active_ban.ban_id} (Status: {active_ban.status.value.upper()}, Expires: {exp_str})")
    else:
        print("Active Ban Status : NOT CURRENTLY BANNED")

    print("-" * 65)
    print("Contributing Score Factors:")
    if profile.factors:
        for f in profile.factors:
            print(f"  • {f.description}")
    else:
        print("  • No explicit factors recorded")

    if events:
        print("-" * 65)
        print("Recent Events Timeline (up to 10):")
        for ev in events:
            u_str = f" user={ev.username}" if ev.username else ""
            print(f"  [{ev.timestamp.strftime('%H:%M:%S')}] {ev.event_type.value.upper():<14} {ev.service.value.upper()}{u_str}")

    print("=" * 65)
    return 0


def command_events(args: argparse.Namespace) -> int:
    """Query stored security events from database."""
    cfg = load_config(args.config)
    storage = _get_storage(args, cfg)

    events = storage.get_events(source_ip=args.ip, limit=args.limit)
    storage.close()

    print(f"📋 B.A.S.T.I.O.N. Telemetry Events (Limit: {args.limit})")
    print("=" * 80)

    if not events:
        print("No telemetry events found matching query.")
        print("=" * 80)
        return 0

    print(f"{'TIMESTAMP':<20} {'TYPE':<16} {'IP':<16} {'SERVICE':<8} {'USER'}")
    print("-" * 80)

    for ev in events:
        u_str = ev.username or "-"
        print(
            f"{ev.timestamp.strftime('%Y-%m-%d %H:%M:%S'):<20} "
            f"{ev.event_type.value:<16} "
            f"{ev.source_ip:<16} "
            f"{ev.service.value:<8} "
            f"{u_str}"
        )

    print("=" * 80)
    print(f"Returned {len(events)} event(s).")
    return 0


def command_stats(args: argparse.Namespace) -> int:
    """Display overall system threat intelligence statistics."""
    cfg = load_config(args.config)
    storage = _get_storage(args, cfg)
    stats = storage.get_stats()
    storage.close()

    print("📊 B.A.S.T.I.O.N. Intelligence Statistics")
    print("=" * 50)
    print(f"Total Telemetry Events    : {stats['total_events']}")
    print(f"Total Behavioral Alerts   : {stats['total_detections']}")
    print(f"Tracked Threat Actors     : {stats['total_actors']}")
    print(f"Active High/Critical Risks: {stats['active_threats']}")
    print(f"Active Firewall Bans      : {stats.get('active_bans', 0)}")
    print("-" * 50)

    print("Top Targeted Usernames:")
    if stats["top_targeted_usernames"]:
        for u in stats["top_targeted_usernames"]:
            print(f"  • {u['username']:<15} : {u['count']} attempts")
    else:
        print("  • None recorded")

    print("\nTop Threat Actors:")
    if stats["top_threats"]:
        for t in stats["top_threats"]:
            print(f"  • {t['source_ip']:<15} : Score {t['threat_score']:>3}/100 [{t['severity'].upper()}] ({t['failures']} failures)")
    else:
        print("  • None recorded")

    print("=" * 50)
    return 0


def command_config_show(args: argparse.Namespace) -> int:
    """Display currently loaded configuration."""
    cfg = load_config(args.config)
    print(f"# B.A.S.T.I.O.N. Configuration (Source: {cfg.loaded_from or 'defaults'})")
    print("-" * 50)
    print(f"[storage]")
    print(f"db_path = \"{cfg.storage.db_path}\"")
    print()
    print("[detectors.brute_force]")
    print(f"enabled = {str(cfg.detectors.brute_force.enabled).lower()}")
    print(f"threshold = {cfg.detectors.brute_force.threshold}")
    print(f"window_seconds = {cfg.detectors.brute_force.window_seconds}")
    print()
    print("[detectors.password_spray]")
    print(f"enabled = {str(cfg.detectors.password_spray.enabled).lower()}")
    print(f"min_usernames = {cfg.detectors.password_spray.min_usernames}")
    print(f"max_attempts_per_user = {cfg.detectors.password_spray.max_attempts_per_user}")
    print(f"window_seconds = {cfg.detectors.password_spray.window_seconds}")
    print()
    print("[detectors.enumeration]")
    print(f"enabled = {str(cfg.detectors.enumeration.enabled).lower()}")
    print(f"threshold = {cfg.detectors.enumeration.threshold}")
    print(f"window_seconds = {cfg.detectors.enumeration.window_seconds}")
    print()
    print("[detectors.burst]")
    print(f"enabled = {str(cfg.detectors.burst.enabled).lower()}")
    print(f"threshold = {cfg.detectors.burst.threshold}")
    print(f"window_seconds = {cfg.detectors.burst.window_seconds}")
    print()
    print("[risk]")
    print(f"medium_threshold = {cfg.risk.medium_threshold}")
    print(f"high_threshold = {cfg.risk.high_threshold}")
    print(f"critical_threshold = {cfg.risk.critical_threshold}")
    print(f"trusted_ips = {cfg.risk.trusted_ips}")
    print()
    print("[response]")
    print(f"mode = \"{cfg.response.mode}\"")
    print(f"backend = \"{cfg.response.backend}\"")
    print(f"isolation_threshold = {cfg.response.isolation_threshold}")
    print(f"default_ban_duration_seconds = {cfg.response.default_ban_duration_seconds}")
    print(f"allowlist_cidrs = {cfg.response.allowlist_cidrs}")
    print("-" * 50)
    return 0


def command_parse(args: argparse.Namespace) -> int:
    """Parse log text or a log file into structured SecurityEvents."""
    parser = SSHLogParser()

    lines: list[str] = []
    if args.log_text:
        lines.append(args.log_text)
    elif args.file:
        try:
            with open(args.file, encoding="utf-8") as f:
                lines = [line.strip() for line in f if line.strip()]
        except OSError as exc:
            print(f"Error opening file '{args.file}': {exc}", file=sys.stderr)
            return 1
    else:
        print("Error: Specify a log string to parse or use --file <path>", file=sys.stderr)
        return 1

    parsed_count = 0
    for line in lines:
        event = parser.parse(line)
        print("-" * 60)
        print(f"RAW: {line}")
        if event is None:
            print("STATUS: [IGNORED / UNMATCHED]")
        else:
            parsed_count += 1
            print("STATUS: [PARSED]")
            print(f"  Timestamp : {event.timestamp.isoformat()}")
            print(f"  Source IP : {event.source_ip}")
            print(f"  Service   : {event.service.value}")
            print(f"  Type      : {event.event_type.value}")
            print(f"  User      : {event.username or '<None>'}")
            if event.metadata:
                print(f"  Metadata  : {event.metadata}")

    print("-" * 60)
    print(f"Parsed {parsed_count} / {len(lines)} line(s).")
    return 0


def command_test_detection(args: argparse.Namespace) -> int:
    """Run a deterministic local detector simulation."""
    if args.attempts <= 0:
        raise SystemExit("--attempts must be greater than zero")

    detector = BruteForceDetector(
        threshold=args.threshold,
        window_seconds=args.window,
    )
    source_ip = "192.0.2.10"

    print("B.A.S.T.I.O.N. Detection Test")
    print("=" * 40)

    result: DetectionResult | None = None
    for i in range(1, args.attempts + 1):
        event = SecurityEvent.now(
            source_ip=source_ip,
            service=ServiceType.SSH,
            event_type=EventType.AUTH_FAILURE,
            username="root",
        )
        result = detector.evaluate(event)
        flag = "[ALERT DETECTED]" if result.detected else "[OK]"
        print(f"  Attempt {i:02d}/{args.attempts:02d} -> Count: {result.event_count:02d}/{result.threshold} {flag}")

    assert result is not None
    print("=" * 40)
    print(f"Source IP : {result.source_ip}")
    print(f"Attempts  : {result.event_count}")
    print(f"Threshold : {result.threshold}")
    print(f"Window    : {result.window_seconds}s")
    print(f"Detected  : {result.detected}")

    if result.detected:
        print(f"Reason    : {result.reason}")

    return 0


def command_monitor(args: argparse.Namespace) -> int:
    """Stream or scan logs through the pipeline with live risk scoring, persistence & defense response."""
    cfg = load_config(args.config)
    storage = None if args.no_db else _get_storage(args, cfg)
    firewall = _get_firewall_backend(args, cfg)

    # Resolve effective response mode
    if args.dry_run:
        response_mode = ResponseMode.DRY_RUN
    elif args.enforce:
        response_mode = ResponseMode.AUTOMATIC
    elif args.mode:
        response_mode = ResponseMode(args.mode)
    else:
        response_mode = ResponseMode(cfg.response.mode)

    # Initialize policy and ban manager
    policy_config = PolicyConfig(
        isolation_threshold=cfg.response.isolation_threshold,
        rate_limit_threshold=cfg.response.rate_limit_threshold,
        default_ban_duration_seconds=cfg.response.default_ban_duration_seconds,
        repeat_offender_ban_duration_seconds=cfg.response.repeat_offender_ban_duration_seconds,
        max_ban_duration_seconds=cfg.response.max_ban_duration_seconds,
        allowlist_cidrs=cfg.response.allowlist_cidrs,
    )
    policy_engine = PolicyEngine(config=policy_config)

    ban_manager = BanManager(
        storage=storage or SQLiteStorage(":memory:"),
        firewall=firewall,
    )

    # Recover state on startup if running in live enforcement
    if response_mode == ResponseMode.AUTOMATIC:
        restored = ban_manager.sync_on_startup()
        if restored > 0:
            print(f"[*] Restored {restored} active ban rule(s) in {firewall.name} firewall.")

    response_engine = ResponseEngine(
        policy=policy_engine,
        ban_manager=ban_manager,
        default_mode=response_mode,
    )

    # Initialize detectors from configuration
    detection_engine = DetectionEngine(
        brute_force=BruteForceDetector(
            threshold=cfg.detectors.brute_force.threshold,
            window_seconds=cfg.detectors.brute_force.window_seconds,
        ),
        password_spray=PasswordSprayDetector(
            min_usernames=cfg.detectors.password_spray.min_usernames,
            max_attempts_per_user=cfg.detectors.password_spray.max_attempts_per_user,
            window_seconds=cfg.detectors.password_spray.window_seconds,
        ),
        enumeration=UsernameEnumerationDetector(
            threshold=cfg.detectors.enumeration.threshold,
            window_seconds=cfg.detectors.enumeration.window_seconds,
        ),
        burst=BurstDetector(
            threshold=cfg.detectors.burst.threshold,
            window_seconds=cfg.detectors.burst.window_seconds,
        ),
    )

    # Initialize risk engine from configuration
    risk_config = RiskScoringConfig(
        failed_auth_weight=cfg.risk.failed_auth_weight,
        invalid_user_weight=cfg.risk.invalid_user_weight,
        burst_velocity_weight=cfg.risk.burst_velocity_weight,
        brute_force_weight=cfg.risk.brute_force_weight,
        password_spray_weight=cfg.risk.password_spray_weight,
        enumeration_weight=cfg.risk.enumeration_weight,
        max_attempts_weight=cfg.risk.max_attempts_weight,
        repeat_offender_weight=cfg.risk.repeat_offender_weight,
        success_auth_weight=cfg.risk.success_auth_weight,
        trusted_ip_discount=cfg.risk.trusted_ip_discount,
        medium_threshold=cfg.risk.medium_threshold,
        high_threshold=cfg.risk.high_threshold,
        critical_threshold=cfg.risk.critical_threshold,
        trusted_ips=set(cfg.risk.trusted_ips),
    )
    risk_engine = RiskEngine(config=risk_config)

    def on_alert(
        event: SecurityEvent,
        profile: ThreatActorProfile,
        detections: list[DetectionResult],
        decision: ResponseDecision | None = None,
    ) -> None:
        print("\n" + "=" * 65, file=sys.stderr)
        print(f"🚨 THREAT DETECTED", file=sys.stderr)
        print(f"Source      : {event.source_ip}", file=sys.stderr)
        print(f"Score       : {profile.threat_score} / 100 [{profile.severity.value.upper()}]", file=sys.stderr)
        print(f"State       : {profile.state.value.replace('_', ' ').upper()}", file=sys.stderr)
        print("Contributing Factors:", file=sys.stderr)
        for f in profile.factors:
            print(f"  • {f.description}", file=sys.stderr)
        if profile.usernames_targeted:
            print(f"Users       : {', '.join(sorted(profile.usernames_targeted))}", file=sys.stderr)

        if decision and decision.action in {ResponseAction.TEMPORARY_ISOLATION, ResponseAction.PERMANENT_BAN}:
            dur_str = f"{decision.duration_seconds // 60}m" if decision.duration_seconds else "Permanent"
            if decision.mode == ResponseMode.DRY_RUN:
                action_text = f"WOULD BLOCK [DRY-RUN] ({dur_str})"
            elif decision.mode == ResponseMode.AUTOMATIC:
                action_text = f"ISOLATED [ENFORCED via {firewall.name}] ({dur_str})"
            elif decision.mode == ResponseMode.MANUAL_APPROVAL:
                action_text = f"PENDING OPERATOR APPROVAL ({dur_str})"
            else:
                action_text = "DISABLED"
            print(f"Defense     : {action_text}", file=sys.stderr)
        else:
            print(f"Action      : {profile.recommended_action.value.replace('_', ' ').upper()} (ADVISORY)", file=sys.stderr)
        print("=" * 65 + "\n", file=sys.stderr, flush=True)

    pipeline = SentinelPipeline(
        parser=SSHLogParser(),
        engine=detection_engine,
        risk_engine=risk_engine,
        response_engine=response_engine,
        storage=storage,
        on_alert=on_alert,
        alert_min_score=cfg.risk.high_threshold,
    )

    def get_stream() -> Iterator[str]:
        if args.stdin:
            for line in sys.stdin:
                cleaned = line.strip()
                if cleaned:
                    yield cleaned
        elif args.file:
            with open(args.file, encoding="utf-8") as f:
                for line in f:
                    cleaned = line.strip()
                    if cleaned:
                        yield cleaned
        else:
            collector = JournalCollector(
                units=args.units,
                identifier=args.identifier,
            )
            if not collector.is_available():
                print(
                    "Error: journalctl is not available. Provide log input via --file or --stdin.",
                    file=sys.stderr,
                )
                sys.exit(1)

            if args.follow:
                yield from collector.follow(lines=args.lines, since=args.since)
            else:
                yield from collector.read(lines=args.lines, since=args.since)

    print(f"🛡️  B.A.S.T.I.O.N. Guardian IPS Monitor v{__version__}")
    print(f"Response    : {response_mode.value.upper()} (Firewall Backend: {firewall.name})")
    print(f"Persistence : {'ENABLED (' + (args.db or cfg.storage.db_path) + ')' if storage else 'DISABLED'}")
    print(f"Mode        : {'LIVE STREAM (follow)' if args.follow else 'BATCH SCAN'}")
    print("Listening for telemetry... (Ctrl+C to stop)\n" + ("-" * 75))

    processed_lines = 0
    security_events = 0

    try:
        for res in pipeline.process(get_stream()):
            processed_lines += 1
            if res.event is not None:
                security_events += 1
                status = f"[{res.event.event_type.value.upper()}]"
                user = f"user={res.event.username}" if res.event.username else ""
                score_str = f"Score={res.profile.threat_score:>2}/100 [{res.profile.severity.value[:4].upper()}]" if res.profile else ""
                defense_str = ""
                if res.decision and res.decision.action in {ResponseAction.TEMPORARY_ISOLATION, ResponseAction.PERMANENT_BAN}:
                    tag = "WOULD-BLOCK" if res.decision.mode == ResponseMode.DRY_RUN else "BLOCKED"
                    defense_str = f"-> [{tag}]"
                print(
                    f"{res.event.timestamp.strftime('%Y-%m-%d %H:%M:%S')} "
                    f"{status:15} IP={res.event.source_ip:<15} {user:<18} {score_str} {defense_str}"
                )
    except KeyboardInterrupt:
        print("\n[Guardian Stopped by User]")
    except JournalError as exc:
        print(f"\nCollector Error: {exc}", file=sys.stderr)
        return 1
    finally:
        if storage:
            storage.close()

    print("-" * 75)
    print(f"Summary: Processed {processed_lines} log entries -> {security_events} security events.")
    return 0


def main() -> int:
    """Execute the B.A.S.T.I.O.N. CLI."""
    parser = build_parser()
    args = parser.parse_args()

    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())