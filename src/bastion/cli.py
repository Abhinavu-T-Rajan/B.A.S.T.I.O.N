from __future__ import annotations

import argparse
import sys
from collections.abc import Iterator

from bastion import __version__
from bastion.collector.journal import JournalCollector, JournalError
from bastion.collector.ssh import SSHLogParser
from bastion.detection.brute_force import BruteForceDetector, DetectionResult
from bastion.models.events import EventType, SecurityEvent, ServiceType
from bastion.pipeline import SentinelPipeline


def build_parser() -> argparse.ArgumentParser:
    """Build the B.A.S.T.I.O.N. CLI parser."""
    parser = argparse.ArgumentParser(
        prog="bastion",
        description=(
            "Behavioral Attack Surveillance & Threat Isolation Operating Network"
        ),
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"B.A.S.T.I.O.N. v{__version__}",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    # 1. status
    status_parser = subparsers.add_parser(
        "status",
        help="Show B.A.S.T.I.O.N. operational status.",
    )
    status_parser.set_defaults(handler=command_status)

    # 2. test-detection
    test_parser = subparsers.add_parser(
        "test-detection",
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

    # 3. parse
    parse_parser = subparsers.add_parser(
        "parse",
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

    # 4. monitor (sentinel)
    monitor_parser = subparsers.add_parser(
        "monitor",
        aliases=["sentinel"],
        help="Monitor SSH logs in real-time or scan recent journal entries.",
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
        "--threshold",
        type=int,
        default=10,
        help="Brute force threshold (default: 10).",
    )
    monitor_parser.add_argument(
        "--window",
        type=int,
        default=60,
        help="Sliding window in seconds (default: 60).",
    )
    monitor_parser.set_defaults(handler=command_monitor)

    return parser


def command_status(_: argparse.Namespace) -> int:
    """Display current project status and subsystem health."""
    journal_avail = JournalCollector.is_available()

    print(f"B.A.S.T.I.O.N. v{__version__}")
    print("Behavioral Attack Surveillance & Threat Isolation Operating Network")
    print("=" * 60)
    print(f"Status      : DEVELOPMENT (Sentinel)")
    print(f"Mode        : SENTINEL TELEMETRY")
    print(f"Engine      : ONLINE")
    print(f"Action      : DETECTION ONLY")
    print(f"Journald    : {'AVAILABLE' if journal_avail else 'UNAVAILABLE (fallback: stdin/files)'}")
    print(f"Parsers     : OpenSSH (sshd)")
    print(f"Detectors   : Sliding-Window Brute-Force")
    print("=" * 60)

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


def command_monitor(args: argparse.Namespace) -> int:
    """Stream or scan logs through the Sentinel pipeline."""
    parser = SSHLogParser()
    detector = BruteForceDetector(
        threshold=args.threshold,
        window_seconds=args.window,
    )

    def on_alert(event: SecurityEvent, result: DetectionResult) -> None:
        print(
            f"\n🚨 [BRUTE FORCE ALERT] IP={event.source_ip} "
            f"Failures={result.event_count}/{result.threshold} "
            f"User={event.username or 'unknown'} "
            f"Time={event.timestamp.strftime('%H:%M:%S')}",
            file=sys.stderr,
            flush=True,
        )

    pipeline = SentinelPipeline(
        parser=parser,
        detector=detector,
        on_alert=on_alert,
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

    print(f"🛡️  B.A.S.T.I.O.N. Sentinel Monitor v{__version__}")
    print(f"Threshold : {args.threshold} attempts / {args.window}s")
    print(f"Mode      : {'LIVE STREAM (follow)' if args.follow else 'BATCH SCAN'}")
    print("Listening for telemetry... (Ctrl+C to stop)\n" + ("-" * 60))

    processed_lines = 0
    security_events = 0

    try:
        for res in pipeline.process(get_stream()):
            processed_lines += 1
            if res.event is not None:
                security_events += 1
                status = f"[{res.event.event_type.value.upper()}]"
                user = f"user={res.event.username}" if res.event.username else ""
                count_str = f"({res.detection.event_count}/{res.detection.threshold})" if res.detection else ""
                print(
                    f"{res.event.timestamp.strftime('%Y-%m-%d %H:%M:%S')} "
                    f"{status:15} IP={res.event.source_ip:<15} {user:<20} {count_str}"
                )
    except KeyboardInterrupt:
        print("\n[Sentinel Stopped by User]")
    except JournalError as exc:
        print(f"\nCollector Error: {exc}", file=sys.stderr)
        return 1

    print("-" * 60)
    print(f"Summary: Processed {processed_lines} log entries -> {security_events} security events.")
    return 0


def main() -> int:
    """Execute the B.A.S.T.I.O.N. CLI."""
    parser = build_parser()
    args = parser.parse_args()

    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())