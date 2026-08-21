from __future__ import annotations
import argparse
from bastion.detection.brute_force import BruteForceDetector
from bastion.models.events import EventType, SecurityEvent, ServiceType


def build_parser() -> argparse.ArgumentParser:
    # Build the B.A.S.T.I.O.N. CLI parser.
    parser = argparse.ArgumentParser(
        prog="bastion",
        description=(
            "Behavioral Attack Surveillance & Threat Isolation "
            "Operating Network"
        ),
    )

    parser.add_argument(
        "--version",
        action="version",
        version="B.A.S.T.I.O.N. v0.1.0",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    status_parser = subparsers.add_parser(
        "status",
        help="Show B.A.S.T.I.O.N. status.",
    )
    status_parser.set_defaults(handler=command_status)

    test_parser = subparsers.add_parser(
        "test-detection",
        help="Run a local brute-force detector simulation.",
    )
    test_parser.add_argument(
        "--attempts",
        type=int,
        default=12,
        help="Number of simulated failed attempts.",
    )
    test_parser.add_argument(
        "--threshold",
        type=int,
        default=10,
        help="Number of failures required for detection.",
    )
    test_parser.add_argument(
        "--window",
        type=int,
        default=60,
        help="Detection window in seconds.",
    )
    test_parser.set_defaults(handler=command_test_detection)

    return parser


def command_status(_: argparse.Namespace) -> int:
    # Display current project status.
    print("B.A.S.T.I.O.N. v0.1.0")
    print("Behavioral Attack Surveillance & Threat Isolation Operating Network")
    print()
    print("Status : DEVELOPMENT")
    print("Mode   : FOUNDATION")
    print("Engine : ONLINE")
    print("Action : DETECTION ONLY")

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
    print("=" * 32)

    result = None

    for _ in range(args.attempts):
        event = SecurityEvent.now(
            source_ip=source_ip,
            service=ServiceType.SSH,
            event_type=EventType.AUTH_FAILURE,
        )

        result = detector.evaluate(event)

    assert result is not None

    print(f"Source IP : {result.source_ip}")
    print(f"Attempts  : {result.event_count}")
    print(f"Threshold : {result.threshold}")
    print(f"Window    : {result.window_seconds}s")
    print(f"Detected  : {result.detected}")

    if result.detected:
        print(f"Reason    : {result.reason}")

    return 0


def main() -> int:
    """Execute the B.A.S.T.I.O.N. CLI."""
    parser = build_parser()
    args = parser.parse_args()

    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())