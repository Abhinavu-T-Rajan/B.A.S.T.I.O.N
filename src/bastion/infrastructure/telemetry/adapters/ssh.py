from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from bastion.core.contracts.collector import TelemetryAdapter
from bastion.core.models.telemetry import RawTelemetry
from bastion.models.events import EventType, SecurityEvent, ServiceType

# Regex for stripping syslog/journald header prefixes
SYSLOG_PREFIX_RE = re.compile(
    r"^(?:(?P<iso_ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2}))|"
    r"(?P<syslog_ts>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}))?\s*"
    r"(?:[\w.-]+\s+)?(?:sshd|sshd-session|sshd-auth)(?:\[(?P<pid>\d+)\])?:\s*",
    re.IGNORECASE,
)

# Common regex patterns for OpenSSH telemetry
FAILED_AUTH_RE = re.compile(
    r"^Failed\s+(?P<method>password|publickey|keyboard-interactive(?:/pam)?|none)\s+"
    r"for\s+(?:(?P<invalid>invalid\s+user)\s+)?(?P<username>\S+)\s+"
    r"from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)\s+ssh2",
    re.IGNORECASE,
)

INVALID_USER_RE = re.compile(
    r"^Invalid\s+user\s+(?P<username>\S+)\s+from\s+(?P<ip>\S+)(?:\s+port\s+(?P<port>\d+))?",
    re.IGNORECASE,
)

ACCEPTED_AUTH_RE = re.compile(
    r"^Accepted\s+(?P<method>password|publickey|keyboard-interactive(?:/pam)?|gssapi-with-mic)\s+"
    r"for\s+(?P<username>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)\s+ssh2"
    r"(?::\s+(?P<auth_info>.*))?",
    re.IGNORECASE,
)

MAX_ATTEMPTS_RE = re.compile(
    r"^maximum\s+authentication\s+attempts\s+exceeded\s+for\s+"
    r"(?:(?P<invalid>invalid\s+user)\s+)?(?P<username>\S+)\s+"
    r"from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)\s+ssh2"
    r"(?:\s+\[(?P<stage>\w+)\])?",
    re.IGNORECASE,
)

CONNECTION_CLOSED_RE = re.compile(
    r"^(?:Connection\s+(?:closed|reset)|Disconnected)\s+(?:by|from)\s+"
    r"(?:authenticating\s+user\s+(?P<username>\S+)\s+)?(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
    r"(?:\s+\[(?P<stage>\w+)\])?",
    re.IGNORECASE,
)

PAM_AUTH_FAILURE_RE = re.compile(
    r"^pam_unix\((?:sshd|sshd-session|sshd-auth):auth\):\s+authentication\s+failure;\s+"
    r".*?\brhost=(?P<ip>\S+)(?:\s+user=(?P<username>\S+))?",
    re.IGNORECASE,
)


def _clean_ip(ip_str: str) -> str:
    """Strip port brackets or prefixes from IP addresses."""
    cleaned = ip_str.strip("[]")
    if cleaned.startswith("::ffff:"):
        return cleaned[7:]
    return cleaned


def _parse_timestamp(iso_ts: str | None, syslog_ts: str | None) -> datetime:
    """Parse extracted timestamp or fallback to current UTC time."""
    if iso_ts:
        try:
            dt = datetime.fromisoformat(iso_ts.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            pass

    if syslog_ts:
        try:
            now = datetime.now(timezone.utc)
            parsed = datetime.strptime(syslog_ts, "%b %d %H:%M:%S")
            return parsed.replace(year=now.year, tzinfo=timezone.utc)
        except ValueError:
            pass

    return datetime.now(timezone.utc)


class SSHLogAdapter(TelemetryAdapter):
    """OpenSSH telemetry adapter normalizing RawTelemetry records into SecurityEvents."""

    name = "openssh"

    def can_handle(self, telemetry: RawTelemetry) -> bool:
        """Determine if this adapter can process the raw telemetry record."""
        if telemetry.unit in {"ssh.service", "sshd.service"}:
            return True
        if telemetry.identifier in {"sshd", "sshd-session", "sshd-auth"}:
            return True
        if "ssh" in telemetry.raw_message.lower() or "pam_unix" in telemetry.raw_message:
            return True
        if SYSLOG_PREFIX_RE.match(telemetry.raw_message):
            return True
        msg = telemetry.raw_message.strip()
        return bool(
            FAILED_AUTH_RE.match(msg)
            or INVALID_USER_RE.match(msg)
            or ACCEPTED_AUTH_RE.match(msg)
            or MAX_ATTEMPTS_RE.match(msg)
            or CONNECTION_CLOSED_RE.match(msg)
            or PAM_AUTH_FAILURE_RE.match(msg)
        )

    def normalize(self, telemetry: RawTelemetry) -> SecurityEvent | None:
        """Parse raw telemetry record into a standardized domain SecurityEvent."""
        raw_line = telemetry.raw_message.strip()
        if not raw_line:
            return None

        # Check for syslog / systemd prefix
        prefix_match = SYSLOG_PREFIX_RE.match(raw_line)
        timestamp: datetime = telemetry.timestamp
        pid: int | None = telemetry.pid

        if prefix_match:
            iso_ts = prefix_match.group("iso_ts")
            syslog_ts = prefix_match.group("syslog_ts")
            timestamp = _parse_timestamp(iso_ts, syslog_ts)
            pid_str = prefix_match.group("pid")
            if pid_str:
                pid = int(pid_str)
            message = raw_line[prefix_match.end() :].strip()
        else:
            message = raw_line

        # 1. Check for Failed Authentication
        failed_match = FAILED_AUTH_RE.match(message)
        if failed_match:
            ip = _clean_ip(failed_match.group("ip"))
            username = failed_match.group("username")
            method = failed_match.group("method")
            port = int(failed_match.group("port"))
            is_invalid = bool(failed_match.group("invalid"))

            metadata: dict[str, Any] = {
                "method": method,
                "port": port,
                "invalid_user": is_invalid,
                "raw": raw_line,
                "source": telemetry.source,
                "transport": telemetry.transport,
            }
            if pid:
                metadata["pid"] = pid

            return SecurityEvent(
                timestamp=timestamp,
                source_ip=ip,
                service=ServiceType.SSH,
                event_type=EventType.AUTH_FAILURE,
                username=username,
                metadata=metadata,
            )

        # 2. Check for Standalone Invalid User Notification
        invalid_match = INVALID_USER_RE.match(message)
        if invalid_match:
            ip = _clean_ip(invalid_match.group("ip"))
            username = invalid_match.group("username")
            port_str = invalid_match.group("port")
            port = int(port_str) if port_str else None

            metadata = {
                "invalid_user": True,
                "port": port,
                "raw": raw_line,
                "source": telemetry.source,
                "transport": telemetry.transport,
            }
            if pid:
                metadata["pid"] = pid

            return SecurityEvent(
                timestamp=timestamp,
                source_ip=ip,
                service=ServiceType.SSH,
                event_type=EventType.INVALID_USER,
                username=username,
                metadata=metadata,
            )

        # 3. Check for Accepted Authentication
        accepted_match = ACCEPTED_AUTH_RE.match(message)
        if accepted_match:
            ip = _clean_ip(accepted_match.group("ip"))
            username = accepted_match.group("username")
            method = accepted_match.group("method")
            port = int(accepted_match.group("port"))
            auth_info = accepted_match.group("auth_info")

            metadata = {
                "method": method,
                "port": port,
                "auth_info": auth_info,
                "raw": raw_line,
                "source": telemetry.source,
                "transport": telemetry.transport,
            }
            if pid:
                metadata["pid"] = pid

            return SecurityEvent(
                timestamp=timestamp,
                source_ip=ip,
                service=ServiceType.SSH,
                event_type=EventType.AUTH_SUCCESS,
                username=username,
                metadata=metadata,
            )

        # 4. Check for Maximum Attempts Exceeded
        max_match = MAX_ATTEMPTS_RE.match(message)
        if max_match:
            ip = _clean_ip(max_match.group("ip"))
            username = max_match.group("username")
            port = int(max_match.group("port"))
            stage = max_match.group("stage")
            is_invalid = bool(max_match.group("invalid"))

            metadata = {
                "max_attempts_exceeded": True,
                "port": port,
                "stage": stage,
                "invalid_user": is_invalid,
                "raw": raw_line,
                "source": telemetry.source,
                "transport": telemetry.transport,
            }
            if pid:
                metadata["pid"] = pid

            return SecurityEvent(
                timestamp=timestamp,
                source_ip=ip,
                service=ServiceType.SSH,
                event_type=EventType.AUTH_FAILURE,
                username=username,
                metadata=metadata,
            )

        # 5. Check for Connection Closed / Reset
        closed_match = CONNECTION_CLOSED_RE.match(message)
        if closed_match:
            ip = _clean_ip(closed_match.group("ip"))
            username = closed_match.group("username")
            port = int(closed_match.group("port"))
            stage = closed_match.group("stage")

            metadata = {
                "connection_closed": True,
                "port": port,
                "stage": stage,
                "raw": raw_line,
                "source": telemetry.source,
                "transport": telemetry.transport,
            }
            if pid:
                metadata["pid"] = pid

            return SecurityEvent(
                timestamp=timestamp,
                source_ip=ip,
                service=ServiceType.SSH,
                event_type=EventType.CONNECTION,
                username=username,
                metadata=metadata,
            )

        # 6. Check for PAM Authentication Failure
        pam_match = PAM_AUTH_FAILURE_RE.match(message)
        if pam_match:
            ip = _clean_ip(pam_match.group("ip"))
            username = pam_match.group("username")

            metadata = {
                "pam_auth_failure": True,
                "raw": raw_line,
                "source": telemetry.source,
                "transport": telemetry.transport,
            }
            if pid:
                metadata["pid"] = pid

            return SecurityEvent(
                timestamp=timestamp,
                source_ip=ip,
                service=ServiceType.SSH,
                event_type=EventType.AUTH_FAILURE,
                username=username,
                metadata=metadata,
            )

        return None
