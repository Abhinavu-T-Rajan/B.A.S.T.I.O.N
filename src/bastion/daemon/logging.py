from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any

# Standard auditable lifecycle event tags
SERVICE_START = "SERVICE_START"
SERVICE_STOP = "SERVICE_STOP"
CONFIG_LOAD = "CONFIG_LOAD"
CONFIG_ERROR = "CONFIG_ERROR"
COLLECTOR_FAILURE = "COLLECTOR_FAILURE"
DATABASE_FAILURE = "DATABASE_FAILURE"
FIREWALL_FAILURE = "FIREWALL_FAILURE"
BAN_RESTORED = "BAN_RESTORED"
BAN_EXPIRED = "BAN_EXPIRED"
RESPONSE_EXECUTED = "RESPONSE_EXECUTED"
RESPONSE_FAILED = "RESPONSE_FAILED"
DEGRADED_MODE = "DEGRADED_MODE"
RECOVERY = "RECOVERY"

SENSITIVE_PATTERNS = [
    re.compile(r"(password\s*[:=]\s*)([^\s,]+)", re.IGNORECASE),
    re.compile(r"(secret\s*[:=]\s*)([^\s,]+)", re.IGNORECASE),
    re.compile(r"(token\s*[:=]\s*)([^\s,]+)", re.IGNORECASE),
    re.compile(r"(api[_-]?key\s*[:=]\s*)([^\s,]+)", re.IGNORECASE),
]


def sanitize_log_message(msg: str) -> str:
    """Strip passwords, API keys, and sensitive tokens from log messages."""
    sanitized = msg
    for pat in SENSITIVE_PATTERNS:
        sanitized = pat.sub(r"\1[REDACTED]", sanitized)
    return sanitized


class StructuredLogFormatter(logging.Formatter):
    """Structured text or JSON log formatter for daemon lifecycle events."""

    def __init__(self, log_format: str = "text") -> None:
        super().__init__()
        self.log_format = log_format.lower()

    def format(self, record: logging.LogRecord) -> str:
        timestamp = datetime.now(timezone.utc).isoformat()
        audit_event = getattr(record, "audit_event", None)
        details = getattr(record, "audit_details", None)
        sanitized_msg = sanitize_log_message(record.getMessage())

        if self.log_format == "json":
            payload: dict[str, Any] = {
                "timestamp": timestamp,
                "level": record.levelname,
                "logger": record.name,
                "message": sanitized_msg,
            }
            if audit_event:
                payload["audit_event"] = audit_event
            if details:
                payload["details"] = details
            return json.dumps(payload)

        # Default text format
        prefix = f"[{timestamp}] [{record.levelname:<7}]"
        if audit_event:
            prefix += f" [{audit_event}]"
        if details:
            return f"{prefix} {sanitized_msg} | details={json.dumps(details)}"
        return f"{prefix} {sanitized_msg}"


def setup_daemon_logging(
    log_level: str = "INFO",
    log_format: str = "text",
    handler: logging.Handler | None = None,
) -> logging.Logger:
    """Configure and return the root B.A.S.T.I.O.N. daemon logger."""
    logger = logging.getLogger("bastion.daemon")
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    logger.setLevel(numeric_level)

    # Avoid duplicate handlers
    if not logger.handlers:
        h = handler or logging.StreamHandler()
        h.setFormatter(StructuredLogFormatter(log_format))
        logger.addHandler(h)
        logger.propagate = False

    return logger


def log_audit(
    logger: logging.Logger,
    event_type: str,
    message: str,
    details: dict[str, Any] | None = None,
    level: int = logging.INFO,
) -> None:
    """Emit an auditable lifecycle or security event with structured metadata."""
    extra = {
        "audit_event": event_type,
        "audit_details": details or {},
    }
    logger.log(level, message, extra=extra)
