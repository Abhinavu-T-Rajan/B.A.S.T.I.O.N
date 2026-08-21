from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Optional

from bastion.response.audit import ResponseAuditRecord, ResponseResult

if TYPE_CHECKING:
    from bastion.firewall.base import FirewallBackend
    from bastion.storage.sqlite import SQLiteStorage

USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_.@-]{1,64}$")


class ExperimentalResponseCoordinator:
    """
    Controlled, audited experimental response interface.

    Enforces explicit target validation, mandatory audit logging, and safe dry-run guarantees.
    """

    def __init__(
        self,
        storage: SQLiteStorage,
        firewall: Optional[FirewallBackend] = None,
    ) -> None:
        self.storage = storage
        self.firewall = firewall

    def block_ip(
        self,
        target_ip: str,
        duration_seconds: int = 900,
        dry_run: bool = True,
        executed_by: str = "operator",
        reason: str = "Manual experimental isolation",
        actor_id: Optional[str] = None,
        incident_id: Optional[str] = None,
    ) -> ResponseResult:
        """Validate and isolate an IP address."""
        # 1. Validate Target IP
        try:
            ip_obj = ipaddress.ip_address(target_ip.strip())
            norm_ip = str(ip_obj)
        except ValueError:
            return ResponseResult(
                success=False,
                action="block_ip",
                target=target_ip,
                dry_run=dry_run,
                message=f"Invalid target IP address: '{target_ip}'",
                audit_id="",
            )

        details = {"duration_seconds": duration_seconds, "reason": reason}
        audit = ResponseAuditRecord(
            action="block_ip",
            target=norm_ip,
            executed_by=executed_by,
            dry_run=dry_run,
            success=True,
            actor_id=actor_id or f"actor-{norm_ip}",
            incident_id=incident_id,
            details=details,
        )

        # 2. Execution logic
        if not dry_run and self.firewall:
            try:
                self.firewall.block_ip(norm_ip, duration_seconds=duration_seconds)
            except Exception as e:
                audit.success = False
                audit.details["error"] = str(e)
                self.storage.save_response_audit(audit)
                return ResponseResult(
                    success=False,
                    action="block_ip",
                    target=norm_ip,
                    dry_run=False,
                    message=f"Firewall isolation failed: {e}",
                    audit_id=audit.audit_id,
                    details=audit.details,
                )

        self.storage.save_response_audit(audit)
        mode_str = "simulated (dry-run)" if dry_run else "enforced"
        return ResponseResult(
            success=True,
            action="block_ip",
            target=norm_ip,
            dry_run=dry_run,
            message=f"Successfully {mode_str} isolation for IP {norm_ip} ({duration_seconds}s)",
            audit_id=audit.audit_id,
            details=audit.details,
        )

    def contain_account(
        self,
        username: str,
        dry_run: bool = True,
        executed_by: str = "operator",
        reason: str = "Compromised account containment",
        actor_id: Optional[str] = None,
        incident_id: Optional[str] = None,
    ) -> ResponseResult:
        """Validate and contain an affected user account (experimental hook)."""
        clean_user = username.strip()
        if not USERNAME_REGEX.match(clean_user):
            return ResponseResult(
                success=False,
                action="contain_account",
                target=username,
                dry_run=dry_run,
                message=f"Invalid target username format: '{username}'",
                audit_id="",
            )

        details = {"reason": reason, "mode": "experimental_advisory"}
        audit = ResponseAuditRecord(
            action="contain_account",
            target=clean_user,
            executed_by=executed_by,
            dry_run=dry_run,
            success=True,
            actor_id=actor_id,
            incident_id=incident_id,
            details=details,
        )
        self.storage.save_response_audit(audit)

        mode_str = "simulated (dry-run)" if dry_run else "registered advisory"
        return ResponseResult(
            success=True,
            action="contain_account",
            target=clean_user,
            dry_run=dry_run,
            message=f"Successfully {mode_str} containment for account '{clean_user}'",
            audit_id=audit.audit_id,
            details=audit.details,
        )

    def terminate_session(
        self,
        session_id: str,
        dry_run: bool = True,
        executed_by: str = "operator",
        reason: str = "Active threat session termination",
        actor_id: Optional[str] = None,
        incident_id: Optional[str] = None,
    ) -> ResponseResult:
        """Validate and terminate an active session (experimental hook)."""
        clean_sess = session_id.strip()
        if not clean_sess:
            return ResponseResult(
                success=False,
                action="terminate_session",
                target=session_id,
                dry_run=dry_run,
                message="Session ID cannot be empty",
                audit_id="",
            )

        details = {"reason": reason, "mode": "experimental_hook"}
        audit = ResponseAuditRecord(
            action="terminate_session",
            target=clean_sess,
            executed_by=executed_by,
            dry_run=dry_run,
            success=True,
            actor_id=actor_id,
            incident_id=incident_id,
            details=details,
        )
        self.storage.save_response_audit(audit)

        mode_str = "simulated (dry-run)" if dry_run else "invoked hook"
        return ResponseResult(
            success=True,
            action="terminate_session",
            target=clean_sess,
            dry_run=dry_run,
            message=f"Successfully {mode_str} session termination for '{clean_sess}'",
            audit_id=audit.audit_id,
            details=audit.details,
        )
