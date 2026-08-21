from __future__ import annotations

import ipaddress
import re
from typing import Tuple

from bastion.intelligence.models import IOCType

DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)
HEX_32_REGEX = re.compile(r"^[a-fA-F0-9]{32}$")
HEX_40_REGEX = re.compile(r"^[a-fA-F0-9]{40}$")
HEX_64_REGEX = re.compile(r"^[a-fA-F0-9]{64}$")


class IOCValidator:
    """Validator for Indicator of Compromise (IOC) values."""

    @classmethod
    def validate(cls, ioc_type: IOCType, value: str) -> Tuple[bool, str]:
        """
        Validate an IOC value against its type.

        Returns (is_valid, normalized_value_or_error_message).
        """
        val = value.strip()
        if not val:
            return False, "IOC value cannot be empty"

        if ioc_type == IOCType.IP:
            try:
                ip_obj = ipaddress.ip_address(val)
                return True, str(ip_obj)
            except ValueError:
                return False, f"Invalid IP address format: '{val}'"

        elif ioc_type == IOCType.DOMAIN:
            val_lower = val.lower()
            if len(val_lower) > 253:
                return False, "Domain name exceeds maximum length of 253 characters"
            if not DOMAIN_REGEX.match(val_lower):
                return False, f"Invalid domain name format: '{val}'"
            return True, val_lower

        elif ioc_type == IOCType.HASH_MD5:
            if not HEX_32_REGEX.match(val):
                return False, "Invalid MD5 hash format (must be 32 hexadecimal characters)"
            return True, val.lower()

        elif ioc_type == IOCType.HASH_SHA1:
            if not HEX_40_REGEX.match(val):
                return False, "Invalid SHA-1 hash format (must be 40 hexadecimal characters)"
            return True, val.lower()

        elif ioc_type == IOCType.HASH_SHA256:
            if not HEX_64_REGEX.match(val):
                return False, "Invalid SHA-256 hash format (must be 64 hexadecimal characters)"
            return True, val.lower()

        elif ioc_type == IOCType.USERNAME:
            if len(val) > 64:
                return False, "Username exceeds maximum length of 64 characters"
            return True, val

        return False, f"Unsupported IOC type: {ioc_type}"
