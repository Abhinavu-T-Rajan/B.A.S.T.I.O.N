# Configuration Reference Guide

This document describes all configuration settings in `bastion.toml` (Format Version 1).

---

## 1. Schema Overview

```toml
# Configuration format schema version
config_version = 1

[telemetry]
source = "journald"             # "journald", "stdin", or "file"
unit = "ssh.service"            # systemd unit to monitor
log_file_path = ""              # Required when source = "file"

[storage]
db_path = "~/.local/share/bastion/bastion.db"  # SQLite database path

[daemon]
health_check_interval_seconds = 30    # Health state dump frequency
reconciliation_interval_seconds = 60  # Firewall reconciliation schedule
health_state_path = "~/.local/share/bastion/health.json"

[detectors.brute_force]
enabled = true
threshold = 10                  # Failures before detection
window_seconds = 60             # Sliding time window in seconds

[detectors.password_spray]
enabled = true
min_usernames = 3               # Minimum distinct usernames probed
max_attempts_per_user = 3       # Max attempts per username
window_seconds = 300            # Sliding window (5 minutes)

[detectors.enumeration]
enabled = true
threshold = 4                   # Invalid username attempts
window_seconds = 60             # Sliding window

[detectors.burst]
enabled = true
threshold = 5                   # High-velocity attempts
window_seconds = 5              # Window (5 seconds)

[risk]
low_threshold = 0
medium_threshold = 40
high_threshold = 70
critical_threshold = 85

[response]
mode = "dry_run"                # "dry_run", "automatic", "manual", "disabled"
backend = "nftables"            # "nftables" or "mock"
isolation_threshold = 85        # Score required for temporary isolation
rate_limit_threshold = 60       # Score required for rate limiting
default_ban_duration_seconds = 900          # 15 minutes
repeat_offender_ban_duration_seconds = 3600 # 1 hour
max_ban_duration_seconds = 86400            # 24 hours
allowlist_cidrs = [
    "127.0.0.0/8",
    "::1/128",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
]
table_name = "bastion"
```

---

## 2. Configuration Validation Rules

The `bastion config validate` command and `BastionDaemon` startup sequence verify the following invariants:

1. **`config_version`**: Must equal `1`.
2. **`db_path` & `health_state_path`**: Must be non-empty strings.
3. **Detector Parameters**:
   - `threshold` and `window_seconds` must be strictly positive integers ($> 0$).
   - `min_usernames` and `max_attempts_per_user` must be strictly positive integers ($> 0$).
4. **Risk Thresholds**:
   - Must satisfy strict monotonicity: $0 \le \text{low} < \text{medium} < \text{high} < \text{critical} \le 100$.
5. **Response Mode**:
   - Must be one of `["dry_run", "automatic", "manual", "disabled"]`.
6. **Ban Durations**:
   - Must be positive integers and satisfy: $\text{default} \le \text{repeat\_offender} \le \text{max\_ban}$.
7. **Allowlist CIDRs**:
   - Every entry in `allowlist_cidrs` must be a valid IPv4 or IPv6 network representation (parsed via `ipaddress.ip_network`).
8. **Threshold Coherence**:
   - `rate_limit_threshold` must not exceed `isolation_threshold`.

---

## 3. Validating Configuration Files

```bash
# Validate default or current directory config
bastion config validate

# Validate specific configuration file
bastion -c /etc/bastion/bastion.toml config validate
```
