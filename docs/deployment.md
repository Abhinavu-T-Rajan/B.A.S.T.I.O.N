# B.A.S.T.I.O.N. Linux Deployment Guide

**Safe Deployment & Operational Hardening for Linux Hosts** (v0.2.0-alpha "Oracle")

---

## 1. System Prerequisites

Before deploying B.A.S.T.I.O.N. in a production or staging Linux environment, verify that the host meets the following prerequisites:

| Requirement | Minimum Version | Notes |
| :--- | :--- | :--- |
| **Operating System** | Linux (Kernel $\ge 5.4$) | Ubuntu 22.04+, Debian 12+, RHEL/Rocky 9+, Arch Linux |
| **Python** | Python 3.11+ | Required for modern typing and `tomllib` standard library |
| **Log Subsystem** | `systemd-journald` | Accessible via `journalctl` utility |
| **SSH Server** | OpenSSH Server 8.0+ | `sshd.service` or `ssh.service` |
| **Firewall Utility** | `nftables` (nft CLI) | Required for active kernel-level packet isolation |

---

## 2. OpenSSH & Journald Configuration

For optimal detection accuracy, OpenSSH should emit structured authentication events:

1. **Verify OpenSSH Logging** in `/etc/ssh/sshd_config`:
   ```text
   SyslogFacility AUTH
   LogLevel VERBOSE
   ```
   *(Note: `LogLevel VERBOSE` records public key fingerprints and failed attempt reasons, enhancing behavioral detection signals).*

2. **Reload SSH Service**:
   ```bash
   sudo systemctl reload sshd   # Or 'ssh' on Debian/Ubuntu
   ```

3. **Verify Journald Access**:
   ```bash
   journalctl -u sshd -n 10 --no-pager
   ```

---

## 3. Installation & Setup

### 3.1 Production Virtual Environment

It is recommended to deploy B.A.S.T.I.O.N. within an isolated virtual environment:

```bash
# 1. Create a dedicated system directory
sudo mkdir -p /opt/bastion /var/lib/bastion /etc/bastion

# 2. Clone the repository
sudo git clone https://github.com/Abhinavu-T-Rajan/B.A.S.T.I.O.N.git /opt/bastion/app
cd /opt/bastion/app

# 3. Create virtual environment
sudo python3 -m venv /opt/bastion/venv
sudo /opt/bastion/venv/bin/pip install --upgrade pip
sudo /opt/bastion/venv/bin/pip install -e .

# 4. Symlink executable
sudo ln -sf /opt/bastion/venv/bin/bastion /usr/local/bin/bastion
```

---

## 4. Configuration Hardening (`/etc/bastion/bastion.toml`)

Create `/etc/bastion/bastion.toml` with hardened settings:

```toml
# B.A.S.T.I.O.N. Production Configuration

[storage]
# Production SQLite database location
db_path = "/var/lib/bastion/bastion.db"

[detectors.brute_force]
enabled = true
threshold = 10
window_seconds = 60

[detectors.password_spray]
enabled = true
min_usernames = 3
max_attempts_per_user = 3
window_seconds = 120

[detectors.enumeration]
enabled = true
threshold = 4
window_seconds = 60

[detectors.burst]
enabled = true
threshold = 5
window_seconds = 5

[risk]
medium_threshold = 40
high_threshold = 70
critical_threshold = 85

# scoring weights
failed_auth_weight = 5
invalid_user_weight = 10
burst_velocity_weight = 25
brute_force_weight = 20
password_spray_weight = 20
enumeration_weight = 20
max_attempts_weight = 20
repeat_offender_weight = 15

# Force score 0 for trusted static IPs
trusted_ips = ["127.0.0.1", "::1", "localhost", "192.168.1.50"]

[response]
# CRITICAL: Always start in dry_run mode during initial deployment!
mode = "dry_run"

# Firewall backend: nftables, mock
backend = "nftables"

# Action thresholds
isolation_threshold = 85
rate_limit_threshold = 60

# Ban duration in seconds (900s = 15m, 3600s = 1h, 86400s = 24h)
default_ban_duration_seconds = 900
repeat_offender_ban_duration_seconds = 3600
max_ban_duration_seconds = 86400

# Subnet allowlist: NEVER remove management subnets or localhost!
allowlist_cidrs = [
    "127.0.0.0/8",
    "::1/128",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    # Add your corporate VPN / Bastion host CIDRs here:
    # "203.0.113.0/24",
]

# Dedicated nftables table namespace
table_name = "bastion"
```

---

## 5. Safe Deployment Workflow

Because B.A.S.T.I.O.N. has active containment capabilities, follow this multi-phase deployment workflow to eliminate false positives and lockout risks:

```
  Phase 1: Validation
  Run unit tests & verify subsystem health
        ↓
  Phase 2: Shadow Evaluation (Dry-Run Mode)
  Run in dry-run mode for 24-48 hours to tune thresholds
        ↓
  Phase 3: Allowlist Verification
  Test that management subnets are explicitly exempt
        ↓
  Phase 4: Active Enforcement
  Enable automated kernel-level containment via nftables
```

### Step 1: Health & Subsystem Verification
```bash
# Verify system status
bastion status

# Verify firewall subsystem availability
bastion firewall status
```

### Step 2: Shadow Evaluation (Dry-Run Mode)
Run B.A.S.T.I.O.N. in dry-run mode to monitor telemetry and record score factors without modifying firewall rules:
```bash
# Monitor live SSH stream in dry-run mode
bastion monitor --follow --dry-run
```
Inspect recorded threat scores and simulated bans over 24 hours:
```bash
bastion threats
bastion bans --all
```

### Step 3: Allowlist Verification
Test an intentional authentication failure from an allowlisted management IP and verify it is not blocked:
```bash
bastion inspect 10.0.0.5   # Verify State=TRUSTED or Action=NONE
```

### Step 4: Enabling Active Enforcement
Once scoring thresholds and allowlists are validated, enable active containment:
```bash
# Start live monitoring with active kernel-level packet dropping
sudo bastion monitor --follow --enforce
```

---

## 6. Operational Management & Troubleshooting

### Emergency Unban & Flush
If an IP is mistakenly isolated by an operator or rule:
```bash
# Release a single IP immediately
sudo bastion unban 198.51.100.23

# Flush all B.A.S.T.I.O.N. firewall blacklist rules
sudo bastion firewall flush
```

### Inspecting Kernel `nftables` Rules Directly
To inspect the dedicated `inet bastion` table outside B.A.S.T.I.O.N.:
```bash
# View table rules
sudo nft list table inet bastion

# View active IPv4 blacklist set
sudo nft list set inet bastion blacklist_v4
```

### Backup & Database Maintenance
```bash
# Backup SQLite intelligence database
sudo sqlite3 /var/lib/bastion/bastion.db ".backup '/var/backups/bastion-$(date +%F).db'"
```
