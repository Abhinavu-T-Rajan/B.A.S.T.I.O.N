# B.A.S.T.I.O.N.

**Behavioral Attack Surveillance & Threat Isolation Operating Network**

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Version: v0.1.3 (Guardian)](https://img.shields.io/badge/version-0.1.3%20(Guardian)-brightgreen.svg)]()

B.A.S.T.I.O.N. is an autonomous, explainable host-level **Intrusion Detection & Prevention System (IDS/IPS)** designed for Linux environments. It monitors live authentication telemetry, detects coordinated attack patterns, calculates multi-signal risk scores (0–100), and provides automated threat containment via `nftables` packet filtering without administrative lockout risks.

---

## Architecture Overview

```
                         B.A.S.T.I.O.N. Architecture
                                      │
                         ┌────────────▼────────────┐
                         │     Telemetry Layer     │ (systemd-journald / sshd / stdin)
                         └────────────┬────────────┘
                                      │
                         ┌────────────▼────────────┐
                         │   Normalized Events     │ (SecurityEvent abstraction)
                         └────────────┬────────────┘
                                      │
                         ┌────────────▼────────────┐
                         │    Detection Suite      │ (Brute-Force, Spray, Enum, Burst)
                         └────────────┬────────────┘
                                      │
                         ┌────────────▼────────────┐
                         │   Threat Risk Engine    │ (Explainable 0–100 Threat Score)
                         └────────────┬────────────┘
                                      │
                         ┌────────────▼────────────┐
                         │      Policy Engine      │ (CIDR Allowlist, Severity Thresholds)
                         └────────────┬────────────┘
                                      │
                         ┌────────────▼────────────┐
                         │     Response Engine     │ (Dry-Run, Automatic, Manual, Disabled)
                         ├─────────────────────────┤
                         │ • Ban Manager           │ (State Machine, Expirations, SQLite)
                         └────────────┬────────────┘
                                      │
                         ┌────────────▼────────────┐
                         │    Firewall Backend     │
                         ├─────────────────────────┤
                         │ • NFTablesBackend       │ (Dedicated 'inet bastion' namespace)
                         │ • MockFirewallBackend   │ (Testing & non-root environments)
                         └─────────────────────────┘
```

---

## Key Features

### 1. Telemetry Ingestion & Log Normalization (v0.1.1 Sentinel)
- **Live Journald Streaming**: Direct non-blocking ingestion from `systemd-journald` for `ssh.service` and `sshd.service`.
- **OpenSSH Log Parser**: Normalized `SecurityEvent` model covering passwords, public keys, invalid users, connection drops, and max attempt violations across IPv4 and IPv6.

### 2. Behavioral Detection Suite (v0.1.2 Aegis)
- **Brute-Force Detector**: Sliding-window counter with time-decay expiration.
- **Password Spray Detector**: Identifies single IPs probing multiple distinct usernames with low attempt counts per account.
- **Username Enumeration Detector**: Flags rapid invalid-user authentication attempts.
- **Burst Velocity Detector**: Detects sudden high-frequency request spikes ($\ge 5$ attempts in 5 seconds).

### 3. Explainable Threat Intelligence & Risk Engine (v0.1.2 Aegis)
- **Multi-Signal 0–100 Scoring**: Transparent scoring model combining auth failures, invalid user probing, detector activations, burst velocity, and repeat offender history.
- **Auditable Score Factors**: Every score is accompanied by human-readable, auditable factor explanations.
- **Forensic Threat Profiles**: Tracks first/last seen, targeted accounts, targeted services, and state transitions.

### 4. Response Engine & Ban Lifecycle Management (v0.1.3 Guardian)
- **Safety Controls & Allowlisting**: Subnet matching (`ipaddress.ip_network`) permanently protects `127.0.0.0/8`, `::1/128`, `10.0.0.0/8`, `172.16.0.0/12`, and `192.168.0.0/16` from accidental lockout.
- **Flexible Response Modes**:
  - `DRY_RUN` *(Default)*: Evaluates risk and displays `"WOULD BLOCK <IP>"` without modifying firewall rules.
  - `AUTOMATIC`: Enforces kernel-level packet isolation via `nftables`.
  - `MANUAL_APPROVAL`: Queues recommendations for operator approval.
  - `DISABLED`: Emergency killswitch.
- **Ban State Machine**: `NEUTRAL` $\rightarrow$ `PROBING` $\rightarrow$ `SUSPICIOUS` $\rightarrow$ `ACTIVE_THREAT` $\rightarrow$ `ISOLATED` $\rightarrow$ `EXPIRED` / `RELEASED`.
- **Automatic Expirations & Startup Recovery**: Auto-releases expired bans and restores active unexpired rules upon daemon restarts.

### 5. Non-Disruptive `nftables` Integration
- **Isolated Namespace**: All firewall rules operate inside a dedicated table `inet bastion` with sets `blacklist_v4` and `blacklist_v6`.
- **Zero Conflict**: Never flushes, overwrites, or alters existing host firewall rules or chains.

---

## Installation

```bash
# Clone the repository
git clone https://github.com/Abhinavu-T-Rajan/B.A.S.T.I.O.N.git
cd B.A.S.T.I.O.N

# Set up Python virtual environment (Python 3.11+)
python3 -m venv .venv
source .venv/bin/activate

# Install in editable mode
pip install -e .
```

---

## CLI Usage

### System & Subsystem Inspection
```bash
# Show system status, database health, response mode, and protected subnets
bastion status

# Show firewall table status and active blocked set
bastion firewall status

# Inspect configuration
bastion config show

# View aggregated intelligence metrics
bastion stats
```

### Threat Monitoring & Live IPS
```bash
# Live stream from systemd-journald in dry-run mode (safe evaluation)
bastion monitor --follow --dry-run

# Live stream with automated firewall enforcement
sudo bastion monitor --follow --enforce

# Pipe simulated logs via stdin
cat test_attack.log | bastion monitor --stdin --dry-run
```

### Forensic Analysis & Threat Actor Profiles
```bash
# List all tracked threat actors ranked by risk score
bastion threats

# Inspect full forensic timeline, score factors, and ban status for an IP
bastion inspect 198.51.100.23

# Query recorded telemetry events
bastion events --ip 198.51.100.23 --limit 20
```

### Ban Management
```bash
# List active or historical bans
bastion bans
bastion bans --all

# Manually isolate an IP (15-minute temporary ban)
bastion ban 203.0.113.50 --duration 900 --reason "Port scanning & brute force"

# Apply a permanent ban
bastion ban 203.0.113.50 --permanent --reason "Persistent attacker"

# Release an active ban
bastion unban 203.0.113.50

# Flush all bastion firewall rules
bastion firewall flush
```

---

## Configuration (`bastion.toml`)

Configure thresholds, scoring weights, and response behaviors in `bastion.toml`:

```toml
[storage]
db_path = "~/.local/share/bastion/bastion.db"

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
trusted_ips = ["127.0.0.1", "::1", "localhost"]

[response]
mode = "dry_run"                  # dry_run, manual, automatic, disabled
backend = "nftables"             # nftables, mock
isolation_threshold = 85         # Score >= 85 triggers isolation
rate_limit_threshold = 60
default_ban_duration_seconds = 900
repeat_offender_ban_duration_seconds = 3600
max_ban_duration_seconds = 86400

# Subnets permanently protected from blocking
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

## Running Tests

Run the complete test suite with `pytest`:

```bash
pytest -v
```

All 71 unit and integration tests validate log parsing, behavioral detection algorithms, risk scoring formulas, CIDR allowlisting, ban state machines, nftables command generation, and CLI interfaces.

---

## Roadmap & Release Progression

- **v0.1.0 — Foundation**: Core architecture, SecurityEvent model, and brute force detection.
- **v0.1.1 — Sentinel**: Systemd-journald streaming & OpenSSH regex parsing.
- **v0.1.2 — Aegis**: Behavioral detection suite (spray, enum, burst), 0–100 risk scoring engine, and SQLite persistence.
- **v0.1.3 — Guardian** *(Current)*: Response engine, policy engine, ban lifecycle manager, nftables integration, and CIDR allowlisting.
- **v0.2.0 — Autonomous Host Defense**: Systemd service integration, daemonized background worker, and notification webhooks.
- **v0.3.0+ — Aegis Enterprise**: Web dashboard, distributed multi-server telemetry, and threat intelligence feeds.

---

## License
 
Apache License 2.0. See [LICENSE](LICENSE) for details.
