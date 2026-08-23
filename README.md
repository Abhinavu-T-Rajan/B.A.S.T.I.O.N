# B.A.S.T.I.O.N.

**Behavioral Attack Surveillance & Threat Isolation Operating Network**

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Version: v0.4.0 (Gateway)](https://img.shields.io/badge/version-0.4.0%20(Gateway)-brightgreen.svg)]()
[![Tests: 154 Passed](https://img.shields.io/badge/tests-154%20passed-brightgreen.svg)]()

> *"Separate what B.A.S.T.I.O.N. does from how B.A.S.T.I.O.N. implements it."*

B.A.S.T.I.O.N. is an autonomous, explainable host-level **Intrusion Detection, Prevention & Threat Correlation Platform (IDS/IPS/SOAR)** designed for Linux environments. Built upon a clean modular core, it isolates domain capabilities from driver implementations through standardized provider interfaces (`CollectorProvider`, `Detector`, `ResponseProvider`, `FirewallProvider`, `StorageProvider`).

---

## Architecture Overview

```
                                  B.A.S.T.I.O.N. v0.4.0 (Gateway)
                                                 │
                 ┌───────────────────────────────┴───────────────────────────────┐
                 │                   Application Service Layer                   │
                 ├───────────────────────────────────────────────────────────────┤
                 │ • DefenseAppService      • IntelligenceAppService             │
                 │ • IncidentAppService     • HealthAppService                   │
                 │ • SentinelPipeline       (Unified Event & Defense Pipeline)   │
                 └───────────────────────────────┬───────────────────────────────┘
                                                 │
        ┌────────────────────────┬───────────────┴───────────────┬────────────────────────┐
        │                        │                               │                        │
┌───────▼────────┐      ┌────────▼────────┐             ┌────────▼────────┐      ┌────────▼────────┐
│   Telemetry    │      │    Behavioral   │             │   Defensive     │      │   Persistence   │
│   Gateway      │      │    Detectors    │             │   Response      │      │   Storage       │
├────────────────┤      ├─────────────────┤             ├─────────────────┤      ├─────────────────┤
│ Collector      │      │ Detector        │             │ Response        │      │ Storage         │
│ Provider       │      │ Provider        │             │ Provider        │      │ Provider        │
│                │      │                 │             │                 │      │                 │
│ • Journald     │      │ • Brute-Force   │             │ • Policy Engine │      │ • SQLiteStorage │
│ • Stdin        │      │ • Spray         │             │ • Ban Manager   │      │   (Migrations)  │
│ • File         │      │ • Enumeration   │             │ • Reconciler    │      │                 │
│                │      │ • Burst         │             │                 │      │                 │
│ RawTelemetry   │      │ • Custom Plugin │             │ Firewall        │      │                 │
│       │        │      └─────────────────┘             │ Provider        │      │                 │
│ Adapters &     │                                      ├─────────────────┤      │                 │
│ Normalizers    │                                      │ • NFTables      │      │                 │
│       ▼        │                                      │ • MockBackend   │      │                 │
│ SecurityEvent  │                                      └─────────────────┘      │                 │
└────────────────┘                                                               └─────────────────┘
```

For complete technical documentation on the internal pipeline and subsystem interfaces, refer to the [System Architecture Guide](docs/architecture.md).

---

## Documentation

- **[System Architecture](docs/architecture.md)**: Detailed breakdown of the modular core, provider contracts, telemetry gateway, and application services.
- **[Development Guide](DEVELOPMENT.md)**: Developer environment setup, architectural conventions, and contribution workflows.
- **[Developer Setup](docs/development/setup.md)** & **[Testing Guide](docs/development/testing.md)**: Environment setup and testing workflows.
- **[Operations & Installation](docs/operations/installation.md)**: Systemd service deployment, directory layout, and privilege configuration.
- **[Service Management](docs/operations/service-management.md)**: Daemon operations, health diagnostics, troubleshooting, and logs.
- **[Configuration Reference](docs/operations/configuration.md)**: Complete `bastion.toml` parameters, thresholds, and schema validation.
- **[Threat Model & Security Analysis](docs/threat-model.md)**: Host threat analysis, parser boundaries, false positives, and fail-safe recovery controls.
- **[Security Policy](SECURITY.md)**: Vulnerability disclosure guidelines and remediation timelines.
- **[Contributing Guide](CONTRIBUTING.md)**: Branching workflow, Conventional Commits, and code review standards.
- **[Changelog](CHANGELOG.md)**: Full release history from `v0.1.0` through `v0.3.0`.
- **[License](LICENSE)**: Full text of the Apache License 2.0.

---

## Key Subsystems & Features

### 1. Persistent Daemon & systemd Integration (Sentinel Core)
- **Production Service Unit**: Official `bastion.service` configured with least privilege (`CAP_NET_ADMIN`), filesystem sandboxing (`ProtectSystem=strict`, `ProtectHome=read-only`), private temp dirs, and auto-restart resilience.
- **Subsystem Health Diagnostics**: Real-time health tracking and atomic state dumping across Database, Firewall, Detection, Threat Intel, Telemetry, Response, and Service lifecycle state.
- **Firewall State Reconciliation**: Startup ban restoration and periodic background sync comparing SQLite active bans against live kernel `nftables` sets, healing dropped rules and cleaning expired bans.
- **Configuration Validation**: Schema validation (`config_version = 1`) validating thresholds, durations, networks, and detector parameters prior to daemon startup.

### 2. Telemetry Ingestion & Log Normalization (Sentinel)
- **Live Journald Streaming**: Direct non-blocking ingestion from `systemd-journald` for `ssh.service` and `sshd.service`.
- **OpenSSH Log Parser**: Normalized `SecurityEvent` model covering passwords, public keys, invalid users, connection drops, and max attempt violations across IPv4 and IPv6.

### 3. Behavioral Detection Suite (Aegis)
- **Brute-Force Detector**: Sliding-window counter with time-decay expiration.
- **Password Spray Detector**: Identifies single IPs probing multiple distinct usernames with low attempt counts per account.
- **Username Enumeration Detector**: Flags rapid invalid-user authentication attempts.
- **Burst Velocity Detector**: Detects sudden high-frequency request spikes ($\ge 5$ attempts in 5 seconds).

### 4. Threat Intelligence & IOC Subsystem (Oracle)
- **Format Validation**: Strict validation for IP addresses, domains, cryptographic hashes (`MD5`, `SHA1`, `SHA256`), and usernames.
- **Provenance Tracking**: Distinguishes data trust levels: `OBSERVED`, `INFERRED`, `CONFIGURED`, `CONFIRMED`, and `UNKNOWN`.
- **Real-Time Event Matching**: Live matching of incoming events against active IOCs with adaptive risk scoring bonuses (+15 to +30 points).

### 5. Threat Correlation & MITRE ATT&CK Mapping (Oracle)
- **MITRE ATT&CK Catalog**: Authentic techniques mapped to behavioral detectors:
  - `T1110.001`: Password Guessing (Brute Force)
  - `T1110.003`: Password Spraying
  - `T1087.001`: Account Discovery (Username Enumeration)
  - `T1499`: Endpoint Denial of Service (Burst Spikes)
  - `T1078`: Valid Accounts
- **Alert Deduplication**: Rolling time-window cache preventing redundant alert output while maintaining full event telemetry.
- **Incident Lifecycle**: Tracks incident progression through `OPEN`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`, and `CLOSED`.
- **Investigation Timelines**: Reconstructs complete forensic histories across events, detections, risk score transitions, bans, and response audits.

### 6. Defensive Response & Firewall Integration (Guardian & Oracle)
- **Safety Controls & Allowlisting**: Subnet matching permanently protects `127.0.0.0/8`, `::1/128`, `10.0.0.0/8`, `172.16.0.0/12`, and `192.168.0.0/16`.
- **Isolated `nftables` Integration**: Dedicated `table inet bastion` with `blacklist_v4` / `blacklist_v6` sets, zero host firewall disruption.
- **Audited Experimental Response**: Isolated response actions with validation and tamper-evident `response_audits` logging.

---

## Installation & Quick Start

### 1. Automated Production Installation (Recommended)

B.A.S.T.I.O.N. includes an automated, production-grade installer that validates the host OS, installs dependencies, creates dedicated service accounts, configures `/etc/bastion`, and enables the `bastion.service` systemd daemon:

```bash
git clone https://github.com/Abhinavu-T-Rajan/B.A.S.T.I.O.N.git
cd B.A.S.T.I.O.N

# Run interactive installer
sudo ./installer/install.sh

# Or non-interactive / unattended deployment:
# sudo ./installer/install.sh --non-interactive
```

### 2. Manual / Developer Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Validate configuration & health
bastion config validate
bastion health
bastion status
```

### 3. Service Lifecycle Management

```bash
# Start or restart daemon
sudo systemctl start bastion.service

# Check live status & health
sudo systemctl status bastion.service
bastion health

# Upgrade to latest release
sudo ./installer/upgrade.sh

# Clean uninstallation
sudo ./installer/uninstall.sh
```

---

## CLI Reference Guide

### Service Management & Diagnostics
```bash
# Validate configuration file
bastion config validate

# Inspect subsystem health status
bastion health

# Output machine-readable JSON health report
bastion health --json

# Display overall platform status and telemetry counters
bastion status
```

### Threat Intelligence (IOC) Management
```bash
# Add a new IOC
bastion ioc add --type ip --value 198.51.100.23 --confidence 90 --tags scanner,c2 --notes "Observed in spray campaign"

# List active IOCs
bastion ioc list --type ip --status active

# Search IOCs by query
bastion ioc search scanner

# Delete an IOC
bastion ioc delete <ioc-id>
```

### Incident Management
```bash
# List open incidents
bastion incident list --status open

# Inspect incident details
bastion incident inspect <incident-id>

# Update incident status
bastion incident update <incident-id> --status contained --notes "Host isolated via nftables"

# Create a manual incident
bastion incident create --title "Investigating Suspicious Login Spike" --severity high --risk 85
```

### Investigation Timelines & MITRE ATT&CK
```bash
# View chronological investigation timeline for an IP
bastion timeline --ip 198.51.100.23

# View chronological investigation timeline for an Incident
bastion timeline --incident <incident-id>

# List MITRE ATT&CK catalog
bastion attack

# Inspect specific technique
bastion attack T1110.003
```

### Threat Actors & Bans
```bash
# List tracked threat actors
bastion threats --min-score 70

# Inspect forensic profile of an IP
bastion inspect 198.51.100.23

# List active bans
bastion bans

# Manually isolate an IP (15 minutes default)
bastion ban 203.0.113.88 --duration 900

# Release a ban
bastion unban 203.0.113.88
```

---

## Running the Automated Test Suite

```bash
pytest -v
```

All 126 test cases cover automated installation and upgrade workflows, configuration validation, daemon lifecycle management, health monitoring, firewall reconciliation, log parsing, behavioral detection, risk scoring, threat intelligence validation, correlation, incident lifecycles, investigation timelines, response auditing, and CLI workflows.

---

## License

B.A.S.T.I.O.N. is licensed under the **Apache License 2.0**. See [LICENSE](LICENSE) for details.
