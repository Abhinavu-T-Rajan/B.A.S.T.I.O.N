# B.A.S.T.I.O.N.

**Behavioral Attack Surveillance & Threat Isolation Operating Network**

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Version: v0.2.0-alpha (Oracle)](https://img.shields.io/badge/version-0.2.0--alpha%20(Oracle)-brightgreen.svg)]()
[![Tests: 93 Passed](https://img.shields.io/badge/tests-93%20passed-brightgreen.svg)]()

> *"Sentinel sees. Aegis analyzes. Guardian protects. Oracle understands."*

B.A.S.T.I.O.N. is an autonomous, explainable host-level **Intrusion Detection, Prevention & Threat Correlation Platform (IDS/IPS/SOAR)** designed for Linux environments. It monitors live authentication telemetry, correlates behavioral detector signals with local threat intelligence (IOCs), maps observed attack patterns to MITRE ATT&CK techniques, tracks incident lifecycles, and executes audited host isolation responses.

---

## Architecture Overview

```
                         B.A.S.T.I.O.N. v0.2.0-alpha (Oracle)
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
                             │ Threat Intel Subsystem  │ (IOC Validation, Storage & Matching)
                             └────────────┬────────────┘
                                          │
                             ┌────────────▼────────────┐
                             │ Threat Risk Engine      │ (Multi-signal 0–100 Threat Score)
                             └────────────┬────────────┘
                                          │
                             ┌────────────▼────────────┐
                             │ Threat Correlation      │ (ATT&CK Mapping, Incident Lifecycle,
                             │       Engine            │  Alert Deduplication, Timelines)
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
                             │ • Experimental Response │ (Audited actions: block, contain, kill)
                             └────────────┬────────────┘
                                          │
                             ┌────────────▼────────────┐
                             │    Firewall Backend     │
                             ├─────────────────────────┤
                             │ • NFTablesBackend       │ (Dedicated 'inet bastion' namespace)
                             │ • MockFirewallBackend   │ (Testing & non-root environments)
                             └─────────────────────────┘
```

For complete technical documentation on the internal pipeline and subsystem interfaces, refer to the [System Architecture Guide](docs/architecture.md).

---

## Documentation

- **[System Architecture](docs/architecture.md)**: Detailed breakdown of the pipeline, data structures, correlation engine, and subsystem contracts.
- **[Threat Model & Security Analysis](docs/threat-model.md)**: Exhaustive analysis of host threats, parser boundaries, false positives, and fail-safe recovery controls.
- **[Linux Deployment Guide](docs/deployment.md)**: Production deployment instructions, OpenSSH tuning, configuration hardening, and safe phase-by-phase rollout workflows.
- **[Security Policy](SECURITY.md)**: Vulnerability disclosure guidelines, reporting channels, and remediation timelines.
- **[Contributing Guide](CONTRIBUTING.md)**: Branching workflow (`main` / `development`), Conventional Commits, and test requirements.
- **[Changelog](CHANGELOG.md)**: Full release history from `v0.1.0` through `v0.2.0-alpha`.
- **[Code of Conduct](CODE_OF_CONDUCT.md)**: Community standards and enforcement policies.
- **[License](LICENSE)**: Full text of the Apache License 2.0.

---

## Key Subsystems & Features

### 1. Telemetry Ingestion & Log Normalization (Sentinel)
- **Live Journald Streaming**: Direct non-blocking ingestion from `systemd-journald` for `ssh.service` and `sshd.service`.
- **OpenSSH Log Parser**: Normalized `SecurityEvent` model covering passwords, public keys, invalid users, connection drops, and max attempt violations across IPv4 and IPv6.

### 2. Behavioral Detection Suite (Aegis)
- **Brute-Force Detector**: Sliding-window counter with time-decay expiration.
- **Password Spray Detector**: Identifies single IPs probing multiple distinct usernames with low attempt counts per account.
- **Username Enumeration Detector**: Flags rapid invalid-user authentication attempts.
- **Burst Velocity Detector**: Detects sudden high-frequency request spikes ($\ge 5$ attempts in 5 seconds).

### 3. Threat Intelligence & IOC Subsystem (Oracle)
- **Format Validation**: Strict validation for IP addresses, domains, cryptographic hashes (`MD5`, `SHA1`, `SHA256`), and usernames.
- **Provenance Tracking**: Distinguishes data trust levels: `OBSERVED`, `INFERRED`, `CONFIGURED`, `CONFIRMED`, and `UNKNOWN`.
- **Real-Time Event Matching**: Live matching of incoming events against active IOCs with adaptive risk scoring bonuses (+15 to +30 points).

### 4. Threat Correlation & MITRE ATT&CK Mapping (Oracle)
- **MITRE ATT&CK Catalog**: Authentic techniques mapped to behavioral detectors:
  - `T1110.001`: Password Guessing (Brute Force)
  - `T1110.003`: Password Spraying
  - `T1087.001`: Account Discovery (Username Enumeration)
  - `T1499`: Endpoint Denial of Service (Burst Spikes)
  - `T1078`: Valid Accounts
- **Alert Deduplication**: Rolling time-window cache preventing redundant alert output while maintaining full event telemetry.
- **Incident Lifecycle**: Tracks incident progression through `OPEN`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`, and `CLOSED`.
- **Investigation Timelines**: Reconstructs complete forensic histories across events, detections, risk score transitions, bans, and response audits.

### 5. Defensive Response & Firewall Integration (Guardian & Oracle)
- **Safety Controls & Allowlisting**: Subnet matching permanently protects `127.0.0.0/8`, `::1/128`, `10.0.0.0/8`, `172.16.0.0/12`, and `192.168.0.0/16`.
- **Isolated `nftables` Integration**: Dedicated `table inet bastion` with `blacklist_v4` / `blacklist_v6` sets, zero host firewall disruption.
- **Audited Experimental Response**: Isolated response actions with validation and tamper-evident `response_audits` logging.

---

## Installation & Quick Start

### 1. Clone and Install in Virtual Environment

```bash
git clone https://github.com/Abhinavu-T-Rajan/B.A.S.T.I.O.N.git
cd B.A.S.T.I.O.N

python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### 2. Check Operational Status

```bash
bastion status
```

### 3. Run Behavioral Simulation

```bash
bastion test-detection --attempts 12 --threshold 10
```

---

## CLI Reference Guide

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

### Live Monitoring
```bash
# Monitor live journald logs in dry-run mode (safe testing)
bastion monitor --follow --dry-run

# Monitor with automatic nftables enforcement
sudo $(which bastion) monitor --follow --enforce
```

---

## Running the Automated Test Suite

```bash
pytest -v
```

All 93 test cases cover log parsing, behavioral detection, risk scoring, threat intelligence validation, correlation, incident lifecycles, investigation timelines, response auditing, and CLI workflows.

---

## License

B.A.S.T.I.O.N. is licensed under the **Apache License 2.0**. See [LICENSE](LICENSE) for details.
