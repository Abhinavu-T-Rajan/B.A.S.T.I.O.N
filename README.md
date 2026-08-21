# B.A.S.T.I.O.N.

**Behavioral Attack Surveillance & Threat Isolation Operating Network**

An active host-level intrusion detection and prevention system designed for Linux environments.

## Features (v0.1.1 - Sentinel)

- **Telemetry Collection**: High-performance systemd-journald ingestion for Linux services (`sshd`).
- **Normalized Event Model**: Technology-agnostic `SecurityEvent` abstraction.
- **Log Parsing**: Robust OpenSSH authentication event parser (passwords, public keys, invalid users, terminations).
- **Behavioral Detection**: Sliding-window brute-force detector with automatic time-decay expiration.
- **Real-Time Sentinel Pipeline**: Live event stream processing and alert triggering.
- **CLI Interface**: Command-line tools for system status, live journal monitoring, event parsing, and detection simulations.

## Installation

```bash
# Clone the repository and enter directory
cd B.A.S.T.I.O.N

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install in editable mode
pip install -e .
```

## CLI Usage

```bash
# Display system status
bastion status

# Monitor live SSH telemetry
bastion monitor --follow

# Inspect/parse a raw SSH log entry
bastion parse "Failed password for invalid user admin from 198.51.100.23 port 43212 ssh2"

# Run a deterministic local brute-force simulation
bastion test-detection --attempts 12 --threshold 10
```

## Running Tests

```bash
pytest -v
```
