# Developer Setup Guide

This guide walks you through configuring a local development environment for contributing to **B.A.S.T.I.O.N.**.

---

## 1. System Requirements

- **Linux**: Ubuntu 22.04+, Debian 12+, Fedora 38+, Arch Linux, RHEL 9+.
- **Python**: 3.11 or higher.
- **Git**: 2.30+.
- **Optional Tools**:
  - `nftables` (for live firewall testing)
  - `systemd` / `journalctl` (for live telemetry tests)

---

## 2. Virtual Environment Setup

```bash
# Clone the repository
git clone https://github.com/Abhinavu-T-Rajan/B.A.S.T.I.O.N.git
cd B.A.S.T.I.O.N

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Upgrade packaging tools
pip install --upgrade pip setuptools wheel

# Install in editable mode with development dependencies
pip install -e ".[dev]"
```

---

## 3. Verifying the Setup

Verify that all entry points and CLI tools operate correctly:

```bash
# Check version
bastion --version

# Run configuration check
bastion config validate

# Inspect health state
bastion health

# Execute behavioural test simulation
bastion test-detection --attempts 12 --threshold 10
```

---

## 4. Running the Daemon in Development Mode

You can run the Sentinel Core daemon directly from your virtual environment without root privileges:

```bash
# Run daemon in dry-run mode (using mock firewall backend)
bastion daemon --dry-run --backend mock

# Check daemon health from another terminal
bastion health
```
