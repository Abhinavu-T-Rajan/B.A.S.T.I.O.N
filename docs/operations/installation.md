# Installation & Production Deployment Guide

This guide describes how to install, upgrade, and manage **B.A.S.T.I.O.N. v0.3.0 (Sentinel Core)** on Linux host systems.

---

## 1. Automated Production Installation

B.A.S.T.I.O.N. provides a modular, production-grade installer located in `installer/install.sh`. It performs preflight validation, package dependency setup, service account creation, filesystem configuration, virtual environment isolation, database initialization, and systemd service activation.

### Quick Start (Interactive)
```bash
git clone https://github.com/Abhinavu-T-Rajan/B.A.S.T.I.O.N.git
cd B.A.S.T.I.O.N

sudo ./installer/install.sh
```

### Non-Interactive / Automation Deployment
```bash
sudo ./installer/install.sh --non-interactive
```

### Preflight Verification (Check Only)
To verify OS support and dependencies without modifying the host system:
```bash
./installer/install.sh --check-only
```

---

## 2. Installer Architecture & Execution Stages

The installer executes through 8 visual, atomic stages:

```
[1/8] Detecting operating system & environment... PASS
[2/8] Installing system dependencies............. PASS
[3/8] Creating dedicated service account......... PASS
[4/8] Configuring filesystem layout & perms...... PASS
[5/8] Installing application into /opt/bastion... PASS
[6/8] Initializing database schema & migrations.. PASS
[7/8] Installing systemd service & firewall...... PASS
[8/8] Running operational health checks.......... PASS
```

### Supported Linux Distributions
- **Ubuntu**: 22.04 LTS, 24.04 LTS+
- **Debian**: 12 (Bookworm), 13 (Trixie)+
- **Fedora**: 38, 39, 40, 41, 42+
- **RHEL / Rocky Linux / AlmaLinux**: 9+
- **Arch Linux / Manjaro**

---

## 3. Standardized Filesystem Layout

| Path | Owner:Group | Mode | Description |
| :--- | :--- | :--- | :--- |
| `/etc/bastion/bastion.toml` | `root:bastion` | `0640` | Production configuration file |
| `/var/lib/bastion/bastion.db` | `bastion:bastion` | `0640` | Persistent forensic SQLite database |
| `/var/lib/bastion/health.json` | `bastion:bastion` | `0640` | Subsystem health snapshot |
| `/var/log/bastion/` | `bastion:bastion` | `0750` | Service log directory |
| `/opt/bastion/venv/` | `root:root` | `0755` | Isolated Python 3 runtime |
| `/usr/local/bin/bastion` | `root:root` | `0755` | System CLI symlink |
| `/etc/systemd/system/bastion.service` | `root:root` | `0644` | Hardened systemd unit |

---

## 4. Firewall Isolation Guarantee

B.A.S.T.I.O.N. creates and manages its own isolated `nftables` namespace:
```
table inet bastion {
    set blacklist_v4 { type ipv4_addr; flags timeout; }
    set blacklist_v6 { type ipv6_addr; flags timeout; }
    chain input { type filter hook input priority -100; policy accept; ... }
}
```
> [!IMPORTANT]
> The installer and service will **never** flush, overwrite, or modify existing host firewall tables (`filter`, `firewalld`, `ufw`, `iptables`).

---

## 5. Upgrading B.A.S.T.I.O.N.

To upgrade an existing installation to the latest release:

```bash
cd B.A.S.T.I.O.N
git pull origin main

sudo ./installer/upgrade.sh
```

### Upgrade Safeguards
- Automatically creates timestamped backups of configuration (`/var/lib/bastion/backups/bastion.toml.bak.*`) and database (`/var/lib/bastion/backups/bastion.db.bak.*`).
- Applies database schema migrations idempotently.
- Validates updated configuration against the new schema version.
- Restarts `bastion.service` and executes health verification.

---

## 6. Clean Uninstallation

To remove B.A.S.T.I.O.N. from a host system:

### Retain Forensic Evidence (Default Safe Mode)
Stops service, removes binaries, removes `nftables` table, but preserves databases and logs:
```bash
sudo ./installer/uninstall.sh
```

### Purge All Data
Removes application binaries, configuration, forensic databases, logs, and service user:
```bash
sudo ./installer/uninstall.sh --purge-all
```
