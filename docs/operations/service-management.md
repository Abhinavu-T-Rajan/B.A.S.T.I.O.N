# Service Management & Operations Guide

This guide covers day-to-day operations, health monitoring, troubleshooting, and maintenance for **B.A.S.T.I.O.N. Sentinel Core**.

---

## 1. Managing the systemd Service

```bash
# Start the service
sudo systemctl start bastion.service

# Stop the service gracefully (allows flush & ban cleanup)
sudo systemctl stop bastion.service

# Restart the service (re-validates config & reconciles bans)
sudo systemctl restart bastion.service

# Inspect systemd unit status
sudo systemctl status bastion.service
```

---

## 2. Health Monitoring & Diagnostics

### Real-Time Health Inspection
Use `bastion health` to inspect the status of all internal subsystems:

```bash
bastion health
```

Example Output:
```text
B.A.S.T.I.O.N. Health
────────────────────────────
Service       : RUNNING
Telemetry     : HEALTHY
Detection     : HEALTHY
Threat Intel  : HEALTHY
Database      : HEALTHY
Firewall      : HEALTHY
Response      : AUTOMATIC
Last Event    : 2026-08-23 08:14:02 UTC
Uptime        : 04h 12m 30s
```

### JSON Health Output (for Nagios / Datadog / Prometheus / Scripts)
```bash
bastion health --json
```

---

## 3. Viewing Logs & Audit Trail

### systemd Journal
```bash
# View live service logs
sudo journalctl -u bastion.service -f

# Filter for lifecycle audit events
sudo journalctl -u bastion.service | grep -E "(SERVICE_START|FIREWALL_FAILURE|BAN_RESTORED)"
```

### Structured Audit Tags
- `[SERVICE_START]`: Service initialization and subsystem startup.
- `[SERVICE_STOP]`: Clean shutdown and lock releases.
- `[CONFIG_LOAD]`: Configuration parsing and validation.
- `[FIREWALL_FAILURE]`: Firewall backend communication issues.
- `[BAN_RESTORED]`: Active bans restored to `nftables` during startup or reconciliation.
- `[BAN_EXPIRED]`: Bans expired and removed from kernel packet filter sets.
- `[DEGRADED_MODE]`: Subsystem operational in degraded fail-safe state.
- `[RECOVERY]`: Subsystem restored to healthy state.

---

## 4. Operational Recovery & Troubleshooting

### Investigating a Degraded Firewall State
If `bastion health` reports `Firewall: DEGRADED`:
1. Check `nft` kernel module availability:
   ```bash
   sudo nft list tables
   ```
2. Verify table permissions and presence of `inet bastion`:
   ```bash
   sudo nft list table inet bastion
   ```
3. Run live firewall diagnostic:
   ```bash
   bastion firewall status
   ```

### Clearing Firewall State Manually
If you need to manually flush all isolated IP entries:
```bash
sudo bastion firewall flush
```

### Unbanning an Inadvertently Isolated Host
```bash
sudo bastion unban <IP_ADDRESS>
```
