# Threat Model & Security Architecture

This document provides a threat model for **B.A.S.T.I.O.N.** (v0.1.3 "Guardian"), assessing security risks against both the protected Linux host and the B.A.S.T.I.O.N. software itself.

---

## 1. Trust Boundaries & Assets

### Protected Assets
1. **Host Availability & Network Reachability**: Ensuring legitimate administrator and user traffic is never improperly blocked.
2. **Authentication Subsystem Integrity**: Safeguarding OpenSSH and Linux host credentials against automated compromise.
3. **Firewall Rule Consistency**: Preserving kernel packet filtering rules without state desynchronization or unintended policy wipes.
4. **Auditability & Threat Intelligence Data**: Maintaining an accurate, tamper-resistant history of security events, offender scores, and ban records.

### Threat Actors
- **External Network Attackers**: Unauthorized entities probing exposed SSH ports using automated brute-force tools, password spraying scripts, and credential stuffing lists.
- **Malicious Remote Probers**: Entities attempting to exploit log parser vulnerabilities, trigger ReDoS, or induce Denial-of-Service (DoS) via log flooding.
- **Compromised Local Users**: Unprivileged local users on the host attempting to manipulate local logs, tamper with the SQLite database, or abuse CLI commands.

---

## 2. Threat Analysis & Mitigations

### 2.1 Malicious Log Input & Parser Exploitation

| Threat | Description | Implemented Mitigation | Unimplemented / Future Controls |
| :--- | :--- | :--- | :--- |
| **ReDoS (Regex Denial of Service)** | Attacker sends crafted SSH banner or username payloads designed to trigger catastrophic backtracking in regex parsers. | Regular expressions in `SSHLogParser` are strictly anchored with non-backtracking patterns and length constraints. | Log input length truncation before regex execution is not explicitly enforced. |
| **Log Injection / Format String Abuse** | Attacker inserts newline (`\n`), ANSI escape codes, or control characters in username fields to falsify log entries. | Events are parsed line-by-line using `strip()`. Extracted fields are stored as typed Python objects and sanitized in terminal alert formatters. | Terminal ANSI escape character sanitization on raw username strings is not yet strictly filtered. |
| **IP Address Spoofing / Malformed IPs** | Attacker injects non-standard IP formats or hostnames to crash the pipeline. | All extracted IP strings are validated through Python's standard `ipaddress.ip_address` library in `NFTablesBackend` and `PolicyEngine`. Invalid IP strings fail gracefully. | Upstream TCP connection state verification (e.g. syn-proxy) is outside B.A.S.T.I.O.N.'s scope. |

---

### 2.2 False Positives & Administrator Lockout

| Threat | Description | Implemented Mitigation | Unimplemented / Future Controls |
| :--- | :--- | :--- | :--- |
| **Accidental Lockout of Local Host / Admin** | High authentication failures from a legitimate management workstation trigger automatic kernel-level isolation. | **Mandatory CIDR Allowlisting**: `PolicyEngine` evaluates `ipaddress.ip_network` against configured subnets (`127.0.0.0/8`, `::1/128`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`). Any matching IP is permanently exempt from isolation. | Dynamic administrator IP detection (e.g., auto-detecting current active SSH session IP) is not yet implemented. |
| **False-Positive Threshold Triggering** | A legitimate user mistypes their password a few times and gets permanently banned. | **Explainable Multi-Signal Scoring**: A single failure only adds +5 points (low severity). A score of $\ge 85$ requires compounding behavioral signals (e.g. spray + enumeration + burst). Furthermore, temporary isolation defaults to 15 minutes, not permanent blocking. | Operator-specific notification webhooks prior to isolation are not yet implemented. |
| **Dry-Run Default Safety** | Accidental deployment of active blocking before tuning detector thresholds. | **Safe Default Execution**: B.A.S.T.I.O.N. defaults to `ResponseMode.DRY_RUN` in both configuration and CLI. Automated packet dropping requires explicit `--enforce` or setting `mode = "automatic"`. | N/A (Feature complete). |

---

### 2.3 Firewall Backend & State Desynchronization

| Threat | Description | Implemented Mitigation | Unimplemented / Future Controls |
| :--- | :--- | :--- | :--- |
| **Host Firewall Rule Collisions** | B.A.S.T.I.O.N. flushes or overwrites existing `iptables` / `nftables` rules configured by the host administrator or Docker. | **Dedicated Table Namespace**: `NFTablesBackend` operates exclusively inside `table inet bastion`. All drop rules and timeout sets are encapsulated in this table and never touch system chains. | Legacy `iptables-legacy` fallback adapter is not yet implemented. |
| **Firewall State Desynchronization on Crash** | B.A.S.T.I.O.N. crashes while an IP is isolated; upon restart, the daemon is unaware of active firewall bans. | **Fail-Safe Startup Synchronization**: `BanManager.sync_on_startup()` queries SQLite for active, unexpired bans and re-inserts them into the firewall backend with updated remaining timeout values upon daemon startup. | Kernel-to-database bidirectional reconciliation loop (detecting out-of-band manual `nft delete` commands) is not yet implemented. |
| **Unbounded Ban Accumulation (Memory Leak)** | Host kernel firewall sets fill up with thousands of stale blocked IPs, degrading packet filtering performance. | **Native NFTables Timeouts & Auto-Expiry**: `NFTablesBackend` creates sets with `flags timeout;`, allowing the Linux kernel to automatically evict expired elements. In addition, `BanManager.check_expirations()` actively cleans database states. | Periodic garbage collection of old historical SQLite rows is not yet implemented. |
| **Command Injection in Firewall Subprocess** | Attacker injects shell metacharacters (`|`, `;`, `&&`) into source IP or duration fields to execute arbitrary commands as root. | **Parameterized Argument Execution**: `NFTablesBackend` invokes `subprocess.run(["nft", ...])` passing arguments as a sequence of strings (`shell=False`). No shell interpolation is performed. | N/A (Feature complete). |

---

### 2.4 Persistence, Privilege & Host Security

| Threat | Description | Implemented Mitigation | Unimplemented / Future Controls |
| :--- | :--- | :--- | :--- |
| **SQL Injection in Database Queries** | Malicious username or IP input alters SQLite queries to dump or corrupt data. | All database queries in `SQLiteStorage` use parameterized parameter substitution (`?`). String interpolation in SQL statements is strictly prohibited. | N/A (Feature complete). |
| **Database File Permissions & Tampering** | An unprivileged local user modifies `bastion.db` to unban malicious IPs or tamper with threat scores. | SQLite database file is stored in user/system data directories (`~/.local/share/bastion/` or `/var/lib/bastion/`). | Explicit file permission hardening (`0600`) at database creation time is not yet strictly enforced. |
| **Privilege Escalation** | B.A.S.T.I.O.N. runs as `root` to execute `nft`, exposing the entire system if a parser bug occurs. | B.A.S.T.I.O.N. separates telemetry collection from firewall manipulation. It can run in unprivileged dry-run mode (`MockFirewallBackend`) without root privileges. | Linux capability isolation (`CAP_NET_ADMIN` without full root) and systemd sandbox sandboxing (`ProtectSystem=strict`, `DynamicUser=yes`) are planned for v0.2.0. |
| **Database Concurrency & Race Conditions** | Concurrent access from background streaming and CLI query commands causes SQLite database locks or corruption. | `SQLiteStorage` enables Write-Ahead Logging (`PRAGMA journal_mode=WAL;`) and enforces a reentrant mutex lock (`threading.RLock`) on all database operations. | N/A (Feature complete). |

---

## 3. Residual Risks & Future Hardening

1. **Privilege Separation (v0.2.0)**: Transition from monolithic root execution to a split-privilege architecture where log parsing runs as an unprivileged service user and firewall manipulations run through a restricted helper or systemd capability assignment.
2. **Log Flooding DoS**: While sliding windows evict old entries, high-velocity log flooding ($> 10,000$ events/sec) could increase CPU utilization. Future releases will introduce ingestion rate limiting and queue bounding.
3. **Distributed Coordination (v0.3.0)**: Currently, threat actor state is host-local. A coordinated attack across 50 servers requires multi-node synchronization, planned for future enterprise milestones.
