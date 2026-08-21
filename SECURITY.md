# Security Policy

## Supported Versions

B.A.S.T.I.O.N. is an active open-source Linux security project. Security updates and bug fixes are applied to the latest minor version of the current release line.

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1.0 | :x:                |

---

## Reporting a Vulnerability

We take the security of B.A.S.T.I.O.N. and the hosts it protects seriously. If you discover a security vulnerability, please follow responsible disclosure guidelines and notify the maintainers privately.

### Preferred Reporting Method

1. **GitHub Security Advisories**: If available on the repository, submit a confidential report via **GitHub Private Vulnerability Reporting** (`Security` tab -> `Report a vulnerability`).
2. **Email Disclosure**: If private vulnerability reporting is unavailable, send an encrypted report to:
   - `[SECURITY_CONTACT_EMAIL_PLACEHOLDER]` *(Maintainer Contact)*

> [!CAUTION]
> **Do not report security vulnerabilities through public GitHub issues, pull requests, discussions, or public chat channels.** Publicly disclosing an unpatched vulnerability puts protected systems at risk.

---

## What to Include in a Report

To help us investigate and remediate the issue efficiently, please provide:

1. **Vulnerability Summary**: A clear description of the vulnerability, its category (e.g., Denial of Service, Parser Bypass, Privilege Escalation, Command Injection), and potential impact.
2. **Component Affected**: Specific module, function, or CLI command (e.g., `src/bastion/collector/ssh.py`, `src/bastion/firewall/nftables.py`, `src/bastion/storage/sqlite.py`).
3. **Step-by-Step Reproduction**: Detailed steps, sample log lines, or minimal proof-of-concept code to reliably reproduce the issue.
4. **Environment Details**: Linux distribution, kernel version, Python version, OpenSSH version, and firewall configuration (`nftables` / `iptables`).
5. **Mitigation Suggestion**: Any proposed patch or workaround, if available.

### What NOT to Include

- **No Real Credentials**: Do not include actual passwords, private SSH keys, production tokens, or sensitive user data in logs or reproduction steps. Use sanitized dummy values (e.g., `198.51.100.23`, `user=test`).
- **No Unsolicited Active Exploitation**: Do not attempt to exploit production or third-party systems. Conduct testing solely on local, isolated lab environments.

---

## Scope

### In Scope

- **Log Parsing Engine**: ReDoS, memory exhaustion, injection, or evasion bugs in OpenSSH log parsing (`SSHLogParser`).
- **Firewall Integration**: Unintended host rule modifications, firewall command injection, or privilege boundary violations in `NFTablesBackend`.
- **State Machine & Storage**: SQL injection, database corruption, or state desynchronization in `SQLiteStorage` and `BanManager`.
- **Policy & Allowlist Evasion**: Circumvention of CIDR allowlist safeguards leading to administrator lockout or false-positive isolation.
- **Denial of Service**: Uncontrolled resource consumption in streaming generators (`JournalCollector`, `SentinelPipeline`).

### Out of Scope

- Vulnerabilities in upstream operating system components (e.g., Linux kernel, `systemd`, `nftables` binary, OpenSSH server) unless directly triggered by misuse in B.A.S.T.I.O.N.
- Physical access attacks or attacks requiring pre-existing `root` access to the host.
- Social engineering attacks against maintainers or contributors.

---

## Disclosure and Resolution Process

1. **Acknowledgment**: Maintainers will acknowledge receipt of the report within **48 hours**.
2. **Assessment & Triage**: Maintainers will reproduce the issue, determine severity, and coordinate on an impact assessment within **5 business days**.
3. **Remediation**: A fix will be developed and tested in a private branch.
4. **Release & Advisory**: A patched release will be published alongside a GitHub Security Advisory detailing the issue, CVE identifier (if applicable), and remediation guidance.
5. **Credit**: Security researchers who practice responsible disclosure will be credited in the release notes and advisory (unless anonymity is requested).
