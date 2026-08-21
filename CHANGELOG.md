# Changelog

All notable changes to the **B.A.S.T.I.O.N.** project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Planned
- **Systemd Daemon Service**: Native background service unit file and daemonized runner.
- **Notification Webhooks**: Outbound alert dispatchers for Slack, Discord, and generic webhooks.
- **Distributed Telemetry**: Multi-node agent-server log shipping and aggregated intelligence.
- **REST / Web API**: Read-only threat telemetry inspection API.

---

## [0.2.0-alpha] — Oracle (2026-08-21)

> *"Sentinel sees. Aegis analyzes. Guardian protects. Oracle understands."*

### Added
- **Threat Intelligence & IOC Subsystem**:
  - `IOCType`: Format validation and support for `IP`, `DOMAIN`, `HASH_MD5`, `HASH_SHA1`, `HASH_SHA256`, and `USERNAME`.
  - `IOCValidator`: RFC-compliant syntax checking and normalization.
  - `IOCManager`: Full CRUD operations, free-text and tag search, and real-time security event matching.
  - Provenance tracking: `OBSERVED`, `INFERRED`, `CONFIGURED`, `CONFIRMED`, and `UNKNOWN`.
- **Threat Correlation Engine (`CorrelationEngine`)**:
  - Unifies multi-detector signals, IOC matches, actor profile state, and incident generation.
  - Rolling time-window alert deduplication (configurable window, default 30s) preventing alert flooding while preserving telemetry.
  - Automatic incident clustering for high and critical threats.
- **MITRE ATT&CK Mapping & Catalog (`AttackRegistry`)**:
  - Standardized ATT&CK technique model (`AttackTechnique`, `AttackTactic`, `AttackMapping`).
  - Catalog of authentic techniques: `T1110.001` (Password Guessing), `T1110.003` (Password Spraying), `T1087.001` (Local Account Discovery), `T1499` (Endpoint DoS), `T1078` (Valid Accounts).
  - Multi-detector technique resolver.
- **Incident Lifecycle Management (`IncidentManager`)**:
  - Incident data model supporting statuses: `OPEN`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`, and `CLOSED`.
  - Many-to-many relationship join tables linking incidents to events, actors, and IOCs.
  - Full querying, status transitioning, and active incident correlation.
- **Investigation Timeline Generator (`TimelineGenerator`)**:
  - Chronological forensic timeline reconstruction across security events, detector signals, risk score adjustments, defensive bans, response audits, and incident lifecycle transitions.
- **Experimental Response Framework & Auditing (`ExperimentalResponseCoordinator`)**:
  - Isolated response layer with target validation, explicit invocation, and safety dry-run capability.
  - Tamper-evident `ResponseAuditRecord` persistence in `response_audits` SQLite table.
- **SQLite Database Migrations (`MigrationRunner`)**:
  - Schema version tracking (`schema_version` table) and transactional migration upgrades from v1 baseline to v2 Oracle schema.
- **CLI Commands**:
  - `bastion incident [list|inspect|update|create]`: Full incident lifecycle management.
  - `bastion ioc [add|list|search|delete]`: Threat intelligence IOC management.
  - `bastion timeline [--ip <IP> | --incident <ID>]`: Investigation timeline generation.
  - `bastion attack [technique_id]`: MITRE ATT&CK technique catalog inspection.

---

## [0.1.3] — Guardian (2026-08-21)

### Added
- **Firewall Abstraction Layer**:
  - `FirewallBackend` abstract base class for host packet filtering and containment.
  - `NFTablesBackend`: Native Linux `nftables` integration utilizing dedicated `table inet bastion` with `blacklist_v4` and `blacklist_v6` timeout sets and early drop hooks, guaranteeing zero interference with existing host firewall rules.
  - `MockFirewallBackend`: In-memory backend for deterministic testing, dry-runs, and non-root development.
- **Policy Engine (`PolicyEngine`)**:
  - CIDR subnet allowlisting via `ipaddress.ip_network` protecting localhost (`127.0.0.0/8`, `::1/128`) and management subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) from accidental lockout.
  - Dynamic score-to-action threshold mapping (`TEMPORARY_ISOLATION` $\ge 85$, `RATE_LIMIT` $\ge 60$, `PERMANENT_BAN` at 100 with persistent failure history).
  - Dynamic duration calculations (default 15m, 1h for repeat offenders, clamped to 24h max).
- **Ban Lifecycle Manager (`BanManager`)**:
  - Offender state machine transitions (`NEUTRAL` $\rightarrow$ `PROBING` $\rightarrow$ `SUSPICIOUS` $\rightarrow$ `ACTIVE_THREAT` $\rightarrow$ `ISOLATED` $\rightarrow$ `EXPIRED` / `RELEASED`).
  - SQLite persistence in `bans` table (`ban_id`, `source_ip`, `reason`, `threat_score`, `created_at`, `expires_at`, `action`, `status`, `metadata`).
  - Automatic expiration polling (`check_expirations`) and startup rule restoration (`sync_on_startup`).
- **Response Engine (`ResponseEngine`)**:
  - Supported execution modes: `DRY_RUN` (default), `AUTOMATIC`, `MANUAL_APPROVAL`, and `DISABLED`.
- **CLI Commands**:
  - `bastion bans [--all]`: Lists active or historical bans.
  - `bastion ban <IP>`: Operator manual isolation command with `--duration`, `--permanent`, and `--reason` flags.
  - `bastion unban <IP>`: Operator manual ban release and firewall rule removal.
  - `bastion firewall status` and `bastion firewall flush`: Firewall table inspection and blacklist flush.
  - `bastion monitor`: Added `--dry-run`, `--enforce`, and `--mode` options.
- **Licensing**:
  - Adopted Apache License 2.0.

---

## [0.1.2] — Aegis (2026-08-21)

### Added
- **Behavioral Detection Suite**:
  - `PasswordSprayDetector`: Detects single IPs probing multiple distinct usernames with low attempt counts.
  - `UsernameEnumerationDetector`: Detects rapid probing targeting invalid or non-existent user accounts.
  - `BurstDetector`: Detects high-frequency authentication bursts ($\ge 5$ attempts in 5 seconds).
  - `DetectionEngine`: Unified coordinator evaluating all behavioral detectors concurrently.
- **Explainable Threat Risk Engine (`RiskEngine`)**:
  - Multi-signal 0–100 threat scoring formula combining base failures, invalid user probing, detector activations, velocity spikes, and repeat offender history.
  - Transparent `ScoreFactor` logging for full auditability.
  - Severity classifications: `LOW` (0–39), `MEDIUM` (40–69), `HIGH` (70–84), `CRITICAL` (85–100).
  - Data model `ThreatActorProfile` tracking forensic history, targeted accounts, and services.
- **Persistent SQLite Storage (`SQLiteStorage`)**:
  - Thread-safe repository managing `events`, `detections`, `threat_actors`, and `score_history` tables with WAL mode and indices.
- **Configuration System (`BastionConfig`)**:
  - TOML-based configuration file (`bastion.toml`) with support for custom database paths, detector settings, and scoring weights.
- **CLI Commands**:
  - `bastion threats`: Offender risk rankings.
  - `bastion inspect <IP>`: Forensic timeline, score factors, and recent events.
  - `bastion events`: Telemetry log query tool.
  - `bastion stats`: Aggregated intelligence summary.
  - `bastion config show`: Active configuration inspector.

---

## [0.1.1] — Sentinel (2026-08-21)

### Added
- **Journal Collector (`JournalCollector`)**:
  - `systemd-journald` streaming reader and live follower (`follow()`) for `ssh.service` and `sshd.service`.
- **OpenSSH Parser (`SSHLogParser`)**:
  - Robust regex parser for OpenSSH log formats (password failures, accepted public keys/passwords, invalid users, connection closed preauth, max attempts exceeded, IPv4/IPv6).
- **Sentinel Pipeline (`SentinelPipeline`)**:
  - Real-time event streaming pipeline connecting telemetry ingestion, normalization, detection, and explainable alerting.
- **CLI Commands**:
  - `bastion monitor`: Live streaming console for SSH telemetry.
  - `bastion parse`: Tool to test and inspect raw log line parsing.

---

## [0.1.0] — Foundation (2026-08-21)

### Added
- Initial project architecture and directory structure.
- Python package setup with `pyproject.toml` and editable install support (`pip install -e .`).
- Technology-agnostic `SecurityEvent` normalization model.
- Sliding-window `BruteForceDetector` with time-decay expiration.
- Initial CLI interface with `bastion status`, `bastion test-detection`, and `bastion --version`.
- Comprehensive initial unit test suite.
