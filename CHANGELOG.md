# Changelog

All notable changes to the **B.A.S.T.I.O.N.** project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Planned
- **Notification Webhooks**: Outbound alert dispatchers for Slack, Discord, and generic webhooks.
- **Distributed Telemetry**: Multi-node agent-server log shipping and aggregated intelligence.
- **REST / Web API**: Read-only threat telemetry inspection API.

---

## [0.3.1] — Sentinel Core Hotfix (2026-08-23)

> *"Reliability in the breach. Precision in defense."*

### Fixed
- **OpenSSH `sshd-session` & Syslog Parsing**:
  - Enhanced `SSHLogParser` prefix matching to capture modern OpenSSH session logs (`sshd-session[PID]: ...`, `sshd-auth[PID]: ...`) and syslog/ISO timestamps.
  - Updated `PAM_AUTH_FAILURE_RE` to match `pam_unix(sshd-session:auth)` events.
- **Journal Collector Unit & Multi-Identifier Streaming**:
  - Configured `JournalCollector` to accept multiple identifiers (`["sshd", "sshd-session"]`) and default to service unit filtering (`ssh.service`, `sshd.service`), preventing dropped modern SSH telemetry or duplicate queries.
- **CLI Stdin Stream & Event Output**:
  - Resolved `monitor --stdin` regression by streaming every normalized `SecurityEvent` to stdout in real-time while formatting box alerts when threat scoring thresholds are exceeded.
- **Idempotent NFTables Table & Chain Initialization**:
  - Fixed `NFTablesBackend.initialize()` to safely inspect existing table, chain, and set definitions in `table inet bastion`.
  - Reuses compatible chains without throwing declaration conflict errors; incrementally adds missing sets or drop rules; safely rejects incompatible external chains with descriptive errors without deleting unrelated firewall tables.
- **Daemon Graceful Shutdown & Subprocess Reaping**:
  - Implemented `JournalCollector.stop()` to cleanly terminate and wait for child `journalctl` processes upon receiving `SIGTERM` / `SIGINT`.
  - Unblocks streaming loops immediately, terminating cleanly within systemd stop timeouts without requiring `SIGKILL`.
- **Fail-Safe Response Enforcement & Real Dependency Health**:
  - When `response.mode = automatic` is configured but the firewall backend is unavailable or fails, `ResponseEngine` refuses enforcement, logs `RESPONSE_FAILED`, marks ban records `FAILED`, and transitions health state to `DEGRADED` / `FAILED`.
  - `HealthTracker.calculate_overall_health()` and CLI diagnostics accurately reflect firewall and dependency states, preventing false `Service: HEALTHY` reporting when critical subsystems are down.

---

## [0.3.0] — Sentinel Core (2026-08-23)

> *"Sentinel sees. Aegis analyzes. Guardian protects. Oracle understands. Sentinel Core endures."*

### Added
- **Persistent Daemon Architecture (`src/bastion/daemon/`)**:
  - `BastionDaemon`: Autonomous, long-running service orchestrator managing storage, telemetry ingestion, detection engine, risk engine, correlation engine, policy engine, ban manager, health tracking, and maintenance background workers.
  - Background maintenance thread: Non-blocking periodic worker handling automated ban expiration polling (5s), firewall state reconciliation (default 60s), and atomic health snapshot dumping (default 30s).
  - Graceful lifecycle management: Controlled transitions across `STARTING` $\rightarrow$ `INITIALIZING` $\rightarrow$ `RUNNING` $\rightarrow$ `STOPPING` $\rightarrow$ `STOPPED`, handling OS signals `SIGTERM`, `SIGINT`, and `SIGHUP`.
- **Official systemd Integration (`bastion.service`)**:
  - Production systemd unit file with security hardening and least-privilege sandboxing:
    - Minimal Linux capabilities (`CAP_NET_ADMIN` for packet filtering).
    - Hardened runtime boundaries: `NoNewPrivileges=true`, `ProtectSystem=strict`, `ProtectHome=read-only`, `PrivateTmp=true`, `ProtectKernelTunables=true`, `ProtectControlGroups=true`, `RestrictSUIDSGID=true`.
    - Dedicated state directory `/var/lib/bastion` with automatic ownership management.
    - Automated recovery with `Restart=on-failure` and exponential backoff restart rate limiting.
- **Subsystem Health Monitoring & Diagnostics (`HealthTracker`)**:
  - Thread-safe operational health tracker monitoring 7 core subsystems: `Service`, `Telemetry`, `Detection`, `Threat Intel`, `Database`, `Firewall`, and `Response`.
  - Atomic JSON health snapshot persistence (`/var/lib/bastion/health.json` or `~/.local/share/bastion/health.json`).
  - Diagnostic probing capability evaluating subsystems even when the background daemon is not running.
- **Configuration Validation & Versioning**:
  - Schema versioning with `config_version = 1` distinguishing configuration file syntax from software and database migration versions.
  - `validate_config` and `validate_config_strict` validators checking parameter bounds, positive detector thresholds, strictly increasing risk severity tiers, CIDR allowlist syntax, and ban duration hierarchies.
- **Firewall State Reconciliation & Startup Ban Restoration (`FirewallReconciler`)**:
  - Automatic synchronization and restoration of unexpired database bans into kernel firewall sets upon daemon startup.
  - Periodic bidirectional reconciliation comparing SQLite active bans against live kernel packet filter rules, cleaning expired rules and restoring missing kernel elements with correct remaining TTL.
  - Resilience against firewall transient unavailability.
- **Structured Logging & Audit Logging**:
  - Standardized structured log formatter with ISO-8601 timestamps, log levels, and auditable event tags (`SERVICE_START`, `SERVICE_STOP`, `CONFIG_LOAD`, `CONFIG_ERROR`, `COLLECTOR_FAILURE`, `DATABASE_FAILURE`, `FIREWALL_FAILURE`, `BAN_RESTORED`, `BAN_EXPIRED`, `RESPONSE_EXECUTED`, `RESPONSE_FAILED`, `DEGRADED_MODE`, `RECOVERY`).
  - Automatic credential and sensitive token redaction (`sanitize_log_message`).
- **New & Enhanced CLI Commands**:
  - `bastion daemon` (aliases: `service`, `run`): Starts the persistent Sentinel Core daemon.
  - `bastion health [--json]`: Inspects operational health diagnostics and error metrics.
  - `bastion config validate`: Verifies syntax and configuration constraints with detailed error reporting.
  - `bastion status`: Displays daemon runtime status and Sentinel Core system details.
- **Comprehensive Documentation Suite**:
  - Added `DEVELOPMENT.md`, `docs/development/setup.md`, `docs/development/testing.md`, `docs/operations/installation.md`, `docs/operations/service-management.md`, and `docs/operations/configuration.md`.

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
  - Robust regex parser for OpenSSH log formats (password failures, accepted public keys/passwords, invalid users, connection drops, and max attempt violations across IPv4 and IPv6).
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
