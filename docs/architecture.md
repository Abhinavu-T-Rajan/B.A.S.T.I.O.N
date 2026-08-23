# B.A.S.T.I.O.N. System Architecture

**Behavioral Attack Surveillance & Threat Isolation Operating Network** (v0.3.0 "Sentinel Core")

> *"Sentinel sees. Aegis analyzes. Guardian protects. Oracle understands. Sentinel Core endures."*

---

## 1. High-Level Architecture

B.A.S.T.I.O.N. is organized as a persistent, service-oriented host defense platform. It combines a hardened systemd background daemon (`BastionDaemon`), thread-safe subsystem health tracking (`HealthTracker`), continuous telemetry collection, log normalization, multi-vector behavioral detection, local threat intelligence (IOCs), MITRE ATT&CK technique mapping, explainable risk scoring (0–100), incident lifecycle management, policy-driven defensive response, firewall rule reconciliation (`FirewallReconciler`), and tamper-evident audit persistence.

```
                         B.A.S.T.I.O.N. v0.3.0 (Sentinel Core)
                                           │
  ┌────────────────────────────────────────▼────────────────────────────────────────┐
  │                           systemd Service Layer                                 │
  │   • Unit file: bastion.service                                                  │
  │   • Security Hardening: CAP_NET_ADMIN, NoNewPrivileges=true, ProtectSystem=strict│
  │   • Lifecycle & Auto-Restart: Restart=on-failure with exponential backoff       │
  └────────────────────────────────────────┬────────────────────────────────────────┘
                                           │
  ┌────────────────────────────────────────▼────────────────────────────────────────┐
  │                         BastionDaemon Orchestrator                              │
  │   • Lifecycle States: STARTING -> INITIALIZING -> RUNNING -> STOPPING -> STOPPED│
  │   • Thread-safe HealthTracker: JSON snapshots & live diagnostic probes          │
  │   • Background Worker Thread: Expiration checks (5s), Rule Reconciler (60s)     │
  │   • Signal Management: SIGTERM, SIGINT, SIGHUP                                  │
  └────────────────────────────────────────┬────────────────────────────────────────┘
                                           │
  ┌────────────────────────────────────────▼────────────────────────────────────────┐
  │                              Telemetry Layer                                    │
  │   • systemd-journald streamer (JournalCollector) with collector retries         │
  │   • File stream & Standard Input (stdin) ingestion                              │
  └────────────────────────────────────────┬────────────────────────────────────────┘
                                           │ raw log string
  ┌────────────────────────────────────────▼────────────────────────────────────────┐
  │                          Log Normalization Layer                                │
  │   • OpenSSH Parser (SSHLogParser)                                               │
  │   • SecurityEvent model (timestamp, IP, user, event_type, metadata)             │
  └────────────────────────────────────────┬────────────────────────────────────────┘
                                           │ SecurityEvent
  ┌────────────────────────────────────────▼────────────────────────────────────────┐
  │                         Behavioral Detection Suite                              │
  │   • Brute-Force Detector (sliding-window threshold)                             │
  │   • Password Spray Detector (multi-account low-volume)                          │
  │   • Username Enumeration Detector (invalid user probing)                        │
  │   • Burst Velocity Detector (high-frequency spikes)                             │
  └────────────────────────────────────────┬────────────────────────────────────────┘
                                           │ list[DetectionResult]
  ┌────────────────────────────────────────▼────────────────────────────────────────┐
  │                     Threat Intelligence Subsystem (Oracle)                      │
  │   • IOC Validation & Provenance Tracking (IOCValidator)                         │
  │   • Active IOC Matching (IP, domain, hashes, usernames)                         │
  └────────────────────────────────────────┬────────────────────────────────────────┘
                                           │ matched IOCs
  ┌────────────────────────────────────────▼────────────────────────────────────────┐
  │                     Threat Intelligence & Risk Engine                           │
  │   • Multi-Signal 0–100 Scorer (RiskEngine)                                      │
  │   • Adaptive IOC Confidence Scoring                                             │
  │   • Offender profiling (ThreatActorProfile)                                     │
  └────────────────────────────────────────┬────────────────────────────────────────┘
                                           │ ThreatActorProfile
  ┌────────────────────────────────────────▼────────────────────────────────────────┐
  │                      Threat Correlation Engine (Oracle)                         │
  │   • MITRE ATT&CK Technique Mapping (AttackRegistry)                             │
  │   • Rolling Alert Deduplication Window (Anti-Flooding)                          │
  │   • Incident Clustering & State Tracking (IncidentManager)                      │
  └────────────────────────────────────────┬────────────────────────────────────────┘
                                           │ CorrelationContext
  ┌────────────────────────────────────────▼────────────────────────────────────────┐
  │                                Policy Engine                                    │
  │   • Subnet Protection & CIDR Allowlisting (PolicyEngine)                        │
  │   • Isolation threshold mapping & dynamic duration                              │
  └────────────────────────────────────────┬────────────────────────────────────────┘
                                           │ ResponseDecision
  ┌────────────────────────────────────────▼────────────────────────────────────────┐
  │                               Response Engine                                   │
  │   • Execution Modes: DRY_RUN, AUTOMATIC, MANUAL, DISABLED                       │
  │   • Ban Lifecycle State Machine (BanManager)                                    │
  │   • Startup Ban Restoration & Periodic FirewallReconciler                       │
  │   • Experimental Response & Audit Log (ResponseAuditRecord)                     │
  └────────────────────────────────────────┬────────────────────────────────────────┘
                                           │ block / unblock IP
  ┌────────────────────────────────────────▼────────────────────────────────────────┐
  │                              Firewall Backend                                   │
  │   • NFTablesBackend (dedicated 'inet bastion' table & timeout sets)             │
  │   • MockFirewallBackend (in-memory test / non-root)                             │
  └────────────────────────────────────────┬────────────────────────────────────────┘
                                           │
  ┌────────────────────────────────────────▼────────────────────────────────────────┐
  │                        Persistence & Audit Storage                              │
  │   • SQLite Database (WAL mode, thread-safe RLock)                               │
  │   • Schema Versioning (MigrationRunner: v1 -> v2)                               │
  │   • Tables: events, detections, threat_actors, score_history, bans, iocs,       │
  │     incidents, incident_events, incident_actors, incident_iocs, response_audits │
  └─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Subsystem Breakdown

### 2.1 Daemon Subsystem & Lifecycle (`src/bastion/daemon/`)
- **`BastionDaemon`**: Orchestrates the persistent service lifecycle. Initializes configuration validation, persistent storage, firewall sets, policy engine, ban manager, detection engines, risk engines, threat intel correlation, and telemetry collectors. Spawns background worker threads and manages OS signals (`SIGTERM`, `SIGINT`, `SIGHUP`).
- **`HealthTracker`**: Thread-safe monitor tracking subsystem statuses (`HEALTHY`, `DEGRADED`, `FAILED`, `UNKNOWN`), total events processed, detection counts, active ban counts, and uptime. Writes atomic JSON state files to `/var/lib/bastion/health.json` (or configured path) and supports on-demand CLI live diagnostic probing.
- **`FirewallReconciler`**: Bidirectional firewall reconciler that runs upon daemon startup and on a periodic schedule (default 60s). Restores active, unexpired database bans into kernel `nftables` sets with correct remaining TTL and cleans up expired rules.
- **`StructuredLogFormatter` & Audit Logging**: Emits ISO-8601 structured logs with machine-readable metadata and standardized lifecycle audit tags (`SERVICE_START`, `SERVICE_STOP`, `FIREWALL_FAILURE`, `BAN_RESTORED`, etc.), with automated credential redaction.

### 2.2 Telemetry Layer (`src/bastion/collector/`)
- **`JournalCollector`**: Executes non-blocking queries against `journalctl` targeting specific system units (`ssh.service`, `sshd.service`) or Syslog identifiers (`sshd`). Provides a generator-based `.follow()` method that streams real-time log entries line-by-line while managing subprocess lifecycles cleanly.
- **File / Stdin Ingestion**: Supports piping historical or simulated log streams via standard input (`--stdin`) or file scanning (`--file <path>`).

### 2.3 Normalization Layer (`src/bastion/models/events.py`, `src/bastion/collector/ssh.py`)
- **`SecurityEvent`**: Canonical, service-agnostic event model encapsulating `timestamp`, `source_ip`, `service` (`ServiceType.SSH`), `event_type` (`EventType.AUTH_FAILURE`, `AUTH_SUCCESS`, `INVALID_USER`, `MAX_ATTEMPTS_EXCEEDED`, `CONNECTION`, `UNKNOWN`), optional `username`, and arbitrary `metadata`.
- **`SSHLogParser`**: Regex parsing engine extracting IPv4/IPv6 addresses, standard PAM and OpenSSH failure notices, invalid user probing, public key authentication, password authentication, and connection preauth terminations across ISO8601 and Syslog timestamp formats.

### 2.4 Behavioral Detection Suite (`src/bastion/detection/`)
- **`BruteForceDetector`**: Tracks failed attempts against a specific IP within a sliding time window (default: 10 attempts in 60s). Expired events are automatically evicted via a double-ended queue (`deque`).
- **`PasswordSprayDetector`**: Identifies distributed account spraying where an IP attempts passwords against $\ge 3$ distinct accounts while keeping per-user attempt rates low ($\le 3$ attempts/user).
- **`UsernameEnumerationDetector`**: Flags rapid invalid-user probing ($\ge 4$ invalid usernames in 60s).
- **`BurstDetector`**: Detects high-velocity brute-force automation spikes ($\ge 5$ requests in 5 seconds).

### 2.5 Threat Intelligence Subsystem (`src/bastion/intelligence/`)
- **`IOCValidator`**: Strict RFC/format validation and normalization for `IP`, `DOMAIN`, `HASH_MD5`, `HASH_SHA1`, `HASH_SHA256`, and `USERNAME`.
- **`IOCManager`**: Manages CRUD operations, search, and real-time security event correlation with provenance tracking (`OBSERVED`, `INFERRED`, `CONFIGURED`, `CONFIRMED`, `UNKNOWN`).

### 2.6 Explainable Risk Engine (`src/bastion/risk/`)
- **`RiskEngine`**: Multi-signal scoring algorithm evaluating base auth failures (+10 pts), invalid user attempts (+20 pts), detector activations (+25 to +40 pts), and IOC matches (+15 to +30 pts), with decay and success credits.
- **`ThreatActorProfile`**: State tracking for threat actors across lifecycle states (`NEUTRAL`, `PROBING`, `SUSPICIOUS`, `ACTIVE_THREAT`, `ISOLATED`).

### 2.7 Threat Correlation Engine (`src/bastion/correlation/`)
- **`CorrelationEngine`**: Aggregates multi-detector signals, IOC matches, and actor risk state into unified `CorrelationContext`.
- **Alert Deduplication**: Configurable time-window cache preventing redundant alert output while maintaining full event telemetry.
- **`IncidentManager`**: Complete lifecycle management for security incidents (`OPEN`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`, `CLOSED`).
- **`TimelineGenerator`**: Unified chronological forensic timeline generator across events, detections, risk score adjustments, bans, and response actions.

### 2.8 Defensive Policy & Response Engine (`src/bastion/response/`, `src/bastion/firewall/`)
- **`PolicyEngine`**: Evaluates allowlists (`127.0.0.0/8`, `::1/128`, RFC 1918 subnets) and determines action thresholds (`TEMPORARY_ISOLATION`, `RATE_LIMIT`, `PERMANENT_BAN`).
- **`BanManager`**: Manages SQLite ban state transitions, startup synchronization, and automatic expiration polling.
- **`NFTablesBackend`**: Native Linux packet filtering utilizing isolated `table inet bastion` with kernel timeout sets.
- **`MockFirewallBackend`**: In-memory firewall backend for unit testing and non-root environments.

### 2.9 Storage & Persistence (`src/bastion/storage/`)
- **`SQLiteStorage`**: Thread-safe repository managing all tables in WAL mode.
- **`MigrationRunner`**: Automated schema migrations tracking versions in `schema_version`.
