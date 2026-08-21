# B.A.S.T.I.O.N. System Architecture

**Behavioral Attack Surveillance & Threat Isolation Operating Network** (v0.2.0-alpha "Oracle")

> *"Sentinel sees. Aegis analyzes. Guardian protects. Oracle understands."*

---

## 1. High-Level Architecture

B.A.S.T.I.O.N. is organized as a decoupled, multi-stage processing pipeline that ingests raw authentication telemetry from Linux host services, normalizes log events into structured abstractions, executes concurrent behavioral detection heuristics, correlates threat intelligence indicators (IOCs), maps observed techniques to the MITRE ATT&CK framework, calculates explainable threat scores (0–100), manages incident lifecycles, and enforces host-level packet filtering via Linux `nftables`.

```
  ┌─────────────────────────────────────────────────────────────┐
  │                    Telemetry Ingestion                      │
  │   • systemd-journald streamer (JournalCollector)            │
  │   • Standard input (sys.stdin) / Local log files            │
  └──────────────────────────────┬──────────────────────────────┘
                                 │ raw log string
  ┌──────────────────────────────▼──────────────────────────────┐
  │                  Log Normalization Layer                    │
  │   • OpenSSH Parser (SSHLogParser)                           │
  │   • SecurityEvent model (timestamp, IP, user, event_type)   │
  └──────────────────────────────┬──────────────────────────────┘
                                 │ SecurityEvent
  ┌──────────────────────────────▼──────────────────────────────┐
  │                 Behavioral Detection Suite                  │
  │   • Brute-Force Detector (sliding-window threshold)         │
  │   • Password Spray Detector (multi-account low-volume)      │
  │   • Username Enumeration Detector (invalid user probing)    │
  │   • Burst Velocity Detector (high-frequency spikes)         │
  └──────────────────────────────┬──────────────────────────────┘
                                 │ list[DetectionResult]
  ┌──────────────────────────────▼──────────────────────────────┐
  │             Threat Intelligence Subsystem (Oracle)          │
  │   • IOC Validation & Provenance Tracking (IOCValidator)     │
  │   • Active IOC Matching (IP, domain, hashes, usernames)     │
  └──────────────────────────────┬──────────────────────────────┘
                                 │ matched IOCs
  ┌──────────────────────────────▼──────────────────────────────┐
  │             Threat Intelligence & Risk Engine               │
  │   • Multi-Signal 0–100 Scorer (RiskEngine)                  │
  │   • Adaptive IOC Confidence Scoring                         │
  │   • Offender profiling (ThreatActorProfile)                 │
  └──────────────────────────────┬──────────────────────────────┘
                                 │ ThreatActorProfile
  ┌──────────────────────────────▼──────────────────────────────┐
  │              Threat Correlation Engine (Oracle)             │
  │   • MITRE ATT&CK Technique Mapping (AttackRegistry)         │
  │   • Rolling Alert Deduplication Window (Anti-Flooding)      │
  │   • Incident Clustering & State Tracking (IncidentManager)  │
  └──────────────────────────────┬──────────────────────────────┘
                                 │ CorrelationContext
  ┌──────────────────────────────▼──────────────────────────────┐
  │                        Policy Engine                        │
  │   • Subnet Protection & CIDR Allowlisting (PolicyEngine)    │
  │   • Isolation threshold mapping & dynamic duration          │
  └──────────────────────────────┬──────────────────────────────┘
                                 │ ResponseDecision
  ┌──────────────────────────────▼──────────────────────────────┐
  │                       Response Engine                       │
  │   • Execution Modes: DRY_RUN, AUTOMATIC, MANUAL, DISABLED   │
  │   • Ban Lifecycle State Machine (BanManager)                │
  │   • Experimental Response & Audit Log (ResponseAuditRecord) │
  └──────────────────────────────┬──────────────────────────────┘
                                 │ block / unblock IP
  ┌──────────────────────────────▼──────────────────────────────┐
  │                      Firewall Backend                       │
  │   • NFTablesBackend (dedicated 'inet bastion' table)        │
  │   • MockFirewallBackend (in-memory test / non-root)         │
  └──────────────────────────────┬──────────────────────────────┘
                                 │
  ┌──────────────────────────────▼──────────────────────────────┐
  │                Persistence & Audit Storage                  │
  │   • SQLite Database (WAL mode, thread-safe RLock)           │
  │   • Schema Versioning (MigrationRunner: v1 -> v2)           │
  │   • Tables: events, detections, threat_actors,              │
  │     score_history, bans, iocs, incidents, incident_events,  │
  │     incident_actors, incident_iocs, timeline_entries,       │
  │     response_audits                                         │
  └─────────────────────────────────────────────────────────────┘
```

---

## 2. Subsystem Breakdown

### 2.1 Telemetry Layer (`src/bastion/collector/`)
- **`JournalCollector`**: Executes non-blocking queries against `journalctl` targeting specific system units (`ssh.service`, `sshd.service`) or Syslog identifiers (`sshd`). Provides a generator-based `.follow()` method that streams real-time log entries line-by-line while managing subprocess lifecycles cleanly.
- **File / Stdin Ingestion**: Supports piping historical or simulated log streams via standard input (`--stdin`) or file scanning (`--file <path>`).

### 2.2 Normalization Layer (`src/bastion/models/events.py`, `src/bastion/collector/ssh.py`)
- **`SecurityEvent`**: Canonical, service-agnostic event model encapsulating `timestamp`, `source_ip`, `service` (`ServiceType.SSH`), `event_type` (`EventType.AUTH_FAILURE`, `AUTH_SUCCESS`, `INVALID_USER`, `MAX_ATTEMPTS_EXCEEDED`, `CONNECTION`, `UNKNOWN`), optional `username`, and arbitrary `metadata`.
- **`SSHLogParser`**: Regex parsing engine extracting IPv4/IPv6 addresses, standard PAM and OpenSSH failure notices, invalid user probing, public key authentication, password authentication, and connection preauth terminations across ISO8601 and Syslog timestamp formats.

### 2.3 Behavioral Detection Suite (`src/bastion/detection/`)
- **`BruteForceDetector`**: Tracks failed attempts against a specific IP within a sliding time window (default: 10 attempts in 60s). Expired events are automatically evicted via a double-ended queue (`deque`).
- **`PasswordSprayDetector`**: Identifies distributed account spraying where an IP attempts passwords against $\ge 3$ distinct accounts while keeping per-user attempt rates low ($\le 3$ attempts/user).
- **`UsernameEnumerationDetector`**: Flags rapid invalid-user probing ($\ge 4$ invalid usernames in 60s).
- **`BurstDetector`**: Detects high-velocity brute-force automation spikes ($\ge 5$ requests in 5 seconds).
- **`DetectionEngine`**: Concurrent orchestrator evaluating an incoming `SecurityEvent` against all configured behavioral detectors simultaneously.

### 2.4 Threat Intelligence Subsystem (`src/bastion/intelligence/`)
- **`IOCType`**: Supports `IP`, `DOMAIN`, `HASH_MD5`, `HASH_SHA1`, `HASH_SHA256`, and `USERNAME`.
- **`IOCValidator`**: Strict RFC-compliant syntax checking and normalization.
- **`IOCManager`**: Full CRUD operations, free-text search, tag indexing, and event matching.
- **`Provenance`**: Data trust classification: `OBSERVED`, `INFERRED`, `CONFIGURED`, `CONFIRMED`, `UNKNOWN`.

### 2.5 Threat Risk Engine (`src/bastion/risk/`)
- **`RiskEngine`**: Multi-signal 0–100 threat score formula combining:
  - Base authentication failure accumulation (up to +30)
  - Invalid username targeting (+10)
  - Max authentication attempts exceeded (+20)
  - Behavioral detector triggers (+20 to +25 each)
  - Matched Threat Intelligence IOCs (+15 to +30 depending on confidence)
  - Repeat offender history (+15)
  - Legitimate authentication successes (-10 deduction)
  - Allowlisted / trusted source discounts (-100 discount)
- **`ScoreFactor`**: Structured dataclass recording factor name, score delta, and explanation.
- **`ThreatActorProfile`**: Persistent entity tracking forensic history, targeted accounts, associated IOCs, and active incident links.

### 2.6 Threat Correlation & Incident Subsystem (`src/bastion/correlation/`, `src/bastion/incidents/`, `src/bastion/attack/`)
- **`AttackRegistry`**: Standardized MITRE ATT&CK catalog mapping detector heuristics to authentic techniques (`T1110.001`, `T1110.003`, `T1087.001`, `T1499`, `T1078`).
- **`CorrelationEngine`**: Correlates events with active IOCs, ATT&CK techniques, and active incidents. Implements a rolling alert deduplication window (default 30s) to prevent notification fatigue while retaining full audit logs.
- **`IncidentManager`**: Complete lifecycle manager for security incidents with statuses: `OPEN`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`, and `CLOSED`.
- **`TimelineGenerator`**: Chronologically merges events, detections, risk changes, bans, and response audits into a unified forensic timeline.

### 2.7 Policy & Response Engine (`src/bastion/response/`)
- **`PolicyEngine`**: Evaluates risk profiles against CIDR allowlists (`ipaddress.ip_network`) and maps scores to response actions (`MONITOR`, `RATE_LIMIT`, `TEMPORARY_ISOLATION`, `PERMANENT_BAN`).
- **`BanManager`**: Manages the ban state machine, SQLite persistence, automatic expiration checking, and startup synchronization.
- **`ExperimentalResponseCoordinator`**: Isolated, target-validated execution coordinator for experimental response actions (`block_ip`, `contain_account`, `terminate_session`) with tamper-evident audit logging.
- **`NFTablesBackend`**: Kernel-level firewall containment using dedicated table `inet bastion` and sets `blacklist_v4` / `blacklist_v6`.

---

## 3. SQLite Database Schema (Migration v2)

```sql
-- Schema version tracking
CREATE TABLE schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

-- Core events & detections
CREATE TABLE events (...);
CREATE TABLE detections (...);
CREATE TABLE threat_actors (...);
CREATE TABLE score_history (...);
CREATE TABLE bans (...);

-- Threat intelligence indicators
CREATE TABLE iocs (
    ioc_id TEXT PRIMARY KEY,
    ioc_type TEXT NOT NULL,
    value TEXT NOT NULL,
    confidence INTEGER NOT NULL,
    source TEXT NOT NULL,
    provenance TEXT NOT NULL,
    status TEXT NOT NULL,
    tags TEXT NOT NULL,
    notes TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- Incidents & Join Tables
CREATE TABLE incidents (
    incident_id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    status TEXT NOT NULL,
    severity TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    summary TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    metadata TEXT NOT NULL
);
CREATE TABLE incident_events (incident_id TEXT, event_id INTEGER, PRIMARY KEY (incident_id, event_id));
CREATE TABLE incident_actors (incident_id TEXT, actor_id TEXT, PRIMARY KEY (incident_id, actor_id));
CREATE TABLE incident_iocs (incident_id TEXT, ioc_id TEXT, PRIMARY KEY (incident_id, ioc_id));

-- Audit and Timelines
CREATE TABLE timeline_entries (...);
CREATE TABLE response_audits (
    audit_id TEXT PRIMARY KEY,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    executed_by TEXT NOT NULL,
    dry_run INTEGER NOT NULL,
    success INTEGER NOT NULL,
    reason TEXT NOT NULL,
    details TEXT NOT NULL,
    timestamp TEXT NOT NULL
);
```
