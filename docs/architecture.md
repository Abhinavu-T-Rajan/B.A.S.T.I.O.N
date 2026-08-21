# B.A.S.T.I.O.N. System Architecture

**Behavioral Attack Surveillance & Threat Isolation Operating Network** (v0.1.3 "Guardian")

---

## 1. High-Level Architecture

B.A.S.T.I.O.N. is organized as a decoupled, multi-stage processing pipeline that ingests raw authentication telemetry from Linux host services, normalizes log events into structured abstractions, executes concurrent behavioral detection heuristics, calculates explainable threat scores (0–100), evaluates defense policies against allowlists, and enforces host-level packet filtering via Linux `nftables`.

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
  │             Threat Intelligence & Risk Engine               │
  │   • Multi-Signal 0–100 Scorer (RiskEngine)                  │
  │   • Explainable ScoreFactor generation                      │
  │   • Offender profiling (ThreatActorProfile)                 │
  └──────────────────────────────┬──────────────────────────────┘
                                 │ ThreatActorProfile
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
  │   • Expiration tracking & Startup recovery                  │
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
  │   • Tables: events, detections, threat_actors,              │
  │     score_history, bans                                     │
  └─────────────────────────────────────────────────────────────┘
```

---

## 2. Component Breakdown

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
- **`DetectionEngine`**: Concurrent orchestrator that evaluates an incoming `SecurityEvent` against all configured behavioral detectors simultaneously and aggregates results.

### 2.4 Threat Intelligence & Risk Engine (`src/bastion/risk/`)
- **`RiskEngine`**: Computes an auditable, explainable threat score (0–100) using a multi-signal additive formula:
  - Base authentication failure accumulation (up to +30)
  - Invalid username targeting (+10)
  - Max authentication attempts exceeded (+20)
  - Behavioral detector triggers (+20 to +25 each)
  - Repeat offender history (+15)
  - Legitimate authentication successes (-10 deduction)
  - Allowlisted / trusted source discounts (-100 discount)
- **`ScoreFactor`**: Structured dataclass recording the exact factor name, score delta, and human-readable explanation for complete forensic transparency.
- **`ThreatActorProfile`**: Persistent entity tracking first/last seen timestamps, failure counts, targeted usernames, targeted services, current threat score, severity (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), and lifecycle state.

### 2.5 Policy Engine (`src/bastion/response/policy.py`)
- **`PolicyEngine`**: Translates threat profiles and risk scores into actionable defensive policies:
  - **CIDR Allowlist Verification**: Uses `ipaddress.ip_network` to protect management subnets and localhost from isolation.
  - **Action Mapping**: Maps scores to actions:
    - Score $\ge 85 \rightarrow$ `TEMPORARY_ISOLATION`
    - Score $\ge 60 \rightarrow$ `RATE_LIMIT`
    - Score $< 60$ with failures $\rightarrow$ `MONITOR`
    - Score 100 with $\ge 30$ historical failures $\rightarrow$ `PERMANENT_BAN`
  - **Dynamic Durations**: Assigns 15m default bans, extended 1h bans for repeat offenders, clamped to a maximum 24h ceiling.

### 2.6 Response Engine & Ban Lifecycle Manager (`src/bastion/response/`)
- **`ResponseEngine`**: Dispatches policy decisions according to the configured `ResponseMode`:
  - `DRY_RUN` *(Default)*: Records simulated ban decisions in storage and displays explainable `"WOULD BLOCK"` alerts without touching packet filtering rules.
  - `AUTOMATIC`: Calls `BanManager` to block the offending IP directly in the firewall.
  - `MANUAL_APPROVAL`: Queues bans in a `PENDING_APPROVAL` state for administrator review.
  - `DISABLED`: Emergency killswitch bypassing all containment.
- **`BanManager`**: Coordinates ban persistence and firewall synchronization:
  - Offender State Machine: `NEUTRAL` $\rightarrow$ `PROBING` $\rightarrow$ `SUSPICIOUS` $\rightarrow$ `ACTIVE_THREAT` $\rightarrow$ `ISOLATED` $\rightarrow$ `EXPIRED` / `RELEASED`.
  - Expiration Polling: Evaluates active ban records and releases expired IPs from the firewall.
  - Startup Recovery: Restores active unexpired bans into the firewall upon service restart.

### 2.7 Firewall Backend Abstraction (`src/bastion/firewall/`)
- **`FirewallBackend`**: Abstract interface defining packet filtering operations.
- **`NFTablesBackend`**: Native Linux `nftables` implementation. Operates strictly within a dedicated namespace:
  - Table: `inet bastion`
  - Sets: `blacklist_v4` and `blacklist_v6` with timeout flags
  - Chain: `input` hook at `priority -10` with early drop rules
  - **Zero Host Interference**: Never alters or flushes existing system firewall rules or chains.
- **`MockFirewallBackend`**: In-memory backend maintaining a thread-safe dictionary of blocked IPs and expiry timestamps, enabling automated testing in unprivileged CI and WSL environments.

### 2.8 Persistence Layer (`src/bastion/storage/sqlite.py`)
- **`SQLiteStorage`**: Persistent storage engine utilizing Write-Ahead Logging (`PRAGMA journal_mode=WAL;`) and a reentrant lock (`threading.RLock`) for concurrent stream processing and CLI inspection.
- **Schema**:
  - `events`: Raw telemetry events with JSON metadata.
  - `detections`: Triggered behavioral detection records.
  - `threat_actors`: ThreatActorProfile records with score history.
  - `score_history`: Time-series score factor log.
  - `bans`: BanRecord lifecycle records.

### 2.9 Sentinel Pipeline & Alerting (`src/bastion/pipeline.py`)
- **`SentinelPipeline`**: Unified real-time coordinator linking Telemetry $\rightarrow$ Normalization $\rightarrow$ Multi-Detection $\rightarrow$ Risk Scoring $\rightarrow$ Policy Evaluation $\rightarrow$ Defensive Action $\rightarrow$ Storage $\rightarrow$ Alert Dispatch.
- **`format_explainable_alert`**: Formats rich terminal alerts detailing source IP, severity, contributing score factors, targeted usernames, and defensive containment status.
