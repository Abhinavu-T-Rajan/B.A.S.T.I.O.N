# B.A.S.T.I.O.N. System Architecture

**Behavioral Attack Surveillance & Threat Isolation Operating Network** (v0.4.0 "Gateway")

> *"Separate what B.A.S.T.I.O.N. does from how B.A.S.T.I.O.N. implements it."*

---

## 1. High-Level Architecture & Dependency Inversion

B.A.S.T.I.O.N. is organized around a clean **Hexagonal / Ports-and-Adapters** architecture. The core application logic and domain models do not depend on external drivers, frameworks, database implementations, or command-line parsers. Instead, core subsystems define pure interfaces (contracts), while infrastructure packages provide concrete adapters.

```
                                  B.A.S.T.I.O.N. v0.4.0 (Gateway)
                                                 │
                 ┌───────────────────────────────┴───────────────────────────────┐
                 │                   Application Service Layer                   │
                 ├───────────────────────────────────────────────────────────────┤
                 │ • DefenseAppService      • IntelligenceAppService             │
                 │ • IncidentAppService     • HealthAppService                   │
                 │ • SentinelPipeline       (Unified Event & Defense Pipeline)   │
                 └───────────────────────────────┬───────────────────────────────┘
                                                 │
        ┌────────────────────────┬───────────────┴───────────────┬────────────────────────┐
        │                        │                               │                        │
┌───────▼────────┐      ┌────────▼────────┐             ┌────────▼────────┐      ┌────────▼────────┐
│   Telemetry    │      │    Behavioral   │             │   Defensive     │      │   Persistence   │
│   Gateway      │      │    Detectors    │             │   Response      │      │   Storage       │
├────────────────┤      ├─────────────────┤             ├─────────────────┤      ├─────────────────┤
│ Collector      │      │ Detector        │             │ Response        │      │ Storage         │
│ Provider       │      │ Provider        │             │ Provider        │      │ Provider        │
│                │      │                 │             │                 │      │                 │
│ • Journald     │      │ • Brute-Force   │             │ • Policy Engine │      │ • SQLiteStorage │
│ • Stdin        │      │ • Spray         │             │ • Ban Manager   │      │   (Migrations)  │
│ • File         │      │ • Enumeration   │             │ • Reconciler    │      │                 │
│                │      │ • Burst         │             │                 │      │                 │
│ RawTelemetry   │      │ • Custom Plugin │             │ Firewall        │      │                 │
│       │        │      └─────────────────┘             │ Provider        │      │                 │
│ Adapters &     │                                      ├─────────────────┤      │                 │
│ Normalizers    │                                      │ • NFTables      │      │                 │
│       ▼        │                                      │ • MockBackend   │      │                 │
│ SecurityEvent  │                                      └─────────────────┘      │                 │
└────────────────┘                                                               └─────────────────┘
```

---

## 2. Core Contracts & Domain Boundaries (`src/bastion/core/`)

The `bastion.core` package contains pure domain models and provider protocols with zero dependencies on concrete I/O libraries or third-party infrastructure.

### 2.1 Telemetry Contracts (`bastion.core.contracts.collector`)
- **`RawTelemetry`**: Immutable domain record capturing raw log lines alongside structured origin context:
  - `raw_message: str`: Exact raw string or payload.
  - `source: str`: Identifier for source driver (`journald`, `stdin`, `file`).
  - `timestamp: datetime`: Ingestion/event timestamp.
  - `transport: str`: Underlying stream transport (`pipe`, `unix_socket`, `file_io`).
  - `unit: str | None`: Systemd unit if applicable (`ssh.service`, `sshd.service`).
  - `identifier: str | None`: Syslog identifier (`sshd`, `sshd-session`, `sshd-auth`).
  - `pid: int | None`: Process ID.
  - `metadata: dict[str, Any]`: Additional origin metadata.
- **`CollectorProvider`**: Protocol for streaming (`stream() -> Iterator[RawTelemetry]`) and querying (`read(limit=50) -> Iterator[RawTelemetry]`) raw telemetry.
- **`TelemetryAdapter`**: Pure parsing interface (`can_handle(telemetry) -> bool`, `normalize(telemetry) -> SecurityEvent | None`).
- **`EventNormalizer`**: Interface for multi-protocol adapter orchestration.

### 2.2 Detector Contract (`bastion.core.contracts.detector`)
- **`Detector`**: Abstract base class and `DetectorProvider` protocol for threat detectors:
  - `evaluate(event: SecurityEvent) -> DetectionResult | None`: Evaluates incoming events and emits detection decisions without side effects on storage or firewalls.
  - `reset() -> None`: Clears internal sliding windows or state buffers.
  - `enabled: bool`: Runtime activation flag.

### 2.3 Firewall & Response Contracts (`bastion.core.contracts.firewall`, `response`)
- **`FirewallProvider`**: Driver-agnostic packet filtering contract (`block_ip`, `unblock_ip`, `is_ip_blocked`, `list_blocked_ips`, `flush_rules`).
- **`ResponseProvider`**: Abstract interface evaluating actor threat profiles and determining defensive response decisions.

### 2.4 Persistence Contracts (`bastion.core.contracts.storage`)
- **`StorageProvider`**: Repository contract isolating persistence operations (`save_event`, `upsert_threat_actor`, `save_ban`, `save_ioc`, `save_incident`, `get_stats`).

---

## 3. Application Services Layer (`src/bastion/services/`)

Application services encapsulate orchestration and business workflows, enabling both the CLI and daemon to execute identical logic without code duplication:

- **`DefenseAppService`**: Manages operational status inspection, threat actor investigation, manual ban/unban workflows, and firewall maintenance.
- **`IntelligenceAppService`**: Coordinates IOC registration, RFC validation, substring searching, lifecycle management, and MITRE ATT&CK catalog queries.
- **`IncidentAppService`**: Manages incident lifecycle transitions, correlation clustering, and forensic timeline construction.
- **`HealthAppService`**: Performs live diagnostic probes across subsystems and formats operational health reports.
- **`SentinelPipeline`**: Orchestrates Normalization $\rightarrow$ IOC Matching $\rightarrow$ Detection $\rightarrow$ Risk Scoring $\rightarrow$ Response Evaluation $\rightarrow$ Threat Correlation $\rightarrow$ Persistence.

---

## 4. Telemetry Gateway & Infrastructure Adapters (`src/bastion/infrastructure/telemetry/`)

- **`JournaldCollector`**: Streams raw entries from `systemd-journald` with exponential reconnection backoff and graceful subprocess lifecycle management.
- **`StdinCollector`**: Ingests raw lines from standard input pipes.
- **`FileCollector`**: Streams log records from authentication log files.
- **`SSHLogAdapter`**: Parses OpenSSH, modern `sshd-session`, `sshd-auth`, and `pam_unix` logs into canonical `SecurityEvent` models.
- **`CompositeEventNormalizer`**: Dispatches `RawTelemetry` records across registered protocol adapters.

---

## 5. Architectural Invariants Enforced by Automated Tests

The test suite includes `tests/test_architecture_boundaries.py` which verifies:
1. **Core Isolation**: `bastion.core` never imports `bastion.infrastructure`, `bastion.cli`, `sqlite3`, `subprocess`, or `argparse`.
2. **Detector Isolation**: Behavioral detectors never import storage, firewall backends, or CLI modules.
3. **Telemetry Isolation**: Telemetry adapters never import response engines or persistence drivers.
4. **Thin CLI**: `bastion.cli` delegates all commands to application services and never interacts directly with low-level database drivers or raw firewall processes.
