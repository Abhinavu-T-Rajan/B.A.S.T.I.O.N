# Testing Guide

This guide details the automated test suite and quality assurance workflows for **B.A.S.T.I.O.N.**.

---

## 1. Test Architecture

B.A.S.T.I.O.N. utilizes `pytest` with 119 unit and integration tests organized by subsystem:

| Test Module | Coverage Area |
| :--- | :--- |
| `tests/test_config_validation.py` | Configuration schema, parameter bounds, strict validation, threshold monotonicity |
| `tests/test_daemon.py` | `BastionDaemon` lifecycle, streaming, graceful shutdown, malformed line resilience |
| `tests/test_daemon_cli.py` | CLI commands (`bastion health`, `bastion config validate`, `bastion daemon`) |
| `tests/test_health.py` | `HealthTracker`, subsystem state transitions, error counting, snapshot save/load |
| `tests/test_reconciliation.py` | `FirewallReconciler`, missing rule restoration, expired ban cleanup, fail-safe mode |
| `tests/test_detection.py` | `BruteForceDetector` sliding window, time-decay evictions |
| `tests/test_aegis_detectors.py` | Password spray, username enumeration, burst velocity detectors |
| `tests/test_risk_scorer.py` | Multi-signal 0–100 risk scoring, explainable factors, allowlist bypass |
| `tests/test_attack_registry.py` | MITRE ATT&CK catalog lookup, technique mapping |
| `tests/test_intelligence.py` | IOC validation (`IP`, `DOMAIN`, `HASH`, `USER`), provenance, matching |
| `tests/test_correlation.py` | Multi-signal correlation, alert deduplication, incident clustering |
| `tests/test_incidents.py` | Incident lifecycle transitions, related event/actor/IOC joins |
| `tests/test_timeline.py` | Chronological investigation timeline generation |
| `tests/test_policy_engine.py` | CIDR allowlist matching, score-to-action thresholding, repeat offender durations |
| `tests/test_response_engine.py` | Response modes (`DRY_RUN`, `AUTOMATIC`, `MANUAL`, `DISABLED`) |
| `tests/test_firewall.py` | `MockFirewallBackend` and `NFTablesBackend` set management |
| `tests/test_storage.py` | SQLite schema, WAL mode, CRUD queries, threat actor profiling |
| `tests/test_migrations.py` | `MigrationRunner` v1 $\rightarrow$ v2 schema versioning |
| `tests/test_journal_collector.py` | Journald streaming, subprocess management, retry logic |
| `tests/test_ssh_parser.py` | OpenSSH log regex extraction (IPv4, IPv6, preauth, invalid users) |
| `tests/test_pipeline.py` | End-to-end `SentinelPipeline` stream ingestion and alert formatting |
| `tests/test_cli.py` & `tests/test_oracle_cli.py` | Full CLI suite commands and formatting |

---

## 2. Running Tests

### Standard Test Run
```bash
# Run all tests
pytest -v
```

### Run Specific Test Modules
```bash
# Test daemon and health tracking
pytest -v tests/test_daemon.py tests/test_health.py tests/test_reconciliation.py

# Test configuration validation
pytest -v tests/test_config_validation.py
```

### Run with Coverage
```bash
pytest -v --cov=bastion --cov-report=term-missing --cov-report=html
```

---

## 3. Testing Principles & Rules

1. **Isolation**: Never perform destructive host actions in tests. Use `MockFirewallBackend` and in-memory or temporary SQLite databases (`tmp_path`).
2. **Deterministic Time**: Tests relying on time windows use relative offsets (`datetime.now(timezone.utc) - timedelta(...)`).
3. **No Synthetic Production Data**: Maintain authentic log formats and RFC-compliant network values.
