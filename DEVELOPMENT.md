# B.A.S.T.I.O.N. Developer Guide

Welcome to the development guide for **B.A.S.T.I.O.N. (Behavioral Attack Surveillance & Threat Isolation Operating Network)**. This document outlines development standards, environment setup, coding patterns, testing guidelines, and submission workflows for contributors.

---

## 1. Development Principles

1. **Host-Level Safety First**:
   - Defensive packet filtering and responses must never lock out system administrators or interfere with legitimate host network connectivity.
   - All tests MUST default to `MockFirewallBackend` and in-memory SQLite storage. Never invoke live `nftables` or modify `/etc` during test runs.

2. **Zero Dummy/Fabricated Data Policy**:
   - B.A.S.T.I.O.N. enforces a strict policy against fake or synthetic production telemetry records. Real forensic telemetry is ingested directly from OpenSSH/journald. Tests use explicitly marked, deterministic unit mocks.

3. **Decoupled, Testable Architecture**:
   - Every subsystem (Telemetry, Normalization, Detection, Risk, Correlation, Policy, Response, Storage, Daemon) must have clean interfaces and isolated unit tests.

4. **Structured Logging & Auditability**:
   - All critical daemon lifecycle actions, firewall changes, and errors must emit structured logs with appropriate audit tags (`SERVICE_START`, `BAN_RESTORED`, etc.).

---

## 2. Environment Setup

### Prerequisites
- Linux OS (Ubuntu 22.04+, Debian 12+, Arch Linux, RHEL 9+, Fedora)
- Python 3.11+ (Python 3.12 recommended)
- `git`
- Optional: `nftables` (for live integration testing with sudo)

### Quick Setup
```bash
# Clone the repository
git clone https://github.com/Abhinavu-T-Rajan/B.A.S.T.I.O.N.git
cd B.A.S.T.I.O.N

# Create and activate Python virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install package in editable mode with development dependencies
pip install -e ".[dev]"
```

Verify the installation:
```bash
bastion --version
# Output: B.A.S.T.I.O.N. v0.3.0 (Sentinel Core)

bastion config validate
# Output: ✓ Configuration is valid (format version 1)
```

---

## 3. Directory Layout

```
B.A.S.T.I.O.N/
├── src/bastion/
│   ├── __init__.py           # Top-level exports
│   ├── version.py            # Version and codename metadata
│   ├── cli.py                # CLI entrypoints and command handlers
│   ├── config.py             # Configuration schema, validation, and loaders
│   ├── pipeline.py           # Sentinel stream processing pipeline
│   ├── attack/               # MITRE ATT&CK models and registry
│   ├── collector/            # Telemetry ingestion (journald, ssh)
│   ├── correlation/          # Threat correlation and incident clustering
│   ├── daemon/               # Sentinel Core daemon, health tracking, reconciliation
│   │   ├── runner.py         # BastionDaemon service orchestrator
│   │   ├── state.py          # HealthTracker and snapshot management
│   │   ├── reconciliation.py # FirewallReconciler rule verification
│   │   └── logging.py        # Structured log formatter and audit tags
│   ├── detection/            # Behavioral detection suite
│   ├── firewall/             # Packet filtering abstraction (nftables, mock)
│   ├── incidents/            # Security incident lifecycle manager
│   ├── intelligence/         # Threat intelligence and IOC validator
│   ├── models/               # Domain models (events, actors)
│   ├── response/             # Policy engine, ban manager, response engine
│   ├── risk/                 # Explainable risk scoring engine
│   ├── storage/              # SQLite persistence and migration runner
│   └── timeline/             # Investigation timeline generator
├── tests/                    # Comprehensive unit and integration test suite
├── systemd/                  # systemd unit files
│   └── bastion.service
├── docs/                     # Documentation suite
│   ├── architecture.md
│   ├── threat-model.md
│   ├── development/
│   │   ├── setup.md
│   │   └── testing.md
│   └── operations/
│       ├── installation.md
│       ├── service-management.md
│       └── configuration.md
├── bastion.toml              # Default configuration file
└── pyproject.toml            # Build metadata and dependencies
```

---

## 4. Running Tests & Quality Assurance

### Run Test Suite
```bash
# Run all tests
pytest -v

# Run with test coverage
pytest -v --cov=bastion --cov-report=term-missing
```

### Static Analysis
```bash
# Type checking
mypy src/bastion

# Formatting and linting
ruff check src/ tests/
```

---

## 5. Adding New Subsystems or Detectors

When adding a new detector or subsystem:
1. Implement the detector class in `src/bastion/detection/` with a sliding time window and `evaluate(event) -> DetectionResult`.
2. Register the detector in `DetectionEngine` (`src/bastion/detection/engine.py`).
3. Add any corresponding MITRE ATT&CK mapping in `AttackRegistry` (`src/bastion/attack/registry.py`).
4. Add configuration parameters to `DetectorsConfig` in `src/bastion/config.py` and implement validation rules in `validate_config`.
5. Add comprehensive unit tests under `tests/` covering positive detections, threshold boundary conditions, and time-decay expiration.

---

## 6. Git & Contribution Workflow

- Follow the [Contributing Guide](CONTRIBUTING.md).
- Use Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`).
- Branch from `development` for feature work; pull requests target `development`.
- Ensure all 119 tests pass prior to submitting a PR.
