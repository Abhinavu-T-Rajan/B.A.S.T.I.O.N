# B.A.S.T.I.O.N. Developer Guide & Repository Workflow

Welcome to the development guide for **B.A.S.T.I.O.N. (Behavioral Attack Surveillance & Threat Isolation Operating Network)**. This document outlines architectural standards, environment setup, coding patterns, testing guidelines, and the official Git workflow for contributors and maintainers.

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
- Optional: `nftables` (for live integration testing in isolated namespaces)

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
# Output: B.A.S.T.I.O.N. v0.3.1 (Sentinel Core)

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
├── installer/                # Production automated installer suite
│   ├── install.sh
│   ├── uninstall.sh
│   ├── upgrade.sh
│   └── lib/
├── systemd/                  # systemd unit files
│   └── bastion.service
├── tests/                    # Comprehensive unit and integration test suite
├── docs/                     # Documentation suite
│   ├── architecture.md
│   ├── threat-model.md
│   ├── deployment.md
│   ├── development/
│   └── operations/
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

### Validate Installer Shell Scripts
```bash
bash -n installer/*.sh installer/lib/*.sh
```

---

## 5. Git Workflow

B.A.S.T.I.O.N. follows a disciplined, professional branching strategy centered around two permanent long-lived branches: `main` and `development`.

```
           feature/* ─────────┐
                              ▼
main ──────────────────► development ───(Release PR)───► main (v0.4.0 tag)
 │                            ▲                           │
 └─── hotfix/* ───────────────┴───────────────────────────┘
```

### Long-Lived Branches

#### `main`
- **Role**: Production / stable release code only.
- Always reflects the latest verified, tagged stable release (e.g. `v0.3.1-stable`).
- Direct commits to `main` are strictly prohibited (except automated release promotions).
- Releases are tagged and published exclusively from `main`.

#### `development`
- **Role**: Continuous integration branch for the next release cycle.
- All new feature, refactor, documentation, and fix branches merge into `development`.
- Must remain healthy, buildable, and CI-passing at all times.
- Serves as the default target branch for Pull Requests.

### Version Branch Policy

> [!IMPORTANT]
> **DO NOT** create long-lived branches named after versions (e.g. `v0.4.0`, `v0.5.0`, `v1.0.0`).
> Version milestones are represented strictly via **immutable Git tags** (`v0.3.1-stable`, `v0.4.0`) and GitHub Releases.

---

## 6. Branch Naming Conventions

All development occurs on short-lived branches created from `development` (or `main` in the case of hotfixes). Use standard categorical prefixes:

| Branch Prefix | Usage | Target Branch | Example |
| :--- | :--- | :--- | :--- |
| `feature/` | New capabilities, subsystems, or user-facing tools | `development` | `feature/web-api`, `feature/metrics-exporter` |
| `refactor/` | Structural improvements, decoupling, clean architecture | `development` | `refactor/core-architecture`, `refactor/collector-providers` |
| `fix/` | Non-emergency bug fixes for issues in `development` | `development` | `fix/config-validation`, `fix/journal-collector` |
| `hotfix/` | Emergency production fixes for defects on `main` | `main` & `development` | `hotfix/production-firewall`, `hotfix/sshd-session` |
| `docs/` | Documentation additions or revisions | `development` | `docs/architecture`, `docs/threat-model` |
| `test/` | Test suite enhancements, regression tests, mocks | `development` | `test/architecture-boundaries`, `test/daemon-lifecycle` |
| `chore/` | Maintenance, dependency updates, CI configurations | `development` | `chore/ci-workflow`, `chore/package-metadata` |

---

## 7. Commit Conventions

B.A.S.T.I.O.N. adheres to the [Conventional Commits](https://www.conventionalcommits.org/) standard.

### Format
```text
<type>(<optional scope>): <short description>

[optional body]

[optional footer]
```

### Allowed Types
- `feat:` New feature or functional addition
- `fix:` Bug fix or defect resolution
- `refactor:` Code refactoring without changing observable behavior
- `docs:` Documentation changes
- `test:` Adding or updating tests
- `build:` Build system, packaging, or dependency changes
- `ci:` Continuous integration scripts and GitHub Actions workflows
- `chore:` Miscellaneous maintenance tasks
- `perf:` Performance optimizations
- `security:` Security enhancements, vulnerability fixes, or hardening

### Guidelines
- Commits must be small, atomic, and descriptive.
- Avoid vague messages such as `"fix"`, `"update"`, `"changes"`, or `"wip"`.

---

## 8. Pull Request Requirements

Before opening or merging a Pull Request (PR):

1. **Target**: Pull requests for regular work MUST target `development`.
2. **CI Passing**: All automated CI tests across all supported Python versions (3.11, 3.12) and script validations must be passing (100% green).
3. **Regression Tests**: Any new feature or bug fix must include comprehensive unit and integration tests.
4. **Documentation**: Update `CHANGELOG.md`, `README.md`, or relevant `docs/` files whenever user-facing interfaces or behaviors change.
5. **No Breaking Regressions**: Preserve decoupled architecture, error containment boundaries, and zero-dummy-data guarantees.

---

## 9. Release Process

Stable releases follow a structured promotion flow:

1. **Feature Completion**: All milestones for the release are merged into `development` and verified in CI.
2. **Release Preparation**:
   - Verify all tests pass (`pytest -v`).
   - Validate installer suite (`bash -n installer/*.sh installer/lib/*.sh`).
   - Update `src/bastion/version.py` (`__version__ = "X.Y.Z"`).
   - Update `pyproject.toml`, `bastion.toml`, and installer banners.
   - Update `CHANGELOG.md` with release notes and date.
3. **Promotion to `main`**:
   - Open a Release PR from `development` into `main`.
   - Once CI passes, merge into `main`.
4. **Tagging & Release**:
   - Create an annotated Git tag on `main`:
     ```bash
     git tag -a v0.4.0 -m "B.A.S.T.I.O.N. v0.4.0: Modular Core & Architecture Refactor"
     git push origin v0.4.0
     ```
   - Publish the corresponding GitHub Release with changelog notes.
5. **Post-Release Sync**:
   - Fast-forward or merge `main` back into `development` to maintain unified history.

---

## 10. Hotfix Process

When an urgent defect is discovered in production:

```
main ────────► hotfix/fix-issue ───► main (vX.Y.Z+1 tag)
                                       │
                                       ▼ (sync back)
                                  development
```

1. **Branch**: Create a branch directly from `main`:
   ```bash
   git switch main
   git pull origin main
   git switch -c hotfix/critical-firewall-patch
   ```
2. **Implement & Test**: Fix the defect and write regression tests. Verify 100% test passage.
3. **Bump Patch Version**: Update `version.py`, `pyproject.toml`, and `CHANGELOG.md`.
4. **Merge to `main` & Tag**:
   - Merge `hotfix/critical-firewall-patch` into `main`.
   - Create and push an annotated tag: `v0.3.2-stable`.
5. **Sync Back to `development`**:
   - Merge `main` into `development` to ensure the hotfix is preserved in the ongoing development cycle:
     ```bash
     git switch development
     git merge main
     git push origin development
     ```

---

## 11. No Force Push Policy

> [!CAUTION]
> **NEVER** use `git push --force` or `git push -f` on `main` or `development`.
> Public history on shared branches must remain immutable. If a commit needs correction, apply a compensating commit (`git revert` or a new fix commit).

---

## 12. Release Artifacts

Every official release includes:
- Clean Git commit on `main`
- Annotated, immutable Git tag (`vX.Y.Z-stable` or `vX.Y.Z`)
- GitHub Release with detailed changelog notes
- Updated `CHANGELOG.md` and documentation
- Validated installation and upgrade scripts (`installer/install.sh`, `installer/upgrade.sh`)
