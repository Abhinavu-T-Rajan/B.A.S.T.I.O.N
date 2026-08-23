# B.A.S.T.I.O.N. — AI-Assisted Development & Engineering Policy

**Version:** 1.0.0  
**Effective Date:** 2026-08-23  
**Status:** Active Governance Standard  

---

## 1. Purpose & Scope

This document defines the mandatory engineering standards, safety guardrails, and quality requirements for all **AI-assisted and automated coding workflows** within the B.A.S.T.I.O.N. repository. 

As a mission-critical host intrusion detection, prevention, and security response platform (IDS/IPS/SOAR), B.A.S.T.I.O.N. requires uncompromising reliability, verifiable correctness, and strict operational safety.

---

## 2. Core Governance Directives

### 2.1 Branching & Repository Integrity
1. **Target `development` by Default**:
   - All AI-assisted feature additions, architectural refactoring, documentation, and non-emergency bug fixes must be authored on short-lived branches (`feature/*`, `refactor/*`, `fix/*`, `docs/*`, `test/*`, `chore/*`) created from `development`.
   - Never push directly to `main` unless executing an explicitly authorized release or emergency hotfix synchronization.
2. **Strict No-Force-Push Policy**:
   - AI tools and agents must **NEVER** execute `git push --force` or `git push -f` on `main` or `development`.
   - History rewriting on shared long-lived branches is strictly forbidden.
3. **Safe Branch Deletion**:
   - Never delete any branch without verifying that its commits are fully reachable and merged into `main` or `development`, and that corresponding releases are preserved via immutable Git tags.

### 2.2 Truthfulness & Test Verification
1. **Zero Dummy/Fabricated Production Telemetry**:
   - AI tools must **NEVER** introduce fake, synthetic, or fabricated production data into core telemetry pipelines or databases.
   - Real telemetry is ingested exclusively from OpenSSH and systemd-journald.
   - Unit and integration tests must use explicitly marked, deterministic mocks (`MockFirewallBackend`, in-memory SQLite).
2. **Never Fabricate Test Results**:
   - Test execution results, command outputs, and coverage figures must represent genuine live execution.
   - Every code modification must be verified by running the test suite (`pytest -v`) before claiming completion.

### 2.3 Host Safety & Security Controls
1. **Fail-Safe Response Enforcement**:
   - Defensive response mechanisms (such as `nftables` packet filtering and IP isolation) must always fail closed and safe.
   - AI tools must ensure that automated responses refuse enforcement and enter a degraded/failed audit state if underlying firewall backends are unavailable, rather than falsely claiming successful defense.
2. **Preserve Security Sandboxing**:
   - Maintain least-privilege systemd security hardening directives (`CAP_NET_ADMIN`, `NoNewPrivileges=true`, `ProtectSystem=strict`, `ProtectHome=read-only`).
   - Never weaken sandboxing boundaries or bypass authentication checks to make a test pass.
3. **Zero Secrets & Credentials Exposure**:
   - AI tools must never log, hardcode, or commit sensitive credentials, private keys, API tokens, or production host identifiers.
   - Ensure all structured logging invocations pass through sanitization routines.

### 2.4 Architectural Discipline & Preservation
1. **Respect Architectural Boundaries**:
   - Maintain strict decoupling between Telemetry, Detection, Risk Scoring, Threat Correlation, Incident Lifecycle, Policy Engine, Ban Management, Storage, and Daemon Runtime.
   - Adhere to the established Provider and Engine patterns.
2. **Preserve Existing Documentation & Comments**:
   - Maintain codebase documentation integrity. Preserve unrelated comments, docstrings, and architectural rationale when editing files.
3. **Avoid Unnecessary Full-File Rewrites**:
   - Prefer targeted, atomic, surgical diffs over wholesale file rewrites whenever modifying existing modules.

---

## 3. Workflow for AI-Assisted Tasks

When an AI agent or developer with AI tooling implements a task in this repository, the following protocol must be followed:

```text
1. Inspect & Understand
   └── Read current code, architecture specs, and existing tests.

2. Branch Creation
   └── Create short-lived branch from development (e.g. refactor/core-architecture).

3. Implementation
   └── Make modular, typed, clean changes following Conventional Commits.

4. Comprehensive Verification
   ├── Run unit and integration tests (pytest -v).
   ├── Validate shell scripts (bash -n installer/*.sh installer/lib/*.sh).
   └── Validate package build and configuration schemas.

5. Pull Request & Review
   └── Submit PR targeting development with clear rationale and test evidence.
```

---

## 4. Compliance & Review

AI-generated code is held to the exact same rigorous security, quality, and review standards as human-authored code. Pull requests generated with AI assistance must pass all automated CI checks and maintain 100% test passing rates before integration into `development` and `main`.
