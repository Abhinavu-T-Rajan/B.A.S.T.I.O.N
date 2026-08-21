# Contributing to B.A.S.T.I.O.N.

Thank you for your interest in contributing to **B.A.S.T.I.O.N.** (Behavioral Attack Surveillance & Threat Isolation Operating Network). We welcome contributions from security researchers, Linux engineers, and software developers.

As an active host-level intrusion detection and prevention system (IDS/IPS), B.A.S.T.I.O.N. interacts directly with Linux networking, system logs, and packet filtering subsystems. Consequently, code quality, security rigor, and test coverage are of paramount importance.

---

## Branching Model & Workflow

We maintain a dual-branch development model:

- **`main`**: Contains verified, tagged, production-stable releases. Direct commits to `main` are restricted.
- **`development`**: Active integration branch where new features, behavioral detectors, and refactors are merged prior to release tagging.
- **Feature / Topic Branches**: Create short-lived branches branched off `development`:
  - `feat/<feature-name>` for new capabilities
  - `fix/<bug-description>` for non-security bug fixes
  - `sec/<cve-or-description>` for security patches
  - `docs/<doc-topic>` for documentation improvements

```
main (v0.1.3) ───────────────────────────● v0.1.4 release
                   ▲                    ▲
                   │                    │
development ───────●────────────────────●
                     \                /
                      ●───●───● (feat/new-detector)
```

---

## Getting Started

1. **Fork and Clone**:
   ```bash
   git clone https://github.com/<your-username>/B.A.S.T.I.O.N.git
   cd B.A.S.T.I.O.N
   git checkout development
   ```

2. **Set Up Local Virtual Environment**:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -e ".[dev]"
   ```

3. **Verify Baseline Test Suite**:
   ```bash
   pytest -v
   ```
   Ensure all existing tests pass before making any changes.

---

## Commit Message Guidelines

We follow the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) specification:

```text
<type>(<optional scope>): <short summary in imperative mood>

[optional body explaining rationale, threat model context, or architectural impact]

[optional footer(s)]
```

### Supported Types
- **`feat`**: A new user-facing feature or detector (e.g., `feat(detection): add distributed brute force detector`).
- **`fix`**: A bug fix (e.g., `fix(parser): handle IPv6 bracketed ports in ssh logs`).
- **`sec`**: Security hardening or vulnerability remediation.
- **`docs`**: Documentation changes (e.g., `docs(threat-model): clarify ReDoS protections`).
- **`test`**: Adding or updating tests (e.g., `test(firewall): verify nftables rule timeout syntax`).
- **`refactor`**: Code changes that neither fix a bug nor add a feature.

---

## Pull Request Guidelines

1. **Base Branch**: Ensure your PR targets `development`, not `main`.
2. **Atomic & Focused**: Keep PRs focused on a single feature, detector, or bugfix.
3. **No Regressions**: Existing unit and integration tests must pass cleanly.
4. **New Test Coverage**: Every new behavioral detector, parser rule, storage query, policy rule, or CLI flag must include corresponding unit and integration tests.
5. **No Blind Firewall Changes**: Never modify firewall execution logic (`NFTablesBackend`) without providing tests using `MockFirewallBackend` or mocked subprocess executions.
6. **Documentation**: Update relevant documentation in `docs/` (`architecture.md`, `threat-model.md`, `deployment.md`) or `README.md` if changing user-facing functionality.

---

## Security-Sensitive Review Expectations

Because B.A.S.T.I.O.N. can modify kernel-level packet filtering rules and parse untrusted log streams, all PRs touching the following areas will undergo mandatory security review:

- **Log Parsers (`src/bastion/collector/`)**:
  - Regular expressions must be evaluated for **ReDoS (Regular Expression Denial of Service)** vulnerabilities.
  - Parsers must never execute shell commands directly with log inputs.
- **Firewall Integration (`src/bastion/firewall/`)**:
  - Code must never modify host firewall rules outside the dedicated `inet bastion` table namespace.
  - Shell command invocations must use parameterized argument lists (`["nft", "add", ...]`)—never unsanitized `shell=True` string formatting.
- **Policy Engine & Allowlisting (`src/bastion/response/policy.py`)**:
  - CIDR allowlists and localhost protections must never be bypassed or weakened.
- **Persistence Layer (`src/bastion/storage/`)**:
  - All database queries must use parameterized SQL bindings (`?`) to prevent SQL injection.

---

## Reporting Vulnerabilities

If you discover a security vulnerability in B.A.S.T.I.O.N., please do **not** open a public issue or pull request. Follow our [SECURITY.md](SECURITY.md) guidelines for responsible disclosure.
