#!/usr/bin/env bash
# ==============================================================================
# B.A.S.T.I.O.N. Installer - Service Account & Filesystem Layout Management
# ==============================================================================

set -euo pipefail

# Standard installation paths
INSTALL_PREFIX="${INSTALL_PREFIX:-/opt/bastion}"
VENV_PATH="${INSTALL_PREFIX}/venv"
CONFIG_DIR="${CONFIG_DIR:-/etc/bastion}"
CONFIG_FILE="${CONFIG_DIR}/bastion.toml"
DATA_DIR="${DATA_DIR:-/var/lib/bastion}"
LOG_DIR="${LOG_DIR:-/var/log/bastion}"
BIN_LINK="${BIN_LINK:-/usr/local/bin/bastion}"
ALT_BIN_LINK="/usr/bin/bastion"

create_service_account() {
    # 1. Create group 'bastion' if not existing
    if ! getent group bastion >/dev/null 2>&1; then
        groupadd -r bastion
    fi

    # 2. Create user 'bastion' if not existing
    if ! getent passwd bastion >/dev/null 2>&1; then
        local nologin_bin="/usr/sbin/nologin"
        if [[ ! -x "${nologin_bin}" ]]; then
            nologin_bin="/sbin/nologin"
            if [[ ! -x "${nologin_bin}" ]]; then
                nologin_bin="/bin/false"
            fi
        fi
        useradd -r -g bastion -d "${DATA_DIR}" -s "${nologin_bin}" \
            -c "B.A.S.T.I.O.N. Sentinel Core Service" -M bastion
    fi
}

setup_directories() {
    # Create required standard directories
    mkdir -p "${INSTALL_PREFIX}"
    mkdir -p "${CONFIG_DIR}"
    mkdir -p "${DATA_DIR}"
    mkdir -p "${LOG_DIR}"

    # Apply strict least-privilege permissions
    chmod 0755 "${INSTALL_PREFIX}"
    chown root:root "${INSTALL_PREFIX}"

    chmod 0750 "${CONFIG_DIR}"
    chown root:bastion "${CONFIG_DIR}"

    chmod 0750 "${DATA_DIR}"
    chown bastion:bastion "${DATA_DIR}"

    chmod 0750 "${LOG_DIR}"
    chown bastion:bastion "${LOG_DIR}"
}

create_default_config() {
    local target_file="${CONFIG_FILE}"

    if [[ -f "${target_file}" ]]; then
        log_info "Existing configuration found at '${target_file}'. Preserving current settings."
        chmod 0640 "${target_file}"
        chown root:bastion "${target_file}"
        return 0
    fi

    cat << 'EOF' > "${target_file}"
# B.A.S.T.I.O.N. Configuration File
# Behavioral Attack Surveillance & Threat Isolation Operating Network
# v0.3.0 — Sentinel Core (Production Default)

config_version = 1

[storage]
# Persistent SQLite database path
db_path = "/var/lib/bastion/bastion.db"

[detectors.brute_force]
enabled = true
threshold = 10
window_seconds = 60

[detectors.password_spray]
enabled = true
min_usernames = 3
max_attempts_per_user = 3
window_seconds = 120

[detectors.enumeration]
enabled = true
threshold = 4
window_seconds = 60

[detectors.burst]
enabled = true
threshold = 5
window_seconds = 5

[risk]
# Threat score tiers (0-100)
medium_threshold = 40
high_threshold = 70
critical_threshold = 85

# Scoring weights
failed_auth_weight = 5
invalid_user_weight = 10
burst_velocity_weight = 25
brute_force_weight = 20
password_spray_weight = 20
enumeration_weight = 20
max_attempts_weight = 20
repeat_offender_weight = 15
success_auth_weight = -10
trusted_ip_discount = -100

# Trusted IP addresses (forced score 0)
trusted_ips = ["127.0.0.1", "::1", "localhost"]

[response]
# Response mode: dry_run, manual, automatic, disabled
# NOTE: Defaulted to 'dry_run' on initial installation for safety.
mode = "dry_run"

# Firewall backend: nftables, mock
backend = "nftables"

# Action thresholds
isolation_threshold = 85
rate_limit_threshold = 60

# Ban duration in seconds (900s = 15m, 3600s = 1h, 86400s = 24h)
default_ban_duration_seconds = 900
repeat_offender_ban_duration_seconds = 3600
max_ban_duration_seconds = 86400

# Subnet allowlist protected from host isolation
allowlist_cidrs = [
    "127.0.0.0/8",
    "::1/128",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
]

# Dedicated nftables table namespace (will NOT touch host firewall rules)
table_name = "bastion"

[telemetry]
# Telemetry ingestion source: journald, file, stdin
source = "journald"
# systemd journal units to monitor
journal_units = ["ssh.service", "sshd.service"]
journal_identifier = "sshd"
log_file_path = ""

[daemon]
# Health check interval and health JSON dump frequency (seconds)
health_check_interval_seconds = 30
# Periodic firewall state reconciliation interval (seconds)
reconciliation_interval_seconds = 60
# Retry backoff for transient collector reconnection (seconds)
journal_retry_backoff_seconds = 5
# Maximum consecutive collector retries before marking telemetry degraded
max_collector_retries = 10
# Location of the runtime health state JSON snapshot
health_state_path = "/var/lib/bastion/health.json"
# Logging level: DEBUG, INFO, WARNING, ERROR, CRITICAL
log_level = "INFO"
# Logging format: text, json
log_format = "text"
EOF

    chmod 0640 "${target_file}"
    chown root:bastion "${target_file}"
}

install_application_package() {
    local source_dir="${1:-.}"
    
    # 1. Create or verify dedicated virtual environment in /opt/bastion/venv
    if [[ ! -d "${VENV_PATH}" ]]; then
        "${PYTHON_BIN}" -m venv "${VENV_PATH}"
    fi

    # 2. Upgrade pip and build tooling inside the venv
    "${VENV_PATH}/bin/pip" install --upgrade --quiet pip setuptools wheel

    # 3. Clean install package into venv
    "${VENV_PATH}/bin/pip" install --quiet "${source_dir}"

    # 4. Create binary symlink in /usr/local/bin
    mkdir -p "$(dirname "${BIN_LINK}")"
    ln -sf "${VENV_PATH}/bin/bastion" "${BIN_LINK}"

    # Optional secondary symlink in /usr/bin if /usr/local/bin is not in default PATH
    if [[ -d "/usr/bin" ]] && [[ ! -e "${ALT_BIN_LINK}" ]]; then
        ln -sf "${VENV_PATH}/bin/bastion" "${ALT_BIN_LINK}" || true
    fi
}

initialize_database() {
    # Execute database initialization and schema migration via installed CLI
    "${VENV_PATH}/bin/bastion" --config "${CONFIG_FILE}" db init >/dev/null 2>&1
    
    # Ensure database file permissions are correct
    if [[ -f "${DATA_DIR}/bastion.db" ]]; then
        chown -R bastion:bastion "${DATA_DIR}"
        chmod 0640 "${DATA_DIR}/bastion.db"
    fi
}
