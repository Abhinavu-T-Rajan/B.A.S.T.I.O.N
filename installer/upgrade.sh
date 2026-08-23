#!/usr/bin/env bash
# ==============================================================================
# B.A.S.T.I.O.N. - Official Linux Host Upgrade Script
# ==============================================================================

set -euo pipefail

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Source modular libraries
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib/common.sh"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib/detect_os.sh"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib/filesystem.sh"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib/service.sh"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib/verify.sh"

# Default upgrade options
NON_INTERACTIVE="${NON_INTERACTIVE:-0}"
BACKUP_DIR="/var/lib/bastion/backups"
PACKAGE_SOURCE="${REPO_ROOT}"
RESTART_SERVICE=1

show_help() {
    print_banner "B.A.S.T.I.O.N. Upgrader"
    cat << EOF
Usage: sudo ./upgrade.sh [OPTIONS]

Options:
  -h, --help               Show this help message and exit
  -y, --yes, --non-interactive
                           Run in non-interactive mode
  --backup-dir <DIR>       Directory to store pre-upgrade backups (default: /var/lib/bastion/backups)
  --source-dir <PATH>      Path to updated B.A.S.T.I.O.N. source code or package wheel
  --no-restart             Do not automatically restart service after upgrade

Examples:
  sudo ./upgrade.sh
  sudo ./upgrade.sh --non-interactive
EOF
}

# Parse CLI arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            show_help
            exit 0
            ;;
        -y|--yes|--non-interactive)
            NON_INTERACTIVE=1
            shift
            ;;
        --backup-dir)
            BACKUP_DIR="$2"
            shift 2
            ;;
        --source-dir)
            PACKAGE_SOURCE="$2"
            shift 2
            ;;
        --no-restart)
            RESTART_SERVICE=0
            shift
            ;;
        *)
            log_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

main() {
    print_banner "B.A.S.T.I.O.N. Upgrader"
    require_root

    local timestamp
    timestamp="$(date +%Y%m%d_%H%M%S)"
    mkdir -p "${BACKUP_DIR}"
    chmod 0700 "${BACKUP_DIR}"

    # 1. Backup Configuration and Database
    log_step "1" "7" "Creating pre-upgrade backups"
    local cfg_backup="${BACKUP_DIR}/bastion.toml.bak.${timestamp}"
    local db_backup="${BACKUP_DIR}/bastion.db.bak.${timestamp}"

    if [[ -f "${CONFIG_FILE}" ]]; then
        cp -p "${CONFIG_FILE}" "${cfg_backup}"
    fi

    if [[ -f "${DATA_DIR}/bastion.db" ]]; then
        # Use sqlite3 backup if available for atomic snapshot, or copy
        if has_cmd sqlite3; then
            sqlite3 "${DATA_DIR}/bastion.db" ".backup '${db_backup}'" 2>/dev/null || cp -p "${DATA_DIR}/bastion.db" "${db_backup}"
        else
            cp -p "${DATA_DIR}/bastion.db" "${db_backup}"
        fi
    fi
    log_step_pass

    # 2. Update Python Application Package
    log_step "2" "7" "Upgrading application in /opt/bastion/venv"
    if [[ ! -d "${VENV_PATH}" ]]; then
        log_error "Existing virtual environment not found at '${VENV_PATH}'. Run install.sh first."
        exit 1
    fi

    if "${VENV_PATH}/bin/pip" install --upgrade --quiet "${PACKAGE_SOURCE}"; then
        log_step_pass
    else
        log_step_fail "UPGRADE_ERROR"
        log_error "Failed to install updated package into virtual environment."
        exit 1
    fi

    # 3. Apply Database Migrations
    log_step "3" "7" "Applying database schema migrations"
    if "${VENV_PATH}/bin/bastion" --config "${CONFIG_FILE}" db init >/dev/null 2>&1; then
        log_step_pass
    else
        log_step_fail "MIGRATION_ERROR"
        log_error "Database migration failed. Rollback database from: ${db_backup}"
        exit 1
    fi

    # 4. Validate Configuration
    log_step "4" "7" "Validating configuration with updated schema"
    if "${VENV_PATH}/bin/bastion" --config "${CONFIG_FILE}" config validate >/dev/null 2>&1; then
        log_step_pass
    else
        log_step_fail "CONFIG_ERROR"
        log_error "Configuration validation failed. Check ${CONFIG_FILE}"
        exit 1
    fi

    # 5. Update systemd Service Unit
    log_step "5" "7" "Updating systemd service unit definition"
    install_systemd_unit
    log_step_pass

    # 6. Restart Service
    log_step "6" "7" "Restarting B.A.S.T.I.O.N. Sentinel Core service"
    if [[ "${RESTART_SERVICE}" -eq 1 ]]; then
        if systemctl restart bastion.service; then
            log_step_pass
        else
            log_step_fail "RESTART_ERROR"
            log_warn "Service failed to restart cleanly. Check 'journalctl -u bastion.service -n 20'"
        fi
    else
        log_step_skip "FLAG_NO_RESTART"
    fi

    # 7. Health Verification
    log_step "7" "7" "Verifying post-upgrade operational health"
    if run_post_install_verification "${RESTART_SERVICE}"; then
        log_step_pass
    else
        log_step_fail "HEALTH_WARNING"
    fi

    cat << EOF

${GREEN}${BOLD}B.A.S.T.I.O.N. upgrade complete.${RESET}

${BOLD}Upgrade Summary:${RESET}
  New Version   : v${BASTION_VERSION} (${BASTION_CODENAME})
  Config Backup : ${cfg_backup}
  DB Backup     : ${db_backup}
  Service       : $(systemctl is-active bastion.service 2>/dev/null || echo "inactive")

Run ${CYAN}bastion health${RESET} or ${CYAN}bastion status${RESET} to verify operational status.
EOF
}

main
