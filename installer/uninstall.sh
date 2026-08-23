#!/usr/bin/env bash
# ==============================================================================
# B.A.S.T.I.O.N. - Official Linux Host Uninstallation Script
# ==============================================================================

set -euo pipefail

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source modular libraries
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib/common.sh"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib/detect_os.sh"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib/filesystem.sh"

# Default uninstallation options
NON_INTERACTIVE="${NON_INTERACTIVE:-0}"
PURGE_DATA=0
PURGE_ALL=0
FORCE=0

show_help() {
    print_banner "B.A.S.T.I.O.N. Uninstaller"
    cat << EOF
Usage: sudo ./uninstall.sh [OPTIONS]

Options:
  -h, --help               Show this help message and exit
  -y, --yes, --non-interactive
                           Run in non-interactive mode
  --keep-data              Retain database and logs (Default: safe forensic mode)
  --purge-data             Remove database and log files (/var/lib/bastion, /var/log/bastion)
  --purge-all              Remove all files including configuration and service accounts
  -f, --force              Force removal without confirmation prompts

Examples:
  sudo ./uninstall.sh
  sudo ./uninstall.sh --keep-data
  sudo ./uninstall.sh --purge-all --force
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
        --keep-data)
            PURGE_DATA=0
            PURGE_ALL=0
            shift
            ;;
        --purge-data)
            PURGE_DATA=1
            shift
            ;;
        --purge-all)
            PURGE_DATA=1
            PURGE_ALL=1
            shift
            ;;
        -f|--force)
            FORCE=1
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
    print_banner "B.A.S.T.I.O.N. Uninstaller"
    require_root

    if [[ "${FORCE}" -eq 0 ]] && [[ "${NON_INTERACTIVE}" -eq 0 ]]; then
        printf "\n"
        log_warn "This will remove B.A.S.T.I.O.N. Sentinel Core from this system."
        if ! confirm_action "Are you sure you want to proceed with uninstallation?" "n"; then
            log_info "Uninstallation cancelled by user."
            exit 0
        fi
    fi

    # 1. Stop and disable systemd service
    log_step "1" "6" "Stopping and disabling systemd service"
    if has_cmd systemctl; then
        systemctl stop bastion.service >/dev/null 2>&1 || true
        systemctl disable bastion.service >/dev/null 2>&1 || true
    fi
    log_step_pass

    # 2. Remove systemd unit file
    log_step "2" "6" "Removing systemd service unit"
    rm -f /etc/systemd/system/bastion.service
    if has_cmd systemctl; then
        systemctl daemon-reload >/dev/null 2>&1 || true
    fi
    log_step_pass

    # 3. Clean up firewall rules
    log_step "3" "6" "Cleaning up dedicated firewall table namespace"
    if has_cmd nft; then
        nft delete table inet bastion >/dev/null 2>&1 || true
    fi
    log_step_pass

    # 4. Remove application binaries and virtual environment
    log_step "4" "6" "Removing application binaries and environment"
    rm -f "${BIN_LINK}"
    rm -f "${ALT_BIN_LINK}"
    rm -rf "${INSTALL_PREFIX}"
    log_step_pass

    # 5. Handle configuration and data retention
    log_step "5" "6" "Processing data retention policies"
    if [[ "${PURGE_ALL}" -eq 1 ]]; then
        rm -rf "${CONFIG_DIR}"
        rm -rf "${DATA_DIR}"
        rm -rf "${LOG_DIR}"
        log_step_pass
    elif [[ "${PURGE_DATA}" -eq 1 ]]; then
        rm -rf "${DATA_DIR}"
        rm -rf "${LOG_DIR}"
        log_step_pass
    else
        log_step_skip "DATA_RETAINED"
        log_info "Forensic database retained at: ${DATA_DIR}/bastion.db"
        log_info "Configuration retained at: ${CONFIG_DIR}/bastion.toml"
    fi

    # 6. Service user/group removal
    log_step "6" "6" "Removing service accounts"
    if [[ "${PURGE_ALL}" -eq 1 ]]; then
        if getent passwd bastion >/dev/null 2>&1; then
            userdel bastion >/dev/null 2>&1 || true
        fi
        if getent group bastion >/dev/null 2>&1; then
            groupdel bastion >/dev/null 2>&1 || true
        fi
        log_step_pass
    else
        log_step_skip "USER_RETAINED"
    fi

    cat << EOF

${GREEN}${BOLD}B.A.S.T.I.O.N. uninstallation complete.${RESET}
The application service and binaries have been removed.
EOF
}

main
