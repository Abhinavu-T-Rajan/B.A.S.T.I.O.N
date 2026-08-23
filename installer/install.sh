#!/usr/bin/env bash
# ==============================================================================
# B.A.S.T.I.O.N. - Official Linux Host Installation Script
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
source "${SCRIPT_DIR}/lib/dependencies.sh"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib/filesystem.sh"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib/service.sh"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib/verify.sh"

# Default runtime options
NON_INTERACTIVE="${NON_INTERACTIVE:-0}"
CHECK_ONLY=0
SKIP_DEPS=0
START_SERVICE=1
PACKAGE_SOURCE="${REPO_ROOT}"

show_help() {
    print_banner
    cat << EOF
Usage: sudo ./install.sh [OPTIONS]

Options:
  -h, --help               Show this help message and exit
  -y, --yes, --non-interactive
                           Run in non-interactive mode without prompts
  --check-only, --dry-run-check
                           Run preflight and OS checks without modifying system
  --no-deps                Skip system package installation step
  --no-start               Install and enable service without starting it immediately
  --prefix <DIR>           Override installation prefix (default: /opt/bastion)
  --config-dir <DIR>       Override configuration directory (default: /etc/bastion)
  --data-dir <DIR>         Override state/database directory (default: /var/lib/bastion)
  --source-dir <PATH>      Path to B.A.S.T.I.O.N. source code or package wheel

Examples:
  sudo ./install.sh
  sudo ./install.sh --non-interactive
  ./install.sh --check-only
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
        --check-only|--dry-run-check)
            CHECK_ONLY=1
            shift
            ;;
        --no-deps)
            SKIP_DEPS=1
            shift
            ;;
        --no-start)
            START_SERVICE=0
            shift
            ;;
        --prefix)
            INSTALL_PREFIX="$2"
            VENV_PATH="${INSTALL_PREFIX}/venv"
            shift 2
            ;;
        --config-dir)
            CONFIG_DIR="$2"
            CONFIG_FILE="${CONFIG_DIR}/bastion.toml"
            shift 2
            ;;
        --data-dir)
            DATA_DIR="$2"
            shift 2
            ;;
        --source-dir)
            PACKAGE_SOURCE="$2"
            shift 2
            ;;
        *)
            log_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

main() {
    print_banner

    # 1. Preflight & OS Detection
    log_step "1" "8" "Detecting operating system & environment"
    if run_preflight_checks; then
        log_step_pass
    else
        log_step_fail "PREFLIGHT_ERROR"
        log_error "Preflight checks failed. Please resolve the errors above."
        exit 1
    fi

    if [[ "${CHECK_ONLY}" -eq 1 ]]; then
        printf "\n"
        log_success "Preflight checks completed successfully (--check-only mode)."
        exit 0
    fi

    # Root privilege assertion for system modification
    require_root

    # 2. Dependency Installation
    log_step "2" "8" "Installing system dependencies"
    if [[ "${SKIP_DEPS}" -eq 1 ]]; then
        log_step_skip "FLAG_NO_DEPS"
    else
        if install_system_dependencies; then
            log_step_pass
        else
            log_step_fail "DEP_ERROR"
            exit 1
        fi
    fi

    # 3. Create Dedicated Service Account
    log_step "3" "8" "Creating dedicated service account"
    if create_service_account; then
        log_step_pass
    else
        log_step_fail "USER_ERROR"
        exit 1
    fi

    # 4. Standardized Filesystem Setup
    log_step "4" "8" "Configuring filesystem layout & permissions"
    if setup_directories && create_default_config; then
        log_step_pass
    else
        log_step_fail "FS_ERROR"
        exit 1
    fi

    # 5. Install Application Package into /opt/bastion/venv
    log_step "5" "8" "Installing application into /opt/bastion/venv"
    if install_application_package "${PACKAGE_SOURCE}"; then
        log_step_pass
    else
        log_step_fail "INSTALL_ERROR"
        exit 1
    fi

    # 6. Database Schema Provisioning
    log_step "6" "8" "Initializing database schema & migrations"
    if initialize_database; then
        log_step_pass
    else
        log_step_fail "DB_ERROR"
        exit 1
    fi

    # 7. Firewall & systemd Service Configuration
    log_step "7" "8" "Installing systemd service & firewall namespace"
    prepare_firewall_namespace
    install_systemd_unit
    if start_and_enable_service "${START_SERVICE}"; then
        log_step_pass
    else
        log_step_fail "SERVICE_ERROR"
        exit 1
    fi

    # 8. Post-Installation Verification
    log_step "8" "8" "Running operational health checks"
    if run_post_install_verification "${START_SERVICE}"; then
        log_step_pass
    else
        log_step_fail "VERIFY_WARNING"
    fi

    display_completion_summary
}

main
