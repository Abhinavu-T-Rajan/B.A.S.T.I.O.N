#!/usr/bin/env bash
# ==============================================================================
# B.A.S.T.I.O.N. Installer - Common Utilities & Logging
# ==============================================================================

set -euo pipefail

# ANSI color codes
if [[ -t 1 ]] || [[ "${FORCE_COLOR:-0}" == "1" ]]; then
    BOLD=$'\033[1m'
    DIM=$'\033[2m'
    RED=$'\033[31m'
    GREEN=$'\033[32m'
    YELLOW=$'\033[33m'
    BLUE=$'\033[34m'
    CYAN=$'\033[36m'
    WHITE=$'\033[37m'
    RESET=$'\033[0m'
else
    BOLD=""
    DIM=""
    RED=""
    GREEN=""
    YELLOW=""
    BLUE=""
    CYAN=""
    WHITE=""
    RESET=""
fi

# Version definitions
BASTION_VERSION="0.3.1"
BASTION_CODENAME="Sentinel Core"

print_banner() {
    local title="${1:-Installer}"
    local line="v${BASTION_VERSION} (${BASTION_CODENAME}) - ${title}"
    printf "%b\n" "${BLUE}${BOLD}╔══════════════════════════════════════════════════════════════╗"
    printf "%b\n" "║        B.A.S.T.I.O.N. Host Intrusion Defense System          ║"
    printf "%b%-62s%b\n" "║        " "${line}" "║"
    printf "%b\n" "╚══════════════════════════════════════════════════════════════╝${RESET}"
}

log_step() {
    local step_num="$1"
    local total_steps="$2"
    local message="$3"
    printf "${BOLD}[%s/%s] %-48s${RESET}" "${step_num}" "${total_steps}" "${message}..."
}

log_step_pass() {
    printf " ${GREEN}${BOLD}PASS${RESET}\n"
}

log_step_fail() {
    local reason="${1:-FAILED}"
    printf " ${RED}${BOLD}%s${RESET}\n" "${reason}"
}

log_step_skip() {
    local reason="${1:-SKIPPED}"
    printf " ${YELLOW}${BOLD}%s${RESET}\n" "${reason}"
}

log_info() {
    printf "${CYAN}ℹ %s${RESET}\n" "$*"
}

log_success() {
    printf "${GREEN}${BOLD}✓ %s${RESET}\n" "$*"
}

log_warn() {
    printf "${YELLOW}${BOLD}⚠ %s${RESET}\n" "$*"
}

log_error() {
    printf "${RED}${BOLD}❌ %s${RESET}\n" "$*" >&2
}

require_root() {
    if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
        log_error "This script requires root privileges to configure system services."
        printf "Please run with: ${BOLD}sudo %s${RESET}\n" "$0" >&2
        exit 1
    fi
}

has_cmd() {
    command -v "$1" >/dev/null 2>&1
}

confirm_action() {
    local prompt="$1"
    local default_ans="${2:-y}"
    
    if [[ "${NON_INTERACTIVE:-0}" == "1" ]]; then
        return 0
    fi

    local choice
    if [[ "${default_ans}" =~ ^[Yy]$ ]]; then
        read -r -p "${prompt} [Y/n]: " choice
        choice="${choice:-y}"
    else
        read -r -p "${prompt} [y/N]: " choice
        choice="${choice:-n}"
    fi

    if [[ "${choice}" =~ ^[Yy]$ ]]; then
        return 0
    else
        return 1
    fi
}
