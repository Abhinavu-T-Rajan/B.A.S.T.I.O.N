#!/usr/bin/env bash
# ==============================================================================
# B.A.S.T.I.O.N. Installer - OS & Environment Preflight Detection
# ==============================================================================

set -euo pipefail

# Exported detection variables
OS_ID="unknown"
OS_NAME="Unknown Linux"
OS_VERSION_ID="unknown"
OS_FAMILY="unknown"
PACKAGE_MANAGER="unknown"
ARCH="$(uname -m 2>/dev/null || echo "unknown")"
PYTHON_BIN=""
PYTHON_VERSION="unknown"

detect_os() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        source /etc/os-release
        OS_ID="${ID:-unknown}"
        OS_NAME="${PRETTY_NAME:-$NAME}"
        OS_VERSION_ID="${VERSION_ID:-unknown}"
    elif [[ -f /etc/redhat-release ]]; then
        OS_ID="rhel"
        OS_NAME="$(cat /etc/redhat-release)"
    elif [[ -f /etc/debian_version ]]; then
        OS_ID="debian"
        OS_NAME="Debian $(cat /etc/debian_version)"
    else
        OS_ID="unknown"
        OS_NAME="$(uname -s 2>/dev/null || echo "Linux")"
    fi

    # Determine distribution family and package manager
    case "${OS_ID}" in
        ubuntu|debian|pop|mint|kali|raspbian)
            OS_FAMILY="debian"
            PACKAGE_MANAGER="apt"
            ;;
        fedora|rhel|centos|rocky|almalinux|ol|amzn)
            OS_FAMILY="rhel"
            PACKAGE_MANAGER="dnf"
            if ! has_cmd dnf && has_cmd yum; then
                PACKAGE_MANAGER="yum"
            fi
            ;;
        arch|manjaro|endeavouros)
            OS_FAMILY="arch"
            PACKAGE_MANAGER="pacman"
            ;;
        opensuse*|sles)
            OS_FAMILY="suse"
            PACKAGE_MANAGER="zypper"
            ;;
        alpine)
            OS_FAMILY="alpine"
            PACKAGE_MANAGER="apk"
            ;;
        *)
            OS_FAMILY="generic"
            if has_cmd apt-get; then
                PACKAGE_MANAGER="apt"
            elif has_cmd dnf; then
                PACKAGE_MANAGER="dnf"
            elif has_cmd pacman; then
                PACKAGE_MANAGER="pacman"
            else
                PACKAGE_MANAGER="unknown"
            fi
            ;;
    esac
}

detect_python() {
    local candidates=("python3" "python3.12" "python3.11" "python3.13")
    for cand in "${candidates[@]}"; do
        if has_cmd "${cand}"; then
            local ver
            ver="$(${cand} -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || echo "")"
            if [[ -n "${ver}" ]]; then
                local major="${ver%%.*}"
                local minor="${ver#*.}"
                if [[ "${major}" -eq 3 ]] && [[ "${minor}" -ge 11 ]]; then
                    PYTHON_BIN="${cand}"
                    PYTHON_VERSION="${ver}"
                    return 0
                fi
            fi
        fi
    done
    return 1
}

check_disk_space_mb() {
    local target_dir="${1:-/var/lib}"
    mkdir -p "${target_dir}" 2>/dev/null || target_dir="/tmp"
    local avail_kb
    avail_kb="$(df -k "${target_dir}" 2>/dev/null | awk 'NR==2 {print $4}')"
    if [[ -n "${avail_kb}" ]]; then
        echo $((avail_kb / 1024))
    else
        echo 1000
    fi
}

run_preflight_checks() {
    detect_os
    
    local preflight_errors=0
    local preflight_warnings=0

    # 1. Architecture Check
    case "${ARCH}" in
        x86_64|amd64|aarch64|arm64)
            ;;
        *)
            log_warn "Architecture '${ARCH}' is experimental. Official support is for x86_64 and aarch64."
            ((preflight_warnings++)) || true
            ;;
    esac

    # 2. Python Version Check
    if ! detect_python; then
        log_error "Python 3.11 or higher is required but not found in system PATH."
        log_info "The installer can attempt to install python3 and python3-venv via '${PACKAGE_MANAGER}'."
    fi

    # 3. systemd Check
    if ! has_cmd systemctl; then
        log_error "systemd is required for B.A.S.T.I.O.N. service management but 'systemctl' was not found."
        ((preflight_errors++)) || true
    fi

    # 4. journald Check
    if ! has_cmd journalctl; then
        log_warn "journalctl was not found. Live systemd-journald telemetry collection requires journalctl."
        ((preflight_warnings++)) || true
    fi

    # 5. nftables Check
    if ! has_cmd nft; then
        log_warn "nftables user utility 'nft' is not currently installed. It will be installed during dependencies step."
    fi

    # 6. Disk Space Check
    local free_mb
    free_mb="$(check_disk_space_mb "/var/lib")"
    if [[ "${free_mb}" -lt 250 ]]; then
        log_error "Insufficient disk space: ${free_mb}MB available in /var/lib (minimum 250MB required)."
        ((preflight_errors++)) || true
    fi

    return "${preflight_errors}"
}
