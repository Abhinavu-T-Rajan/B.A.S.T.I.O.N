#!/usr/bin/env bash
# ==============================================================================
# B.A.S.T.I.O.N. Installer - Package Dependencies Management
# ==============================================================================

set -euo pipefail

install_system_dependencies() {
    local pm="${PACKAGE_MANAGER:-unknown}"

    case "${pm}" in
        apt)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -qq
            apt-get install -y -qq --no-install-recommends \
                python3 \
                python3-venv \
                python3-pip \
                nftables \
                systemd \
                util-linux \
                curl \
                ca-certificates >/dev/null 2>&1
            ;;
        dnf)
            dnf install -y -q \
                python3 \
                python3-pip \
                nftables \
                systemd \
                util-linux \
                curl \
                ca-certificates >/dev/null 2>&1
            ;;
        yum)
            yum install -y -q \
                python3 \
                python3-pip \
                nftables \
                systemd \
                util-linux \
                curl \
                ca-certificates >/dev/null 2>&1
            ;;
        pacman)
            pacman -Sy --noconfirm --needed \
                python \
                python-pip \
                nftables \
                systemd \
                curl \
                ca-certificates >/dev/null 2>&1
            ;;
        zypper)
            zypper --non-interactive install -y \
                python3 \
                python3-pip \
                nftables \
                systemd \
                util-linux \
                curl \
                ca-certificates >/dev/null 2>&1
            ;;
        *)
            log_warn "Unknown package manager '${pm}'. Skipping automated OS package installation."
            log_info "Please ensure python3 (>=3.11), python3-venv, and nftables are installed."
            ;;
    esac

    # Re-detect python after dependency installation
    if ! detect_python; then
        log_error "Failed to locate Python 3.11+ after package installation."
        return 1
    fi

    # Verify python3 -m venv support
    if ! "${PYTHON_BIN}" -m venv --help >/dev/null 2>&1; then
        log_error "Python venv module ('python3 -m venv') is missing or not working."
        if [[ "${pm}" == "apt" ]]; then
            log_info "Attempting to install python3-venv explicitly..."
            apt-get install -y python3-venv >/dev/null 2>&1 || true
        fi
    fi

    return 0
}
