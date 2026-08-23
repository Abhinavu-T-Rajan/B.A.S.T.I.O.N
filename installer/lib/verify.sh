#!/usr/bin/env bash
# ==============================================================================
# B.A.S.T.I.O.N. Installer - Post-Installation Verification
# ==============================================================================

set -euo pipefail

run_post_install_verification() {
    local service_started="${1:-1}"
    local ver_errors=0

    # 1. CLI binary accessibility check
    if ! has_cmd bastion; then
        log_error "CLI binary 'bastion' not found in system PATH."
        ((ver_errors++)) || true
    fi

    # 2. Configuration validation
    if has_cmd bastion; then
        if ! bastion -c "${CONFIG_FILE}" config validate >/dev/null 2>&1; then
            log_error "Configuration validation check failed for '${CONFIG_FILE}'."
            ((ver_errors++)) || true
        fi
    fi

    # 3. Health diagnostics check
    if has_cmd bastion; then
        if ! bastion -c "${CONFIG_FILE}" health >/dev/null 2>&1; then
            log_warn "Operational health diagnostic probe returned warning status."
        fi
    fi

    # 4. Service status check (if service was supposed to start)
    if [[ "${service_started}" == "1" ]]; then
        if has_cmd systemctl; then
            if ! systemctl is-active --quiet bastion.service; then
                log_error "Service 'bastion.service' is not active."
                ((ver_errors++)) || true
            fi
        fi
    fi

    return "${ver_errors}"
}

display_completion_summary() {
    local service_state="ACTIVE"
    if ! systemctl is-active --quiet bastion.service 2>/dev/null; then
        service_state="STOPPED (or disabled)"
    fi

    local fw_status="READY (inet bastion)"
    if ! has_cmd nft; then
        fw_status="MOCK (nftables not installed)"
    fi

    cat << EOF

${GREEN}${BOLD}B.A.S.T.I.O.N. installation complete.${RESET}

${BOLD}Installation Summary:${RESET}
  Version       : v${BASTION_VERSION} (${BASTION_CODENAME})
  Configuration : ${CONFIG_FILE}
  Database      : ${DATA_DIR}/bastion.db
  Service       : ${service_state}
  Response Mode : ${YELLOW}${BOLD}DRY_RUN${RESET} (Safety Default)
  Firewall      : ${fw_status}

${BOLD}Next Steps & Administration:${RESET}
  1. Inspect operational health:
     ${CYAN}bastion health${RESET}

  2. Check platform statistics:
     ${CYAN}bastion status${RESET}

  3. Monitor live authentication events:
     ${CYAN}sudo journalctl -u bastion.service -f${RESET}

  4. When ready to enable automatic blocking, edit ${CONFIG_FILE}:
     ${CYAN}sudo nano ${CONFIG_FILE}${RESET}
     Set ${BOLD}mode = "automatic"${RESET}, then run:
     ${CYAN}sudo systemctl restart bastion.service${RESET}
EOF
}
