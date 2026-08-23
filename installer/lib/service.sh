#!/usr/bin/env bash
# ==============================================================================
# B.A.S.T.I.O.N. Installer - systemd Service & Firewall Namespace Setup
# ==============================================================================

set -euo pipefail

SYSTEMD_UNIT_PATH="/etc/systemd/system/bastion.service"

prepare_firewall_namespace() {
    if ! has_cmd nft; then
        log_info "nft utility not found. B.A.S.T.I.O.N. will use mock/dry-run backend until nftables is available."
        return 0
    fi

    # Check for existing firewall rules
    local existing_tables=""
    existing_tables="$(nft list tables 2>/dev/null || echo "")"
    
    if [[ -n "${existing_tables}" ]]; then
        log_info "Existing host firewall rules detected. B.A.S.T.I.O.N. uses isolated namespace 'inet bastion'."
        log_info "Existing firewall rules will NOT be modified."
    fi

    # Initialize dedicated table inet bastion if not already present
    if ! nft list table inet bastion >/dev/null 2>&1; then
        nft add table inet bastion 2>/dev/null || true
        nft 'add set inet bastion blacklist_v4 { type ipv4_addr; flags timeout; }' 2>/dev/null || true
        nft 'add set inet bastion blacklist_v6 { type ipv6_addr; flags timeout; }' 2>/dev/null || true
        nft 'add chain inet bastion input { type filter hook input priority -100; policy accept; }' 2>/dev/null || true
        nft 'add rule inet bastion input ip saddr @blacklist_v4 drop' 2>/dev/null || true
        nft 'add rule inet bastion input ip6 saddr @blacklist_v6 drop' 2>/dev/null || true
    fi
}

install_systemd_unit() {
    local exec_bin="${VENV_PATH}/bin/bastion"
    local cfg_path="${CONFIG_FILE}"

    cat << EOF > "${SYSTEMD_UNIT_PATH}"
[Unit]
Description=B.A.S.T.I.O.N. Sentinel Core Security Service
Documentation=https://github.com/Abhinavu-T-Rajan/B.A.S.T.I.O.N
After=network.target systemd-journald.service
Wants=network.target

[Service]
Type=simple
ExecStart=${exec_bin} daemon --config ${cfg_path}
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5s

# Sandboxing and Least Privilege
CapabilityBoundingSet=CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_ADMIN
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=${DATA_DIR} ${LOG_DIR} /run/bastion
StateDirectory=bastion
RuntimeDirectory=bastion
LogsDirectory=bastion

# Resource and Signal Constraints
TimeoutStopSec=15s
KillMode=mixed
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    chmod 0644 "${SYSTEMD_UNIT_PATH}"
    systemctl daemon-reload
}

start_and_enable_service() {
    local start_service="${1:-1}"

    systemctl daemon-reload
    systemctl enable bastion.service >/dev/null 2>&1

    if [[ "${start_service}" == "1" ]]; then
        systemctl restart bastion.service || systemctl start bastion.service
        
        # Wait up to 5 seconds for service to achieve active status
        local attempts=0
        while [[ "${attempts}" -lt 10 ]]; do
            if systemctl is-active --quiet bastion.service; then
                return 0
            fi
            sleep 0.5
            ((attempts++)) || true
        done

        if ! systemctl is-active --quiet bastion.service; then
            log_error "bastion.service failed to transition to active state."
            log_info "Check service logs with: journalctl -u bastion.service -n 20"
            return 1
        fi
    else
        log_info "Service enabled but not started (--no-start specified)."
    fi

    return 0
}
