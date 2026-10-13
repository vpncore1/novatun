#!/usr/bin/env bash
# ==============================================================================
# novatun - High-Performance DPI-Resistant Tunnel Protocol
# Server Automated Production Installation & Systemd Hardening Script
# ==============================================================================
set -euo pipefail

# 1. Root Check
if [[ "${EUID}" -ne 0 ]]; then
    echo "[ERROR] This installer must be run as root (or via sudo)." >&2
    exit 1
fi

echo "=========================================================="
echo "          novatun Production Server Installer"
echo "=========================================================="

INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/novatun"
SERVER_BIN="${INSTALL_DIR}/novatun-server"
CONFIG_FILE="${CONFIG_DIR}/server.json"
SERVICE_FILE="/etc/systemd/system/novatun-server.service"

# 2. Check Prerequisites
if ! command -v openssl &>/dev/null; then
    echo "[INFO] Installing openssl..."
    if command -v apt-get &>/dev/null; then
        apt-get update -y && apt-get install -y openssl
    elif command -v yum &>/dev/null; then
        yum install -y openssl
    fi
fi

# 3. Create novatun System User and Directories
if ! id -u novatun &>/dev/null; then
    echo "[INFO] Creating unprivileged system user 'novatun'..."
    useradd --system --no-create-home --shell /usr/sbin/nologin novatun
fi

mkdir -p "${CONFIG_DIR}"
chmod 700 "${CONFIG_DIR}"

# 4. Binary Installation
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARENT_DIR="$(dirname "${SCRIPT_DIR}")"

if [[ -f "${SCRIPT_DIR}/novatun-server" ]]; then
    cp "${SCRIPT_DIR}/novatun-server" "${SERVER_BIN}"
elif [[ -f "${PARENT_DIR}/novatun-server" ]]; then
    cp "${PARENT_DIR}/novatun-server" "${SERVER_BIN}"
elif command -v go &>/dev/null && [[ -d "${PARENT_DIR}/cmd/server" ]]; then
    echo "[INFO] Building novatun-server binary from source..."
    (cd "${PARENT_DIR}" && go build -ldflags="-s -w" -o "${SERVER_BIN}" ./cmd/server)
else
    echo "[WARN] No novatun-server binary found in current directory. Please place novatun-server in ${INSTALL_DIR}"
    touch "${SERVER_BIN}"
fi

if [[ -f "${SERVER_BIN}" ]]; then
    chmod 755 "${SERVER_BIN}"
    # Allow binding to privileged ports (<1024 like 443) without root privileges
    if command -v setcap &>/dev/null; then
        setcap 'cap_net_bind_service=+ep' "${SERVER_BIN}" || true
    fi
fi

# 5. Generate Cryptographic Pre-Shared Key (PSK) and Camouflage Path
PSK_HEX=$(openssl rand -hex 32 2>/dev/null || od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
RAND_PATH="/api/v1/stream-$(openssl rand -hex 4 2>/dev/null || od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"
LISTEN_PORT="443"

# 6. Deploy Server Configuration
if [[ ! -f "${CONFIG_FILE}" ]]; then
    echo "[INFO] Generating secure configuration in ${CONFIG_FILE}..."
    cat <<EOF > "${CONFIG_FILE}"
{
  "listen": ":${LISTEN_PORT}",
  "psk": "${PSK_HEX}",
  "mode": "ws",
  "path": "${RAND_PATH}",
  "fallback_addr": "127.0.0.1:80",
  "log_level": "info"
}
EOF
    chmod 600 "${CONFIG_FILE}"
    chown -R novatun:novatun "${CONFIG_DIR}"
else
    echo "[INFO] Configuration ${CONFIG_FILE} already exists; preserving existing keys."
    PSK_HEX=$(grep -o '"psk": *"[^"]*"' "${CONFIG_FILE}" | cut -d'"' -f4)
    RAND_PATH=$(grep -o '"path": *"[^"]*"' "${CONFIG_FILE}" | cut -d'"' -f4)
fi

# 7. Install Systemd Service Unit with Security Sandbox Hardening
echo "[INFO] Installing systemd hardened service at ${SERVICE_FILE}..."
cat <<EOF > "${SERVICE_FILE}"
[Unit]
Description=novatun High-Performance DPI-Resistant Tunnel Server
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=novatun
Group=novatun
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
ExecStart=${SERVER_BIN} -config ${CONFIG_FILE}
Restart=always
RestartSec=3s
LimitNOFILE=1048576

# Hardening Directives
ProtectSystem=strict
ProtectHome=true
NoNewPrivileges=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
MemoryDenyWriteExecute=true
RestrictRealtime=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

# Read access to configuration file
ReadOnlyPaths=${CONFIG_DIR}

[Install]
WantedBy=multi-user.target
EOF

# 8. Reload Systemd and Enable Service
systemctl daemon-reload
systemctl enable novatun-server.service || true
if [[ -x "${SERVER_BIN}" && -s "${SERVER_BIN}" ]]; then
    systemctl restart novatun-server.service || true
fi

# 9. Determine Public IP
PUBLIC_IP=$(curl -s https://api.ipify.org || curl -s https://icanhazip.com || echo "YOUR_SERVER_IP")

echo ""
echo "=========================================================="
echo "          novatun Server Installed Successfully!"
echo "=========================================================="
echo "Status:   systemctl status novatun-server"
echo "Logs:     journalctl -u novatun-server -f"
echo "Config:   ${CONFIG_FILE}"
echo ""
echo "------------------- Client Configuration -----------------"
cat <<CLIENT_CONF
{
  "server": "${PUBLIC_IP}:${LISTEN_PORT}",
  "psk": "${PSK_HEX}",
  "mode": "ws",
  "host": "${PUBLIC_IP}",
  "path": "${RAND_PATH}",
  "socks": "127.0.0.1:1080",
  "tun": true,
  "tun_name": "novatun0"
}
CLIENT_CONF
echo "----------------------------------------------------------"
echo "Save this client config JSON to 'client.json' on your client device."
echo "=========================================================="
