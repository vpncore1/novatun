#!/usr/bin/env bash
# ==============================================================================
# novatun - Unified One-Line Installer & Manager
# Supports:
# 1) Kharej Server (Exit Node / Uplink)
# 2) Iran Relay / Client (Inbound Gateway)
# ==============================================================================
set -euo pipefail

# Color Codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/novatun"
KHAREJ_CONFIG="${CONFIG_DIR}/kharej.json"
IRAN_CONFIG="${CONFIG_DIR}/iran.json"
KHAREJ_SERVICE="/etc/systemd/system/novatun-kharej.service"
IRAN_SERVICE="/etc/systemd/system/novatun-iran.service"
GITHUB_REPO="vpncore1/novatun"

# Helper print functions
info() { echo -e "${BLUE}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# Root Check
check_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        error "This script must be run as root. Please run with 'sudo -i' or as root user."
        exit 1
    fi
}

# Detect Arch
detect_arch() {
    ARCH=$(uname -m)
    case "${ARCH}" in
        x86_64|amd64)
            GOARCH="amd64"
            ;;
        aarch64|arm64)
            GOARCH="arm64"
            ;;
        *)
            error "Unsupported architecture: ${ARCH}. Supported architectures: amd64, arm64."
            exit 1
            ;;
    esac
    info "Detected CPU Architecture: ${GOARCH}"
}

# Dependency Setup
ensure_deps() {
    local missing=()
    for cmd in curl jq openssl tar; do
        if ! command -v "${cmd}" &>/dev/null; then
            missing+=("${cmd}")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        info "Installing required dependencies: ${missing[*]}..."
        if command -v apt-get &>/dev/null; then
            apt-get update -y && apt-get install -y "${missing[@]}"
        elif command -v yum &>/dev/null; then
            yum install -y "${missing[@]}"
        fi
    fi
}

# Download or build binaries
install_binaries() {
    detect_arch
    mkdir -p "${INSTALL_DIR}" "${CONFIG_DIR}"
    chmod 755 "${INSTALL_DIR}"
    chmod 700 "${CONFIG_DIR}"

    info "Fetching latest release from GitHub (${GITHUB_REPO})..."
    local release_json
    release_json=$(curl -s "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" || true)
    local download_url=""

    if [[ -n "${release_json}" ]] && echo "${release_json}" | jq -e '.assets' &>/dev/null; then
        download_url=$(echo "${release_json}" | jq -r ".assets[] | select(.name | contains(\"linux-${GOARCH}\") and endswith(\".tar.gz\")) | .browser_download_url" | head -n 1)
    fi

    local installed=false
    if [[ -n "${download_url}" && "${download_url}" != "null" ]]; then
        info "Downloading precompiled binary from: ${download_url}..."
        local tmp_archive="/tmp/novatun.tar.gz"
        if curl -fsSL -o "${tmp_archive}" "${download_url}"; then
            tar -xzf "${tmp_archive}" -C /tmp/
            if [[ -f "/tmp/novatun-server" && -f "/tmp/novatun-client" ]]; then
                mv /tmp/novatun-server "${INSTALL_DIR}/novatun-server"
                mv /tmp/novatun-client "${INSTALL_DIR}/novatun-client"
                chmod 755 "${INSTALL_DIR}/novatun-server" "${INSTALL_DIR}/novatun-client"
                installed=true
                success "Binaries installed from GitHub Release successfully."
            fi
            rm -f "${tmp_archive}"
        fi
    fi

    # Fallback to local build if no binary was downloaded
    if [[ "${installed}" = false ]]; then
        if [[ -f "./novatun-server" && -f "./novatun-client" ]]; then
            info "Using binaries from local directory..."
            cp ./novatun-server "${INSTALL_DIR}/novatun-server"
            cp ./novatun-client "${INSTALL_DIR}/novatun-client"
            chmod 755 "${INSTALL_DIR}/novatun-server" "${INSTALL_DIR}/novatun-client"
            installed=true
        elif command -v go &>/dev/null; then
            info "Building novatun binaries from source using local Go toolchain..."
            go build -trimpath -ldflags="-s -w" -o "${INSTALL_DIR}/novatun-server" ./cmd/server
            go build -trimpath -ldflags="-s -w" -o "${INSTALL_DIR}/novatun-client" ./cmd/client
            chmod 755 "${INSTALL_DIR}/novatun-server" "${INSTALL_DIR}/novatun-client"
            installed=true
            success "Binaries compiled and installed successfully."
        else
            error "Could not download release assets and Go is not installed to compile from source."
            error "Please install Go ('apt install golang -y') or make sure release assets exist on GitHub."
            exit 1
        fi
    fi

    # Capability for low port binding (< 1024)
    if command -v setcap &>/dev/null; then
        setcap 'cap_net_bind_service=+ep' "${INSTALL_DIR}/novatun-server" || true
    fi
}

get_public_ip() {
    local ip
    ip=$(curl -s -4 https://api.ipify.org || curl -s -4 https://icanhazip.com || echo "YOUR_SERVER_IP")
    echo "${ip}"
}

# 1. Install Kharej Server
install_kharej() {
    echo ""
    echo -e "${CYAN}====================================================${NC}"
    echo -e "${BOLD}       Install / Update Server Kharej (Exit Node)${NC}"
    echo -e "${CYAN}====================================================${NC}"

    ensure_deps
    install_binaries

    local default_port="443"
    read -rp "Enter listen port [Default: ${default_port}]: " listen_port
    listen_port="${listen_port:-$default_port}"

    local default_psk
    default_psk=$(openssl rand -hex 32)
    read -rp "Enter PSK (32-byte hex) [Press ENTER to generate random]: " input_psk
    local psk="${input_psk:-$default_psk}"

    local rand_suffix
    rand_suffix=$(openssl rand -hex 4)
    local default_path="/api/v1/stream-${rand_suffix}"
    read -rp "Enter WebSocket Camouflage Path [Default: ${default_path}]: " input_path
    local path="${input_path:-$default_path}"

    local default_fallback="127.0.0.1:80"
    read -rp "Enter Fallback Web Address for Active Probing [Default: ${default_fallback}]: " input_fallback
    local fallback="${input_fallback:-$default_fallback}"

    cat <<EOF > "${KHAREJ_CONFIG}"
{
  "listen": ":${listen_port}",
  "psk": "${psk}",
  "mode": "ws",
  "path": "${path}",
  "fallback_addr": "${fallback}",
  "log_level": "info"
}
EOF
    chmod 600 "${KHAREJ_CONFIG}"
    success "Configuration written to ${KHAREJ_CONFIG}"

    # Systemd Service
    cat <<EOF > "${KHAREJ_SERVICE}"
[Unit]
Description=novatun Kharej Server Daemon
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/novatun-server -config ${KHAREJ_CONFIG}
Restart=always
RestartSec=3s
LimitNOFILE=65535

# Hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadOnlyPaths=${CONFIG_DIR}

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable novatun-kharej.service
    systemctl restart novatun-kharej.service

    local pub_ip
    pub_ip=$(get_public_ip)

    echo ""
    echo -e "${GREEN}====================================================${NC}"
    echo -e "${BOLD}       Kharej Server Installed and Started!         ${NC}"
    echo -e "${GREEN}====================================================${NC}"
    echo -e "Status:  ${CYAN}systemctl status novatun-kharej${NC}"
    echo -e "Logs:    ${CYAN}journalctl -u novatun-kharej -f${NC}"
    echo ""
    echo -e "${YELLOW}>>> COPY THE FOLLOWING INFO FOR SERVER IRAN: <<<${NC}"
    echo -e "----------------------------------------------------"
    echo -e "Kharej IP:   ${BOLD}${pub_ip}${NC}"
    echo -e "Port:        ${BOLD}${listen_port}${NC}"
    echo -e "PSK:         ${BOLD}${psk}${NC}"
    echo -e "Path:        ${BOLD}${path}${NC}"
    echo -e "----------------------------------------------------"
    echo ""
}

# 2. Install Iran Relay
install_iran() {
    echo ""
    echo -e "${CYAN}====================================================${NC}"
    echo -e "${BOLD}    Install / Update Server Iran (Relay / Client)${NC}"
    echo -e "${CYAN}====================================================${NC}"

    ensure_deps
    install_binaries

    read -rp "Enter Remote Kharej Server IP: " kharej_ip
    while [[ -z "${kharej_ip}" ]]; do
        error "Kharej Server IP cannot be empty!"
        read -rp "Enter Remote Kharej Server IP: " kharej_ip
    done

    read -rp "Enter Remote Kharej Server Port [Default: 443]: " kharej_port
    kharej_port="${kharej_port:-443}"

    read -rp "Enter 32-byte Hex PSK (from Kharej): " psk
    while [[ -z "${psk}" ]]; do
        error "PSK cannot be empty!"
        read -rp "Enter 32-byte Hex PSK: " psk
    done

    read -rp "Enter WebSocket Camouflage Path (from Kharej, e.g. /api/v1/stream-xxxx): " path
    while [[ -z "${path}" ]]; do
        error "Path cannot be empty!"
        read -rp "Enter WebSocket Camouflage Path: " path
    done

    read -rp "Enter SNI / Host Header [Default: ${kharej_ip}]: " host
    host="${host:-$kharej_ip}"

    read -rp "Enter Inbound SOCKS5 Listen Address [Default: 0.0.0.0:1080]: " socks
    socks="${socks:-0.0.0.0:1080}"

    read -rp "Enable System-Wide TUN VPN Mode? (y/N) [Default: n]: " enable_tun
    local tun_bool=false
    if [[ "${enable_tun}" =~ ^[Yy]$ ]]; then
        tun_bool=true
    fi

    cat <<EOF > "${IRAN_CONFIG}"
{
  "server": "${kharej_ip}:${kharej_port}",
  "psk": "${psk}",
  "mode": "ws",
  "host": "${host}",
  "path": "${path}",
  "socks": "${socks}",
  "tun": ${tun_bool},
  "tun_name": "novatun0",
  "log_level": "info"
}
EOF
    chmod 600 "${IRAN_CONFIG}"
    success "Configuration written to ${IRAN_CONFIG}"

    # Systemd Service
    cat <<EOF > "${IRAN_SERVICE}"
[Unit]
Description=novatun Iran Relay Daemon
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/novatun-client -config ${IRAN_CONFIG}
Restart=always
RestartSec=3s
LimitNOFILE=65535

# Hardening
NoNewPrivileges=false
ProtectSystem=full
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable novatun-iran.service
    systemctl restart novatun-iran.service

    local pub_ip
    pub_ip=$(get_public_ip)

    echo ""
    echo -e "${GREEN}====================================================${NC}"
    echo -e "${BOLD}       Iran Relay Installed and Started!            ${NC}"
    echo -e "${GREEN}====================================================${NC}"
    echo -e "Status:    ${CYAN}systemctl status novatun-iran${NC}"
    echo -e "Logs:      ${CYAN}journalctl -u novatun-iran -f${NC}"
    echo -e "Inbound:   ${BOLD}SOCKS5 running on ${pub_ip}:${socks}${NC}"
    echo ""
}

# 3. Show Config
show_config() {
    echo ""
    echo -e "${CYAN}================ Configuration Files ================${NC}"
    if [[ -f "${KHAREJ_CONFIG}" ]]; then
        echo -e "${BOLD}--- Server Kharej Config (${KHAREJ_CONFIG}) ---${NC}"
        cat "${KHAREJ_CONFIG}"
        echo ""
    fi
    if [[ -f "${IRAN_CONFIG}" ]]; then
        echo -e "${BOLD}--- Server Iran Config (${IRAN_CONFIG}) ---${NC}"
        cat "${IRAN_CONFIG}"
        echo ""
    fi
    if [[ ! -f "${KHAREJ_CONFIG}" && ! -f "${IRAN_CONFIG}" ]]; then
        warn "No configurations found in ${CONFIG_DIR}."
    fi
}

# 4. Status and Restart
status_and_restart() {
    echo ""
    echo -e "${CYAN}================ Service Management =================${NC}"
    echo "1) Restart Kharej Server"
    echo "2) Restart Iran Relay"
    echo "3) Check Kharej Status"
    echo "4) Check Iran Status"
    echo "5) View Kharej Live Logs"
    echo "6) View Iran Live Logs"
    read -rp "Select option [1-6]: " opt
    case "${opt}" in
        1) systemctl restart novatun-kharej && success "Kharej restarted." ;;
        2) systemctl restart novatun-iran && success "Iran restarted." ;;
        3) systemctl status novatun-kharej || true ;;
        4) systemctl status novatun-iran || true ;;
        5) journalctl -u novatun-kharej -f ;;
        6) journalctl -u novatun-iran -f ;;
        *) warn "Invalid option." ;;
    esac
}

# 5. Uninstall
uninstall_novatun() {
    echo ""
    read -rp "Are you sure you want to completely uninstall novatun? (y/N): " confirm
    if [[ ! "${confirm}" =~ ^[Yy]$ ]]; then
        info "Uninstallation canceled."
        return
    fi

    info "Stopping and disabling services..."
    systemctl stop novatun-kharej 2>/dev/null || true
    systemctl disable novatun-kharej 2>/dev/null || true
    systemctl stop novatun-iran 2>/dev/null || true
    systemctl disable novatun-iran 2>/dev/null || true

    rm -f "${KHAREJ_SERVICE}" "${IRAN_SERVICE}"
    systemctl daemon-reload

    info "Removing binaries and configuration..."
    rm -f "${INSTALL_DIR}/novatun-server" "${INSTALL_DIR}/novatun-client"
    rm -rf "${CONFIG_DIR}"

    success "novatun uninstalled completely from the system."
}

# Interactive Menu
show_menu() {
    clear
    echo -e "${CYAN}====================================================${NC}"
    echo -e "${BOLD}         novatun Protocol Management Tool           ${NC}"
    echo -e "       High-Performance DPI-Resistant Tunnel        ${NC}"
    echo -e "${CYAN}====================================================${NC}"
    echo -e " 1) Install / Update as ${BOLD}Server Kharej${NC} (Exit Node)"
    echo -e " 2) Install / Update as ${BOLD}Server Iran${NC} (Relay / Inbound Gateway)"
    echo -e " 3) Show Configurations"
    echo -e " 4) Service Status, Logs & Restart"
    echo -e " 5) Uninstall novatun"
    echo -e " 0) Exit"
    echo -e "${CYAN}====================================================${NC}"
    read -rp "Select an option [0-5]: " choice

    case "${choice}" in
        1) install_kharej ;;
        2) install_iran ;;
        3) show_config ;;
        4) status_and_restart ;;
        5) uninstall_novatun ;;
        0) exit 0 ;;
        *) error "Invalid choice. Please choose 0 to 5." ;;
    esac
}

main() {
    check_root
    if [[ $# -gt 0 ]]; then
        case "$1" in
            kharej) install_kharej ;;
            iran) install_iran ;;
            status) show_config ;;
            uninstall) uninstall_novatun ;;
            *) error "Unknown parameter: $1. Usage: $0 [kharej|iran|status|uninstall]" ;;
        esac
    else
        show_menu
    fi
}

main "$@"
