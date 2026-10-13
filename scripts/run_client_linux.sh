#!/usr/bin/env bash
# ==============================================================================
# novatun - High-Performance DPI-Resistant Tunnel Protocol
# Linux Client Launcher with Root/TUN Capability Verification
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "${SCRIPT_DIR}")"
CLIENT_BIN="${SCRIPT_DIR}/novatun-client"

# 1. Locate client binary or build from source
if [[ ! -f "${CLIENT_BIN}" ]]; then
    if [[ -f "${PROJECT_ROOT}/novatun-client" ]]; then
        CLIENT_BIN="${PROJECT_ROOT}/novatun-client"
    elif command -v go &>/dev/null && [[ -d "${PROJECT_ROOT}/cmd/client" ]]; then
        echo "[INFO] novatun-client binary not found. Compiling from source..."
        (cd "${PROJECT_ROOT}" && go build -ldflags="-s -w" -o "${CLIENT_BIN}" ./cmd/client)
    fi
fi

if [[ ! -f "${CLIENT_BIN}" ]]; then
    echo "[FATAL] Unable to locate or build novatun-client binary." >&2
    exit 1
fi

chmod +x "${CLIENT_BIN}"

# 2. Determine config file
CONFIG_PATH="${SCRIPT_DIR}/client.json"
if [[ ! -f "${CONFIG_PATH}" && -f "${PROJECT_ROOT}/client.json" ]]; then
    CONFIG_PATH="${PROJECT_ROOT}/client.json"
fi

# 3. Check for root privileges (required for creating TUN interface and routing tables)
if [[ "${EUID}" -ne 0 ]]; then
    echo "[INFO] TUN interface allocation and routing configuration require root privileges."
    echo "[INFO] Elevating permissions via sudo..."
    if [[ -f "${CONFIG_PATH}" ]]; then
        exec sudo "${CLIENT_BIN}" -config "${CONFIG_PATH}" "$@"
    else
        exec sudo "${CLIENT_BIN}" "$@"
    fi
fi

if [[ -f "${CONFIG_PATH}" ]]; then
    echo "[INFO] Starting novatun client with configuration: ${CONFIG_PATH}"
    exec "${CLIENT_BIN}" -config "${CONFIG_PATH}" "$@"
else
    echo "[INFO] Starting novatun client with arguments: $*"
    exec "${CLIENT_BIN}" "$@"
fi
