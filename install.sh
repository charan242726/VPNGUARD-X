#!/usr/bin/env bash
# VPNGUARD-X Linux developer/prototype installer.
# This script never launches the desktop application as root.
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3.12}"
APP_VENV="${XDG_CONFIG_HOME:-$HOME/.config}/VPNGUARD-X/.venv"

if [ "$(uname -s)" != "Linux" ]; then
  echo "VPNGUARD-X desktop installer currently supports Linux only." >&2
  exit 1
fi

need_command() { command -v "$1" >/dev/null 2>&1; }

if ! need_command "$PYTHON_BIN" || ! need_command node || ! need_command npm || ! need_command setcap; then
  if ! need_command apt-get; then
    echo "Missing prerequisites. Install Python 3.12, Node.js/npm, libcap2-bin, and dumpcap manually." >&2
    exit 1
  fi
  echo "System prerequisites are missing. Administrator approval is required to install them."
  sudo apt-get update
  sudo apt-get install -y python3.12 python3.12-venv nodejs npm libcap2-bin wireshark-common
fi

if ! need_command dumpcap; then
  echo "dumpcap was not installed. Install wireshark-common, then rerun this script." >&2
  exit 1
fi

cd "$ROOT_DIR"
mkdir -p "$(dirname "$APP_VENV")"
"$PYTHON_BIN" -m venv "$APP_VENV"
"$APP_VENV/bin/python" -m pip install --upgrade pip
"$APP_VENV/bin/python" -m pip install -e '.[ml]'
npm --prefix vpnguardx-desktop install

echo
echo "Optional authorized live-capture capability: only dumpcap receives CAP_NET_RAW/CAP_NET_ADMIN."
read -r -p "Grant this capability now? [y/N] " grant_capture
if [[ "$grant_capture" =~ ^[Yy]$ ]]; then
  DUMPCAP_BIN="$(command -v dumpcap)"
  sudo setcap cap_net_raw,cap_net_admin=eip "$DUMPCAP_BIN"
  getcap "$DUMPCAP_BIN"
fi

echo
echo "Installation complete. Start the desktop prototype with:"
echo "  cd vpnguardx-desktop && npm run dev"
echo "For a Debian package: cd vpnguardx-desktop && npm run dist:deb"
echo "Python runtime installed at: $APP_VENV"
echo "Live capture is limited to interfaces you are authorized to monitor."
