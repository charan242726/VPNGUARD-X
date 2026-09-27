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

if ! "$PYTHON_BIN" -c 'import sys; sys.exit(0 if (3, 12) <= sys.version_info[:2] < (3, 13) else 1)' 2>/dev/null; then
  echo "VPNGUARD-X requires Python 3.12 (the ML runtime is pinned to that supported version). Found: $($PYTHON_BIN --version 2>&1)" >&2
  echo "Set PYTHON_BIN to a Python 3.12 executable and rerun this script." >&2
  exit 1
fi

if ! node -e 'const [major, minor] = process.versions.node.split(".").map(Number); process.exit(major >= 23 || (major === 22 && minor >= 12) ? 0 : 1)' >/dev/null 2>&1; then
  echo "VPNGUARD-X desktop requires Node.js 22.12 or newer (Electron 44/Vite 8). Found: $(node --version 2>&1)" >&2
  echo "Install a current Node.js release, then rerun this script. The distro nodejs package may be too old." >&2
  exit 1
fi

cd "$ROOT_DIR"
mkdir -p "$(dirname "$APP_VENV")"
"$PYTHON_BIN" -m venv "$APP_VENV"
"$APP_VENV/bin/python" -m pip install --upgrade pip
"$APP_VENV/bin/python" -m pip install -e '.[ml]'
npm --prefix vpnguardx-desktop install

# Make the desktop menu launch this checkout, not an older similarly named
# prototype that may be installed elsewhere on the workstation.
DESKTOP_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
mkdir -p "$DESKTOP_DIR"
sed "s|@ROOT_DIR@|$ROOT_DIR|g" "$ROOT_DIR/packaging/vpnguardx.desktop.in" > "$DESKTOP_DIR/vpnguardx.desktop"

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
echo "  ./scripts/launch-desktop.sh"
echo "For a Debian package: cd vpnguardx-desktop && npm run dist:deb"
echo "Python runtime installed at: $APP_VENV"
echo "Desktop launcher installed at: $DESKTOP_DIR/vpnguardx.desktop"
echo "Live capture is limited to interfaces you are authorized to monitor."
