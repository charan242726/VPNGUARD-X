#!/usr/bin/env bash
# Produce a self-contained Ubuntu 24.04 .deb. The target system only needs
# Python 3.12 (declared as a package dependency); Python libraries are bundled.
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
APP_DIR="$ROOT_DIR/vpnguardx-desktop"
RUNTIME_DIR="$APP_DIR/backend-runtime/python_packages"
TARGET="deb"
if [[ "${1:-}" == "--appimage" ]]; then TARGET="appimage"; fi

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required to build the Python 3.12 dependency bundle." >&2
  exit 1
fi
if ! docker info >/dev/null 2>&1; then
  echo "Docker daemon is unavailable. Start Docker and ensure your user can access it." >&2
  exit 1
fi
if [[ ! -d "$APP_DIR/node_modules" ]]; then
  echo "Desktop dependencies are missing. Run: npm --prefix vpnguardx-desktop ci" >&2
  exit 1
fi

mkdir -p "$RUNTIME_DIR"
docker run --rm \
  --volume "$ROOT_DIR:/workspace" \
  --workdir /workspace \
  python:3.12-slim-bookworm \
  python -m pip install --disable-pip-version-check --no-warn-script-location \
    --no-deps --upgrade --target /workspace/vpnguardx-desktop/backend-runtime/python_packages \
    --requirement requirements/desktop-runtime.lock

if [[ "$TARGET" == "appimage" ]]; then
  npm --prefix "$APP_DIR" run dist:appimage:pack
else
  npm --prefix "$APP_DIR" run dist:deb:pack
fi

echo "Package built under: $APP_DIR/dist"
