#!/usr/bin/env bash
# Produce a self-contained Ubuntu .deb or Fedora .rpm. Python analysis libraries
# are bundled; the target system supplies Python 3.12 and native OS libraries.
set -euo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
APP_DIR="$ROOT_DIR/vpnguardx-desktop"
RUNTIME_DIR="$APP_DIR/backend-runtime/python_packages"
TARGET="deb"
case "${1:-}" in
  --appimage) TARGET="appimage" ;;
  --rpm) TARGET="rpm" ;;
esac

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
if docker run --rm --volume "$ROOT_DIR:/workspace:ro" python:3.12-slim-bookworm \
  python -c 'import importlib.metadata as m,sys; sys.path.insert(0,"/workspace/vpnguardx-desktop/backend-runtime/python_packages"); expected={"PyYAML":"6.0.3","reportlab":"4.4.1","numpy":"2.2.1","scipy":"1.15.1","Pillow":"11.1.0","chardet":"5.2.0","xgboost":"3.4.1"}; sys.exit(0 if all(m.version(k)==v for k,v in expected.items()) else 1)' >/dev/null 2>&1; then
  echo "Using existing locked Python 3.12 runtime bundle."
else
  docker run --rm \
    --volume "$ROOT_DIR:/workspace" \
    --workdir /workspace \
    python:3.12-slim-bookworm \
    python -m pip install --disable-pip-version-check --no-warn-script-location \
      --no-deps --upgrade --target /workspace/vpnguardx-desktop/backend-runtime/python_packages \
      --requirement requirements/desktop-runtime.lock
fi

if [[ "$TARGET" == "appimage" ]]; then
  npm --prefix "$APP_DIR" run dist:appimage:pack
elif [[ "$TARGET" == "rpm" ]]; then
  docker run --rm \
    --volume "$ROOT_DIR:/workspace" \
    --workdir /workspace/vpnguardx-desktop \
    node:22-bookworm \
    sh -lc 'apt-get update >/dev/null && apt-get install -y rpm libgtk-3-0 libnss3 libxss1 libasound2 libatk1.0-0 libatk-bridge2.0-0 libatspi2.0-0 libcups2 libdrm2 libgbm1 libxkbcommon0 libx11-xcb1 libxcb-dri3-0 libxcomposite1 libxdamage1 libxfixes3 libxrandr2 libpango-1.0-0 >/dev/null && npm run dist:rpm:pack'
elif [[ "$TARGET" == "deb" ]]; then
  docker run --rm \
    --volume "$ROOT_DIR:/workspace" \
    --workdir /workspace/vpnguardx-desktop \
    node:22-bookworm \
    sh -lc 'apt-get update >/dev/null && apt-get install -y libgtk-3-0 libnss3 libxss1 libasound2 libatk1.0-0 libatk-bridge2.0-0 libatspi2.0-0 libcups2 libdrm2 libgbm1 libxkbcommon0 libx11-xcb1 libxcb-dri3-0 libxcomposite1 libxdamage1 libxfixes3 libxrandr2 libpango-1.0-0 >/dev/null && npm run dist:deb:pack'
else
  npm --prefix "$APP_DIR" run dist:appimage:pack
fi

case "$TARGET" in
  deb) PACKAGE_SUFFIX="*.deb" ;;
  rpm) PACKAGE_SUFFIX="*.rpm" ;;
  appimage) PACKAGE_SUFFIX="*.AppImage" ;;
esac
PACKAGE_FILE="$(find "$APP_DIR/dist" -maxdepth 1 -type f -name "$PACKAGE_SUFFIX" -print -quit)"
if [[ -z "$PACKAGE_FILE" ]]; then
  echo "Packaging completed but no $TARGET artifact was found in $APP_DIR/dist." >&2
  exit 1
fi
PRESERVED_DIR="$APP_DIR/packages/$TARGET"
mkdir -p "$PRESERVED_DIR"
cp "$PACKAGE_FILE" "$PRESERVED_DIR/"
(
  cd "$PRESERVED_DIR"
  sha256sum "$(basename "$PACKAGE_FILE")" > "$(basename "$PACKAGE_FILE").sha256"
)
echo "Package and SHA-256 saved under: $PRESERVED_DIR"
