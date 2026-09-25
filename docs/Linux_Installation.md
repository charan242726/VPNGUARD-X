# VPNGUARD-X Linux Installation

VPNGUARD-X is a Linux-focused, local-first research prototype. The desktop UI
and PCAP analysis run locally; packet capture is permitted only on interfaces
the operator is authorized to monitor.

## Source installation (recommended for SIH demonstration)

```bash
git clone https://github.com/charan242726/ip-sec-vpn-analyzer-new-.git
cd ip-sec-vpn-analyzer-new-
./install.sh
./scripts/launch-desktop.sh
```

The installer creates the runtime at `~/.config/VPNGUARD-X/.venv`, installs the
model dependencies and Electron dependencies, and optionally requests
administrator approval to grant `dumpcap` packet-capture capability. The
desktop app and Python analyzer remain unprivileged.

## Debian package

Build a package from a source checkout:

```bash
cd vpnguardx-desktop
npm run dist:deb
```

Install the generated package on Debian/Ubuntu:

```bash
sudo apt install ./dist/VPNGUARD-X-1.0.0-amd64.deb
```

The package contains the Electron UI, backend source, and verified deployment
bundle. Before first model-backed analysis on a new machine, run `./install.sh`
from a trusted source checkout to install the supported local Python runtime.

## Capture permissions

Do not run VPNGUARD-X as root. If live capture is needed, authorize only
`dumpcap` (the installer offers this step):

```bash
sudo setcap cap_net_raw,cap_net_admin=eip "$(command -v dumpcap)"
getcap "$(command -v dumpcap)"
```

Use PCAP upload when capture permission is unavailable. Never import PSKs,
private keys, session keys, or raw VPN configuration files into the UI.
