# VPNGUARD-X Linux Installation

VPNGUARD-X is a Linux-focused, local-first research prototype. The desktop UI
and PCAP analysis run locally; packet capture is permitted only on interfaces
the operator is authorized to monitor.

Source installation requires Python 3.12 and Node.js 22.12 or newer. Some
Linux distributions ship an older Node.js in their default package repository;
the installer checks versions before downloading project dependencies and
prints the detected version if it is unsupported.

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

Use `./scripts/launch-desktop.sh` to open the Electron application. Do not
open the Vite development URL in a browser: it cannot access the local Python
backend or model bundle and is deliberately shown a blocking message instead
of a mock dashboard.

For live analysis, select the interface that sees the IPsec outer peer
addresses. A Docker lab typically uses its host bridge; a physical or cloud
gateway typically uses its underlay NIC. A VPN tunnel interface carries
decapsulated inner traffic and may not show native ESP. `any` or multiple
bridges can see the same packets, so matching assessments can be legitimate.
After capture, the sensor shows the interface, packet count, IKE/ESP counts,
and trace SHA-256. The technical PDF and evidence JSON preserve that capture
provenance. If no IPsec packets were captured, the app reports that and does
not create an assessment.

Confirm the backend and verified deployment bundle are usable with:

```bash
~/.config/VPNGUARD-X/.venv/bin/python vpnguardx.py health \
  --deployment artifacts/deployment_bundle --allow-demo-deployment
```

## Debian package

Build a self-contained package from a source checkout (Docker is used to stage
the locked Python 3.12 runtime libraries):

```bash
cd ip-sec-vpn-analyzer-new-
npm --prefix vpnguardx-desktop ci
npm --prefix vpnguardx-desktop run dist:deb
```

Install the generated package on Ubuntu 24.04 (amd64):

```bash
sudo apt install ./vpnguardx-desktop/dist/VPNGUARD-X-1.0.0-amd64.deb
```

The package contains the Electron UI, backend source, verified deployment
bundle, and locked Python analysis libraries. A compatible Python 3.12 runtime
and `dumpcap` are declared Debian dependencies, so installation does not
require a separate source checkout or a pip download. Open VPNGUARD-X from the
applications menu. PCAP analysis works without capture privileges; live
capture requires separately authorizing `dumpcap` as described below.

This `.deb` is not installable on Fedora. Fedora needs a separate RPM package
with Fedora-specific dependency names; do not convert this package with
`alien` or force-install it.

## Capture permissions

Do not run VPNGUARD-X as root. If live capture is needed, authorize only
`dumpcap` (the installer offers this step):

```bash
sudo setcap cap_net_raw,cap_net_admin=eip "$(command -v dumpcap)"
getcap "$(command -v dumpcap)"
```

Use PCAP upload when capture permission is unavailable. Never import PSKs,
private keys, session keys, or raw VPN configuration files into the UI.
