# Security and authorization boundary

VPNGUARD-X is a defensive analyzer. Use it only with captures, interfaces, endpoint telemetry, and laboratory systems you are authorized to inspect.

- The software performs no scanning, exploitation, credential guessing, or public-target interaction.
- Live capture requires an explicit `--i-am-authorized` acknowledgement and uses a fixed IKE/ESP BPF filter on an existing local interface.
- The cyber-range accepts scenario IDs from the repository matrix only; traffic targets are hard-coded private/ULA addresses on Docker-internal networks.
- Never place production PSKs, private keys, IKE/ESP key material, or unredacted XFRM state in reports or datasets.
- `cyber_range/range.py` redacts XFRM keys before persistence. Treat generated `swanctl.conf` as private laboratory material and do not publish it.
- Uploaded PCAPs may contain sensitive addressing and timing metadata. Apply access controls and retention policy outside this prototype.

Report security defects privately to the project maintainers. Include the affected version and a minimal synthetic reproducer; do not include third-party secrets or captures.
