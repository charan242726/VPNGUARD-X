"""Narrow, administrator-authorized helper for local endpoint telemetry.

This module is launched only by the desktop application's explicit Gateway
Connector action through Polkit.  It does not accept a command to execute and
uses the same fixed, read-only collectors as the unprivileged backend.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from observability.local_gateway import collect_local_gateway_telemetry


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="write normalized local IPsec telemetry")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--uid", type=int, required=True)
    parser.add_argument("--gid", type=int, required=True)
    args = parser.parse_args(argv)
    if args.uid < 0 or args.gid < 0:
        raise ValueError("uid and gid must be non-negative")

    values = collect_local_gateway_telemetry(authorized=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(values, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(args.output, 0o600)
    os.chown(args.output, args.uid, args.gid)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
