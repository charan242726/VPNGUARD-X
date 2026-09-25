"""Explicitly authorized, read-only local IPsec gateway telemetry collection."""

from __future__ import annotations

import shutil
import subprocess
from typing import Any

from .cooperative import cooperative_evidence_from_swanctl, cooperative_evidence_from_xfrm


def _read_command(command: list[str]) -> str | None:
    """Return stdout only; raw command output is never persisted or logged."""
    if shutil.which(command[0]) is None:
        return None
    result = subprocess.run(command, check=False, text=True, capture_output=True, timeout=15)
    return result.stdout if result.returncode == 0 else None


def collect_local_gateway_telemetry(*, authorized: bool) -> dict[str, Any]:
    """Return normalized, non-secret endpoint facts from this Linux gateway.

    This deliberately invokes fixed read-only commands.  It never reads
    strongSwan configuration files and never stores raw outputs, keys, PSKs,
    or certificate private material.
    """
    if not authorized:
        raise PermissionError("explicit authorization acknowledgement is required")
    swanctl_raw = _read_command(["swanctl", "--list-sas", "--raw"])
    xfrm_raw = _read_command(["ip", "-s", "xfrm", "state"])
    if swanctl_raw is None and xfrm_raw is None:
        raise RuntimeError("no readable local strongSwan or Linux XFRM telemetry was available")
    values: dict[str, Any] = {}
    if swanctl_raw is not None:
        values.update({record.property_name: record.value for record in cooperative_evidence_from_swanctl(swanctl_raw).records if record.value is not None})
    if xfrm_raw is not None:
        values.update({record.property_name: record.value for record in cooperative_evidence_from_xfrm(xfrm_raw).records if record.value is not None})
    if not values:
        raise RuntimeError("gateway telemetry contained no active normalized IPsec SA facts")
    return values
