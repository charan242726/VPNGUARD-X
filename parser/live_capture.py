"""Authorized local live-capture wrapper with a fixed defensive BPF filter."""

from __future__ import annotations

import json
import shutil
import signal
import socket
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from common.provenance import sha256_file


IPSEC_CAPTURE_FILTER = "udp port 500 or udp port 4500 or ip proto 50 or ip6 proto 50"


def available_interfaces() -> set[str]:
    return {name for _, name in socket.if_nameindex()}


def capture_live(
    interface: str,
    output_path: str | Path,
    *,
    duration_seconds: int,
    authorized: bool,
) -> dict[str, Any]:
    if not authorized:
        raise PermissionError("explicit authorization acknowledgement is required")
    if interface not in available_interfaces():
        raise ValueError("interface must be an existing local interface")
    if duration_seconds < 1 or duration_seconds > 3600:
        raise ValueError("duration_seconds must be between 1 and 3600")
    tcpdump = shutil.which("tcpdump")
    if tcpdump is None:
        raise RuntimeError("tcpdump is required for live capture")
    selected = Path(output_path).resolve()
    selected.parent.mkdir(parents=True, exist_ok=True)
    version = subprocess.run([tcpdump, "--version"], check=False, text=True, capture_output=True, timeout=10).stdout.splitlines()[0]
    command = [tcpdump, "-i", interface, "-s", "0", "-U", "-w", str(selected), IPSEC_CAPTURE_FILTER]
    started = datetime.now(timezone.utc).isoformat()
    process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    try:
        time.sleep(duration_seconds)
        process.send_signal(signal.SIGINT)
        _, stderr = process.communicate(timeout=15)
    except Exception:
        process.kill()
        process.wait(timeout=5)
        raise
    if process.returncode not in {0, 130, -signal.SIGINT}:
        raise RuntimeError(f"tcpdump failed: {stderr.strip()}")
    if not selected.exists() or selected.stat().st_size < 24:
        raise RuntimeError("tcpdump did not produce a classic-PCAP header")
    manifest = {
        "capture_file": str(selected),
        "capture_sha256": sha256_file(selected),
        "interface": interface,
        "filter": IPSEC_CAPTURE_FILTER,
        "duration_seconds": duration_seconds,
        "started_at_utc": started,
        "completed_at_utc": datetime.now(timezone.utc).isoformat(),
        "tcpdump_version": version,
        "authorization_acknowledged": True,
        "active_probe_performed": False,
    }
    selected.with_suffix(selected.suffix + ".manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest
