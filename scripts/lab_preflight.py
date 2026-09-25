#!/usr/bin/env python3
"""Record a non-secret laboratory environment fingerprint and readiness gates."""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from common.provenance import sha256_file


def _command(command: list[str]) -> dict:
    try:
        result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, timeout=30, check=False)
        return {
            "available": True,
            "returncode": result.returncode,
            "stdout": result.stdout.strip()[:4000],
            "stderr": result.stderr.strip()[:4000],
        }
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return {"available": False, "error": f"{type(exc).__name__}: {exc}"}


def preflight() -> dict:
    disk = shutil.disk_usage(ROOT)
    python_ok = sys.version_info[:2] == (3, 12)
    docker = _command(["docker", "version", "--format", "{{json .}}"])
    compose = _command(["docker", "compose", "version", "--short"])
    compose_config = _command(["docker", "compose", "-f", str(ROOT / "cyber_range/compose.yaml"), "config", "--quiet"])
    interop_config = _command(["docker", "compose", "-f", str(ROOT / "cyber_range/compose.libreswan.yaml"), "config", "--quiet"])
    tests = _command([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"])
    gates = {
        "linux_host": platform.system() == "Linux",
        "python_3_12": python_ok,
        "docker_engine_reachable": docker.get("returncode") == 0,
        "docker_compose_available": compose.get("returncode") == 0,
        "strongswan_compose_valid": compose_config.get("returncode") == 0,
        "libreswan_compose_valid": interop_config.get("returncode") == 0,
        "unit_tests_pass": tests.get("returncode") == 0,
        "free_space_at_least_100_gib": disk.free >= 100 * 1024**3,
    }
    return {
        "schema_version": "0.2.0",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "platform": platform.platform(),
        "kernel": platform.release(),
        "machine": platform.machine(),
        "cpu_count": os.cpu_count(),
        "python": sys.version,
        "repository_root": str(ROOT),
        "scenario_matrix_sha256": sha256_file(ROOT / "data/CyberRange_Scenario_Matrix.csv"),
        "benchmark_design_sha256": sha256_file(ROOT / "configs/benchmark_design.yaml"),
        "free_disk_bytes": disk.free,
        "docker": docker,
        "compose": compose,
        "compose_strongswan_validation": compose_config,
        "compose_libreswan_validation": interop_config,
        "tests": tests,
        "gates": gates,
        "ready_for_strongswan_pilot": all(
            gates[name]
            for name in (
                "linux_host", "python_3_12", "docker_engine_reachable",
                "docker_compose_available", "strongswan_compose_valid", "unit_tests_pass",
            )
        ),
        "ready_for_libreswan_pilot": all(gates.values()),
        "empirical_results": "TBD — readiness checks are not benchmark results",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Check and record VPNGUARD-X lab readiness")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--require-docker", action="store_true")
    args = parser.parse_args()
    result = preflight()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output.resolve()), "gates": result["gates"]}, indent=2, sort_keys=True))
    if args.require_docker and not result["ready_for_strongswan_pilot"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
