#!/usr/bin/env python3
"""Create a balanced, deterministic cyber-range run plan.

The source scenario matrix supplies VPN configuration templates.  This planner
crosses each selected configuration with every application profile so traffic
labels cannot be predicted from a configuration-only shortcut.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from common.provenance import sha256_file, stable_hash
from cyber_range.range import DEFAULT_MATRIX, _canonical_properties, load_scenarios
from experiments.build_dataset import _match_candidates
from cgii import load_catalogue


STACK_STRONGSWAN = "strongSwan-6.1.0"
STACK_INTEROP = "strongSwan-6.1.0-to-Libreswan-5.4"
PLAN_FIELDS = (
    "run_id",
    "base_scenario_id",
    "seed",
    "session_index",
    "application_class",
    "application_profile",
    "capture_variant",
    "stack",
    "configuration_id",
    "configuration_fingerprint",
    "plan_version",
)


def _short_profile(profile: str) -> str:
    tokens = {
        "https_seeded": "WEB",
        "udp_video_seeded": "VID",
        "udp_voip_seeded": "VOIP",
        "tcp_bulk_seeded": "BULK",
        "interactive_seeded": "MSG",
        "icmp_seeded": "CTRL",
        "dns_burst_seeded": "ODNS",
        "iot_telemetry_seeded": "OIOT",
        "mixed_unknown_seeded": "OMIX",
    }
    if profile not in tokens:
        raise ValueError(f"unregistered application profile: {profile}")
    return tokens[profile]


def load_design(path: str | Path) -> dict[str, Any]:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("benchmark design must be a mapping")
    return data


def generate_plan(
    design_path: str | Path,
    *,
    profile: str,
    stack: str,
    matrix_path: str | Path = DEFAULT_MATRIX,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if profile not in {"pilot", "full"}:
        raise ValueError("profile must be pilot or full")
    if stack not in {STACK_STRONGSWAN, STACK_INTEROP}:
        raise ValueError(f"unsupported stack: {stack}")
    design = load_design(design_path)
    scenarios = load_scenarios(matrix_path)
    catalogue = load_catalogue(ROOT / "configs/candidate_catalogue.yaml")
    template_key = "libreswan_interop_templates" if stack == STACK_INTEROP else "strongswan_configuration_templates"
    templates = [str(value) for value in design[template_key]]
    seeds = [int(value) for value in design["seeds"]]
    traffic = list(design["in_domain_traffic"]) + list(design.get("ood_traffic", []))
    if profile == "pilot":
        pilot = design["pilot"]
        templates = templates[: int(pilot["templates_per_stack"])]
        seeds = [int(value) for value in pilot["seeds"]]
        if not bool(pilot.get("include_ood", True)):
            traffic = list(design["in_domain_traffic"])
    sessions = int(design.get("sessions_per_seed", 1))
    stack_code = "SL" if stack == STACK_INTEROP else "SS"
    if sessions < 1:
        raise ValueError("sessions_per_seed must be positive")

    rows: list[dict[str, Any]] = []
    configuration_ids: set[str] = set()
    for template_index, scenario_id in enumerate(templates, start=1):
        if scenario_id not in scenarios:
            raise KeyError(f"benchmark template is absent from scenario matrix: {scenario_id}")
        scenario = scenarios[scenario_id]
        if scenario["enabled"].lower() != "true" or scenario["capture_variant"] != "FULL":
            raise ValueError(f"benchmark template must be enabled and FULL: {scenario_id}")
        matches = _match_candidates(_canonical_properties(scenario), catalogue)
        if len(matches) != 1:
            raise ValueError(f"benchmark template must map to one candidate: {scenario_id}: {matches}")
        configuration_id = matches[0]
        if configuration_id in configuration_ids:
            raise ValueError(f"duplicate catalogue configuration in benchmark templates: {configuration_id}")
        configuration_ids.add(configuration_id)
        fingerprint = stable_hash(_canonical_properties(scenario))[:16]
        for traffic_spec in traffic:
            application_class = str(traffic_spec["application_class"])
            application_profile = str(traffic_spec["application_profile"])
            for seed in seeds:
                if seed not in {int(value) for value in scenario["replicate_seeds"].split("|")}:
                    raise ValueError(f"seed {seed} is not declared by template {scenario_id}")
                for session_index in range(1, sessions + 1):
                    run_id = (
                        f"BENCH-{stack_code}-{template_index:02d}-{_short_profile(application_profile)}"
                        f"-S{seed:02d}-R{session_index:02d}"
                    )
                    rows.append(
                        {
                            "run_id": run_id,
                            "base_scenario_id": scenario_id,
                            "seed": seed,
                            "session_index": session_index,
                            "application_class": application_class,
                            "application_profile": application_profile,
                            "capture_variant": "FULL",
                            "stack": stack,
                            "configuration_id": configuration_id,
                            "configuration_fingerprint": fingerprint,
                            "plan_version": str(design["benchmark_version"]),
                        }
                    )
    if len({row["run_id"] for row in rows}) != len(rows):
        raise AssertionError("generated run IDs are not unique")
    counts: dict[str, dict[str, int]] = {}
    for row in rows:
        counts.setdefault(row["configuration_id"], {})
        label = row["application_profile"]
        counts[row["configuration_id"]][label] = counts[row["configuration_id"]].get(label, 0) + 1
    count_vectors = {tuple(sorted(value.items())) for value in counts.values()}
    if len(count_vectors) != 1:
        raise AssertionError("configuration-by-traffic plan is unbalanced")
    manifest = {
        "schema_version": "0.2.0",
        "profile": profile,
        "stack": stack,
        "row_count": len(rows),
        "configuration_count": len(configuration_ids),
        "traffic_profile_count": len(traffic),
        "seeds": seeds,
        "sessions_per_seed": sessions,
        "design_sha256": sha256_file(design_path),
        "scenario_matrix_sha256": sha256_file(matrix_path),
        "catalogue_hash": catalogue.catalogue_hash,
        "balanced_configuration_by_traffic": True,
        "results": "TBD — requires experiment",
    }
    return rows, manifest


def write_plan(rows: list[dict[str, Any]], manifest: dict[str, Any], output: str | Path) -> dict[str, Any]:
    selected = Path(output).resolve()
    selected.parent.mkdir(parents=True, exist_ok=True)
    with selected.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=PLAN_FIELDS, quoting=csv.QUOTE_ALL)
        writer.writeheader()
        writer.writerows(rows)
    finalized = dict(manifest)
    finalized["plan_file"] = str(selected)
    finalized["plan_sha256"] = sha256_file(selected)
    selected.with_suffix(selected.suffix + ".manifest.json").write_text(
        json.dumps(finalized, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return finalized


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a balanced VPNGUARD-X benchmark plan")
    parser.add_argument("--design", type=Path, default=ROOT / "configs/benchmark_design.yaml")
    parser.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
    parser.add_argument("--profile", choices=["pilot", "full"], default="pilot")
    parser.add_argument("--stack", choices=[STACK_STRONGSWAN, STACK_INTEROP], default=STACK_STRONGSWAN)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    rows, manifest = generate_plan(args.design, profile=args.profile, stack=args.stack, matrix_path=args.matrix)
    print(json.dumps(write_plan(rows, manifest, args.output), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
