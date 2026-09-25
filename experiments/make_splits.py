#!/usr/bin/env python3
"""Create generalization split manifests from a built dataset."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cgii import load_catalogue
from experiments.splits import ExperimentRecord, build_generalization_splits


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("dataset", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seeds", type=int, nargs="+", default=[11, 22, 33, 44, 55])
    parser.add_argument("--include-derived", action="store_true", help="not recommended; base FULL captures are the default")
    args = parser.parse_args()
    catalogue = load_catalogue(ROOT / "configs/candidate_catalogue.yaml")
    records = []
    for line in args.dataset.read_text(encoding="utf-8").splitlines():
        row = json.loads(line)
        if not args.include_derived and row.get("capture_variant", "FULL") != "FULL":
            continue
        configuration_id = row.get("configuration_id")
        if not configuration_id:
            continue
        candidate = catalogue.by_id[configuration_id]
        records.append(
            ExperimentRecord(
                row["artifact_id"],
                configuration_id,
                candidate.child_encryption,
                candidate.child_mode,
                candidate.outer_ip_version,
                candidate.encapsulation,
                str(row.get("stack", "strongSwan-6.1.0")),
                row["application_class"],
                str(row.get("replicate_group", f"{row['scenario_id']}::{row.get('seed', '')}")),
            )
        )
    args.output.mkdir(parents=True, exist_ok=True)
    manifest_count = 0
    split_ids: set[str] = set()
    for seed in args.seeds:
        manifests = [manifest.to_dict() for manifest in build_generalization_splits(records, seed=seed)]
        seed_directory = args.output / f"seed-{seed}"
        seed_directory.mkdir(parents=True, exist_ok=True)
        for manifest in manifests:
            name = manifest["split_id"].replace("::", "__").replace("->", "_to_").replace("/", "_") + ".json"
            (seed_directory / name).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            manifest_count += 1
            split_ids.add(manifest["split_id"])
    print(
        json.dumps(
            {
                "split_manifest_count": manifest_count,
                "unique_split_count": len(split_ids),
                "seeds": args.seeds,
                "output": str(args.output.resolve()),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
