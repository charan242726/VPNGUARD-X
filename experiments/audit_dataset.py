#!/usr/bin/env python3
"""Audit benchmark completeness, lineage, class balance, and split leakage."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from common.provenance import sha256_file


def audit_dataset(dataset_path: str | Path, split_root: str | Path | None = None) -> dict:
    selected = Path(dataset_path).resolve()
    rows = [json.loads(line) for line in selected.read_text(encoding="utf-8").splitlines() if line.strip()]
    problems: list[str] = []
    warnings: list[str] = []
    artifact_ids = [row.get("artifact_id") for row in rows]
    if None in artifact_ids or len(set(artifact_ids)) != len(artifact_ids):
        problems.append("artifact IDs are missing or duplicated")
    source_hashes = [row.get("pcap_sha256") for row in rows]
    if None in source_hashes:
        problems.append("one or more PCAP hashes are missing")
    hash_groups: dict[str, set[str]] = defaultdict(set)
    for row in rows:
        hash_groups[str(row.get("pcap_sha256"))].add(str(row.get("replicate_group")))
    cross_group_duplicates = sorted(digest for digest, groups in hash_groups.items() if len(groups) > 1)
    if cross_group_duplicates:
        problems.append(f"byte-identical PCAPs cross replicate groups: {len(cross_group_duplicates)}")
    elif len(set(source_hashes)) != len(source_hashes):
        warnings.append("some packet-loss variants are byte-identical within the same replicate group")
    for row in rows:
        if row.get("capture_variant") != "FULL" and not row.get("source_artifact_id"):
            problems.append(f"derived artifact lacks source_artifact_id: {row.get('artifact_id')}")
        if row.get("application_class") == "UNKNOWN" and not str(row.get("application_profile", "")).endswith("_seeded"):
            problems.append(f"UNKNOWN artifact lacks a registered OOD profile: {row.get('artifact_id')}")
        if row.get("stack") in {None, "UNKNOWN"}:
            problems.append(f"artifact lacks stack ground truth: {row.get('artifact_id')}")
    full_rows = [row for row in rows if row.get("capture_variant") == "FULL"]
    balance: dict[str, Counter] = defaultdict(Counter)
    for row in full_rows:
        cell = f"{row.get('stack')}::{row.get('configuration_id')}"
        balance[cell][str(row.get("application_profile"))] += 1
    if balance:
        vectors = {tuple(sorted(counter.items())) for counter in balance.values()}
        if len(vectors) != 1:
            warnings.append("FULL dataset is not balanced across configuration-by-traffic cells")
    else:
        problems.append("dataset has no FULL captures")

    split_count = 0
    if split_root is not None:
        ids = set(artifact_ids)
        group_by_id = {row["artifact_id"]: row.get("replicate_group") for row in rows}
        for split_path in sorted(Path(split_root).resolve().rglob("*.json")):
            split = json.loads(split_path.read_text(encoding="utf-8"))
            if not {"train_ids", "calibration_ids", "test_ids"} <= set(split):
                continue
            split_count += 1
            partitions = [set(split[name]) for name in ("train_ids", "calibration_ids", "test_ids")]
            if any(not part <= ids for part in partitions):
                problems.append(f"split references unknown artifacts: {split_path}")
            if partitions[0] & partitions[1] or partitions[0] & partitions[2] or partitions[1] & partitions[2]:
                problems.append(f"artifact overlap in split: {split_path}")
            group_partitions = [{group_by_id.get(artifact_id) for artifact_id in part} for part in partitions]
            if group_partitions[0] & group_partitions[1] or group_partitions[0] & group_partitions[2] or group_partitions[1] & group_partitions[2]:
                problems.append(f"replicate-group leakage in split: {split_path}")
    return {
        "schema_version": "0.2.0",
        "dataset": str(selected),
        "dataset_sha256": sha256_file(selected),
        "row_count": len(rows),
        "full_capture_count": len(full_rows),
        "derived_capture_count": len(rows) - len(full_rows),
        "configuration_count": len({row.get("configuration_id") for row in full_rows}),
        "stack_configuration_cell_count": len(balance),
        "application_profile_count": len({row.get("application_profile") for row in full_rows}),
        "stack_counts": dict(sorted(Counter(str(row.get("stack")) for row in rows).items())),
        "split_manifest_count": split_count,
        "problems": problems,
        "warnings": warnings,
        "valid": not problems,
        "empirical_results": "TBD — this audit validates artifacts, not model performance",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit a VPNGUARD-X generated dataset")
    parser.add_argument("dataset", type=Path)
    parser.add_argument("--splits", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = audit_dataset(args.dataset, args.splits)
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
