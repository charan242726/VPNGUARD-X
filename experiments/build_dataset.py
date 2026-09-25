#!/usr/bin/env python3
"""Build a model-ready JSONL dataset from paired PCAP/ground-truth artifacts."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cgii import load_catalogue
from common.provenance import sha256_file, stable_hash
from features import FLOW_FEATURE_NAMES, extract_capture_features, extract_sequence_features
from parser import analyze_pcap
from common.evidence import EvidenceStatus


PROPERTY_TO_FIELD = {
    "ike.version": "ike_version",
    "outer.ip_version": "outer_ip_version",
    "encapsulation": "encapsulation",
    "ike.selected_encryption": "ike_encryption",
    "ike.selected_integrity": "ike_integrity",
    "ike.selected_prf": "ike_prf",
    "ike.initial_ke_group": "ike_ke_group",
    "child.mode": "child_mode",
    "child.encryption": "child_encryption",
    "child.integrity": "child_integrity",
    "child.pfs_group": "child_pfs_group",
    "child.esn": "esn",
    "child.anti_replay_enabled": "anti_replay",
    "sa.configured_lifetime": "child_lifetime_seconds",
    "ike.authentication_family": "authentication_family",
}

PROTOCOL_EVALUATION_PROPERTIES = (
    "ike.version",
    "outer.ip_version",
    "encapsulation",
    "ike.selected_encryption",
    "ike.selected_integrity",
    "ike.selected_prf",
    "ike.initial_ke_group",
)


def _match_candidates(configured: dict[str, Any], catalogue: Any) -> list[str]:
    matches = []
    for candidate in catalogue.candidates:
        valid = True
        for property_name, field_name in PROPERTY_TO_FIELD.items():
            expected = configured.get(property_name)
            if expected is None or expected == "UNKNOWN":
                continue
            if candidate.field_value(field_name) != expected:
                valid = False
                break
        if valid:
            matches.append(candidate.candidate_id)
    return sorted(matches)


def build_dataset(artifact_root: str | Path, output_path: str | Path, *, sequence_length: int = 128) -> dict[str, Any]:
    catalogue = load_catalogue(ROOT / "configs/candidate_catalogue.yaml")
    rows: list[dict[str, Any]] = []
    problems: list[str] = []
    excluded_failed_count = 0
    for ground_truth_path in sorted(Path(artifact_root).resolve().rglob("ground_truth.json")):
        ground_truth = json.loads(ground_truth_path.read_text(encoding="utf-8"))
        if ground_truth.get("outcome") != "COMPLETED":
            excluded_failed_count += 1
            continue
        pcap = ground_truth_path.parent / ground_truth["capture"]["pcap_file"]
        if not pcap.exists() or sha256_file(pcap) != ground_truth["capture"]["sha256"]:
            problems.append(f"{ground_truth_path}: PCAP missing or hash mismatch")
            continue
        analysis = analyze_pcap(pcap)
        sequence = extract_sequence_features(analysis.packets, sequence_length=sequence_length)
        matches = _match_candidates(ground_truth.get("configured_properties", {}), catalogue)
        if len(matches) != 1:
            problems.append(f"{ground_truth_path}: expected one catalogue candidate, found {matches}")
        scenario_id = str(ground_truth["scenario_id"])
        seed = int(ground_truth["seed"])
        hard_evidence = [
            record.to_dict()
            for record in analysis.evidence.records
            if record.status in {EvidenceStatus.OBSERVED, EvidenceStatus.DETERMINISTICALLY_DERIVED}
        ]
        protocol_predicted = {
            property_name: record.value
            for property_name in PROTOCOL_EVALUATION_PROPERTIES
            if (record := analysis.evidence.best(property_name)) is not None
            and record.status in {EvidenceStatus.OBSERVED, EvidenceStatus.DETERMINISTICALLY_DERIVED}
            and record.value is not None
        }
        capture_variant = str(ground_truth["capture"]["capture_variant"])
        deliberately_hidden = capture_variant in {"REMOVE_IKE_SA_INIT", "MIDSTREAM_ESP_ONLY"}
        # Packet-loss variants retain full laboratory truth, allowing missing
        # extractions to be measured.  Deliberate midstream/no-handshake cases
        # instead test correct abstention and do not claim transform visibility.
        visible_truth = (
            {}
            if deliberately_hidden
            else {
                property_name: ground_truth.get("configured_properties", {}).get(property_name)
                for property_name in PROTOCOL_EVALUATION_PROPERTIES
            }
        )
        lineage = ground_truth.get("lineage", {})
        root_artifact_id = str(
            lineage.get(
                "root_artifact_id",
                stable_hash(
                    {
                        "pcap": ground_truth["capture"]["sha256"],
                        "scenario": scenario_id,
                        "seed": seed,
                        "capture_variant": "FULL",
                    }
                )[:24],
            )
        )
        loss_manifest = ground_truth["capture"].get("loss_manifest") or {}
        artifact_id = stable_hash(
            {
                "pcap": ground_truth["capture"]["sha256"],
                "scenario": scenario_id,
                "seed": seed,
                "capture_variant": capture_variant,
                "transformation_seed": loss_manifest.get("seed"),
            }
        )[:24]
        row = {
            "artifact_id": artifact_id,
            "pcap_sha256": ground_truth["capture"]["sha256"],
            "scenario_id": scenario_id,
            "seed": seed,
            "configuration_id": matches[0] if len(matches) == 1 else None,
            "configuration_candidates": matches,
            "application_class": ground_truth["application"]["label"],
            "application_profile": ground_truth["application"].get("profile"),
            "capture_variant": capture_variant,
            "packet_loss_fraction": loss_manifest.get("requested_loss_fraction", 0.0),
            "source_artifact_id": lineage.get("source_artifact_id"),
            "replicate_group": root_artifact_id,
            "stack": ground_truth.get("stack", ground_truth.get("scenario", {}).get("stack", "UNKNOWN")),
            "flow_feature_names": list(FLOW_FEATURE_NAMES),
            "flow_features": extract_capture_features(analysis.packets),
            "sequence_values": [list(values) for values in sequence.values],
            "sequence_mask": list(sequence.mask),
            "packet_count": analysis.packet_count,
            "hard_evidence": hard_evidence,
            "protocol_truth": visible_truth,
            "protocol_predicted": protocol_predicted,
            "ground_truth_path": str(ground_truth_path),
            "pcap_path": str(pcap),
        }
        rows.append(row)
    if not rows:
        raise ValueError("no valid paired ground-truth artifacts found")
    selected = Path(output_path).resolve()
    selected.parent.mkdir(parents=True, exist_ok=True)
    selected.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")
    manifest = {
        "schema_version": "0.2.0",
        "dataset_file": str(selected),
        "dataset_sha256": sha256_file(selected),
        "row_count": len(rows),
        "sequence_length": sequence_length,
        "catalogue_id": catalogue.catalogue_id,
        "catalogue_hash": catalogue.catalogue_hash,
        "problems": problems,
        "excluded_failed_run_count": excluded_failed_count,
        "capture_variant_counts": {
            variant: sum(row["capture_variant"] == variant for row in rows)
            for variant in sorted({row["capture_variant"] for row in rows})
        },
        "stack_counts": {
            stack: sum(row["stack"] == stack for row in rows)
            for stack in sorted({row["stack"] for row in rows})
        },
        "publishable_secret_material": False,
    }
    selected.with_suffix(selected.suffix + ".manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifact_root", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--sequence-length", type=int, default=128)
    args = parser.parse_args()
    result = build_dataset(args.artifact_root, args.output, sequence_length=args.sequence_length)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if result["problems"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
