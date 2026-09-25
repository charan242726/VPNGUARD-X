#!/usr/bin/env python3
"""Recompute publication metrics without retraining any model.

This post-processing command reads the immutable prediction JSONL files from a
completed evaluation, applies the current metric semantics, and writes a new
results tree containing corrected per-run metrics, aggregate summaries, a
hierarchical bootstrap, and a provenance audit.  It deliberately does not
modify the original result directory.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from common.provenance import sha256_file, stable_hash
from experiments.bootstrap_results import bootstrap
from experiments.metrics import evaluate_prediction_records
from experiments.run_evaluation import _aggregate


METRIC_SEMANTICS = {
    "version": "0.3.0",
    "configuration_point_decision": "singleton prediction set; otherwise abstain",
    "configuration_exact_match": "unconditional; abstentions count as incorrect",
    "configuration_conditional_exact_match": "correct among emitted singleton decisions only",
    "configuration_prediction_set": "retained independently of point-decision abstention",
}


def _load_records(path: Path) -> list[dict]:
    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not records:
        raise ValueError(f"empty prediction file: {path}")
    return records


def recompute(
    results_root: str | Path,
    output_root: str | Path,
    *,
    iterations: int = 2000,
    bootstrap_seed: int = 26160,
    dataset_file: str = "data/generated/vpnguard_x_combined.jsonl",
    dataset_sha256: str | None = None,
) -> dict:
    source = Path(results_root).resolve()
    destination = Path(output_root).resolve()
    if source == destination or source in destination.parents:
        raise ValueError("output_root must be outside results_root")
    prediction_paths = sorted(source.rglob("predictions.jsonl"))
    if not prediction_paths:
        raise ValueError("no prediction JSONL files found")

    completed: list[dict] = []
    prediction_index: list[dict[str, str]] = []
    for prediction_path in prediction_paths:
        relative = prediction_path.relative_to(source)
        source_metrics_path = prediction_path.with_name("metrics.json")
        if not source_metrics_path.is_file():
            raise ValueError(f"missing source metrics beside {relative}")
        metadata = json.loads(source_metrics_path.read_text(encoding="utf-8"))
        prediction_hash = sha256_file(prediction_path)
        if metadata.get("prediction_sha256") != prediction_hash:
            raise ValueError(f"prediction hash mismatch: {relative}")
        records = _load_records(prediction_path)
        identity = {(row.get("split_id"), row.get("seed"), row.get("method")) for row in records}
        expected = {(metadata.get("split_id"), metadata.get("seed"), metadata.get("method"))}
        if identity != expected:
            raise ValueError(f"prediction identity mismatch: {relative}")

        corrected = dict(metadata)
        corrected["schema_version"] = "0.3.0"
        if dataset_sha256 is not None:
            corrected["source_dataset_sha256"] = metadata.get("dataset_sha256")
            corrected["dataset_sha256"] = dataset_sha256
        corrected["source_metrics_sha256"] = sha256_file(source_metrics_path)
        corrected["metric_semantics"] = METRIC_SEMANTICS
        corrected["metrics"] = evaluate_prediction_records(records)
        target = destination / relative.parent / "metrics.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(corrected, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        completed.append(corrected)
        prediction_index.append({"path": relative.as_posix(), "sha256": prediction_hash})

    source_aggregate_path = source / "aggregate-results.json"
    aggregate = {}
    if source_aggregate_path.is_file():
        aggregate = {
            key: value
            for key, value in json.loads(source_aggregate_path.read_text(encoding="utf-8")).items()
            if key != "aggregate"
        }
    aggregate.update(
        {
            "schema_version": "0.3.0",
            "dataset_file": dataset_file,
            "split_root": "artifacts/splits",
            "completed_method_runs": len(completed),
            "metric_semantics": METRIC_SEMANTICS,
            "aggregate": _aggregate(completed),
        }
    )
    if dataset_sha256 is not None:
        aggregate["source_dataset_sha256"] = aggregate.get("dataset_sha256")
        aggregate["dataset_sha256"] = dataset_sha256
    destination.mkdir(parents=True, exist_ok=True)
    aggregate_path = destination / "aggregate-results.json"
    aggregate_path.write_text(json.dumps(aggregate, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    # Bootstrap the immutable prediction records.  They deliberately remain in
    # the source tree; no model is retrained and no prediction is rewritten.
    hierarchical = bootstrap(source, iterations=iterations, seed=bootstrap_seed)
    hierarchical["schema_version"] = "0.3.0"
    hierarchical["metric_semantics"] = METRIC_SEMANTICS
    bootstrap_path = destination / "bootstrap-hierarchical.json"
    bootstrap_path.write_text(json.dumps(hierarchical, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    audit = {
        "schema_version": "0.3.0",
        "created_at_utc": datetime.now(UTC).isoformat(),
        "model_retraining_performed": False,
        "prediction_file_count": len(prediction_paths),
        "prediction_index_hash": stable_hash(prediction_index),
        "dataset_file": dataset_file,
        "dataset_sha256": dataset_sha256 or aggregate.get("dataset_sha256"),
        "metric_file_count": len(completed),
        "hierarchical_interval_count": len(hierarchical["intervals"]),
        "paired_effect_count": len(hierarchical["paired_cgii_effects"]),
        "bootstrap_iterations": iterations,
        "bootstrap_seed": bootstrap_seed,
        "metric_semantics": METRIC_SEMANTICS,
        "outputs": {
            "aggregate_results_sha256": sha256_file(aggregate_path),
            "bootstrap_hierarchical_sha256": sha256_file(bootstrap_path),
        },
    }
    audit_path = destination / "metric-recomputation-audit.json"
    audit_path.write_text(json.dumps(audit, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return audit


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results_root", type=Path)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--iterations", type=int, default=2000)
    parser.add_argument("--bootstrap-seed", type=int, default=26160)
    parser.add_argument("--dataset-file", default="data/generated/vpnguard_x_combined.jsonl")
    parser.add_argument("--dataset-sha256")
    args = parser.parse_args()
    result = recompute(
        args.results_root,
        args.output_root,
        iterations=args.iterations,
        bootstrap_seed=args.bootstrap_seed,
        dataset_file=args.dataset_file,
        dataset_sha256=args.dataset_sha256,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
