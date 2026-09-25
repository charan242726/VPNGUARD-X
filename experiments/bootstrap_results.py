#!/usr/bin/env python3
"""Scenario-grouped bootstrap confidence intervals and paired CGII effects."""

from __future__ import annotations

import argparse
import json
import math
import random
from collections import defaultdict
from pathlib import Path
from statistics import mean
from typing import Any

from experiments.metrics import evaluate_prediction_records


def _flatten_numeric(value: Any, prefix: str = "") -> dict[str, float]:
    output: dict[str, float] = {}
    if isinstance(value, dict):
        for key, child in value.items():
            name = f"{prefix}.{key}" if prefix else str(key)
            output.update(_flatten_numeric(child, name))
    elif isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(float(value)):
        output[prefix] = float(value)
    return output


def _quantile(values: list[float], probability: float) -> float:
    ordered = sorted(values)
    position = probability * (len(ordered) - 1)
    lower = int(position)
    upper = min(len(ordered) - 1, lower + 1)
    fraction = position - lower
    return ordered[lower] * (1 - fraction) + ordered[upper] * fraction


def _read_predictions(root: Path) -> list[dict[str, Any]]:
    rows = []
    for path in sorted(root.rglob("predictions.jsonl")):
        rows.extend(json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip())
    if not rows:
        raise ValueError("no prediction JSONL files found")
    return rows


def _resample(records: list[dict[str, Any]], rng: random.Random) -> list[dict[str, Any]]:
    by_group: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in records:
        group = str(row.get("replicate_group") or row["artifact_id"])
        by_group[group].append(row)
    groups = sorted(by_group)
    return [row for _ in groups for row in by_group[rng.choice(groups)]]


def _mean_seed_metrics(records: list[dict[str, Any]]) -> tuple[dict[str, float], list[int]]:
    """Return the equal-seed mean, avoiding cross-model pooling of scores."""
    by_seed: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for row in records:
        by_seed[int(row["seed"])].append(row)
    values: dict[str, list[float]] = defaultdict(list)
    for seed_records in by_seed.values():
        for name, value in _flatten_numeric(evaluate_prediction_records(seed_records)).items():
            if name != "sample_count":
                values[name].append(value)
    return {name: mean(metric_values) for name, metric_values in values.items()}, sorted(by_seed)


def _hierarchical_resample_metrics(
    records: list[dict[str, Any]], rng: random.Random
) -> dict[str, float]:
    """Resample evaluation seeds, then scenario groups within each seed."""
    by_seed: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for row in records:
        by_seed[int(row["seed"])].append(row)
    seeds = sorted(by_seed)
    sampled: dict[str, list[float]] = defaultdict(list)
    for seed in (rng.choice(seeds) for _ in seeds):
        metrics = _flatten_numeric(evaluate_prediction_records(_resample(by_seed[seed], rng)))
        for name, value in metrics.items():
            if name != "sample_count":
                sampled[name].append(value)
    return {name: mean(values) for name, values in sampled.items()}


def bootstrap(root: str | Path, *, iterations: int, seed: int) -> dict[str, Any]:
    if iterations < 200:
        raise ValueError("use at least 200 bootstrap iterations")
    rows = _read_predictions(Path(root).resolve())
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[(str(row["split_id"]), str(row["method"]))].append(row)
    rng = random.Random(seed)
    intervals = []
    for (split_id, method), records in sorted(grouped.items()):
        point, seeds = _mean_seed_metrics(records)
        samples: dict[str, list[float]] = defaultdict(list)
        for _ in range(iterations):
            metrics = _hierarchical_resample_metrics(records, rng)
            for name, value in metrics.items():
                if name != "sample_count":
                    samples[name].append(value)
        intervals.append(
            {
                "split_id": split_id,
                "method": method,
                "seed_count": len(seeds),
                "seeds": seeds,
                "replicate_group_count": len({row.get("replicate_group") for row in records}),
                "metrics": {
                    name: {
                        "estimate": point[name],
                        "bootstrap_mean": mean(values),
                        "ci95_percentile": [_quantile(values, 0.025), _quantile(values, 0.975)],
                    }
                    for name, values in sorted(samples.items())
                    if name in point
                },
            }
        )

    paired = []
    pairs = (
        ("XGB_UNCONSTRAINED+XGBOOST_APP", "CGII_XGB_CONFORMAL+XGBOOST_APP"),
        ("XGB_UNCONSTRAINED+TCN_APP", "CGII_XGB_CONFORMAL+TCN_APP"),
        ("PARSER_ONLY+XGBOOST_APP", "CGII_XGB_CONFORMAL+XGBOOST_APP"),
        ("PARSER_ONLY+TCN_APP", "CGII_XGB_CONFORMAL+TCN_APP"),
    )
    split_values = sorted({key[0] for key in grouped})
    for split_id in split_values:
        for baseline, cgii in pairs:
            if (split_id, baseline) not in grouped or (split_id, cgii) not in grouped:
                continue
            base_by_seed_group: dict[int, dict[str, list[dict[str, Any]]]] = defaultdict(lambda: defaultdict(list))
            cgii_by_seed_group: dict[int, dict[str, list[dict[str, Any]]]] = defaultdict(lambda: defaultdict(list))
            for row in grouped[(split_id, baseline)]:
                base_by_seed_group[int(row["seed"])][str(row.get("replicate_group") or row["artifact_id"])].append(row)
            for row in grouped[(split_id, cgii)]:
                cgii_by_seed_group[int(row["seed"])][str(row.get("replicate_group") or row["artifact_id"])].append(row)
            seeds = sorted(set(base_by_seed_group) & set(cgii_by_seed_group))
            groups_by_seed = {
                seed: sorted(set(base_by_seed_group[seed]) & set(cgii_by_seed_group[seed]))
                for seed in seeds
            }
            seeds = [seed for seed in seeds if groups_by_seed[seed]]
            if not seeds:
                continue
            point_differences: dict[str, list[float]] = defaultdict(list)
            for seed in seeds:
                base_rows = [row for group in groups_by_seed[seed] for row in base_by_seed_group[seed][group]]
                cgii_rows = [row for group in groups_by_seed[seed] for row in cgii_by_seed_group[seed][group]]
                base_metrics = _flatten_numeric(evaluate_prediction_records(base_rows))
                cgii_metrics = _flatten_numeric(evaluate_prediction_records(cgii_rows))
                for name in set(base_metrics) & set(cgii_metrics):
                    if name != "sample_count":
                        point_differences[name].append(cgii_metrics[name] - base_metrics[name])
            difference_samples: dict[str, list[float]] = defaultdict(list)
            for _ in range(iterations):
                iteration_differences: dict[str, list[float]] = defaultdict(list)
                for seed in (rng.choice(seeds) for _ in seeds):
                    groups = groups_by_seed[seed]
                    chosen = [rng.choice(groups) for _ in groups]
                    base_rows = [row for group in chosen for row in base_by_seed_group[seed][group]]
                    cgii_rows = [row for group in chosen for row in cgii_by_seed_group[seed][group]]
                    base_metrics = _flatten_numeric(evaluate_prediction_records(base_rows))
                    cgii_metrics = _flatten_numeric(evaluate_prediction_records(cgii_rows))
                    for name in set(base_metrics) & set(cgii_metrics):
                        if name != "sample_count":
                            iteration_differences[name].append(cgii_metrics[name] - base_metrics[name])
                for name, values in iteration_differences.items():
                    difference_samples[name].append(mean(values))
            paired.append(
                {
                    "split_id": split_id,
                    "baseline": baseline,
                    "comparison": cgii,
                    "seed_count": len(seeds),
                    "seeds": seeds,
                    "paired_replicate_group_count": len(set().union(*(set(groups_by_seed[seed]) for seed in seeds))),
                    "difference_is_comparison_minus_baseline": True,
                    "metrics": {
                        name: {
                            "estimate_mean_difference": mean(point_differences[name]),
                            "bootstrap_mean_difference": mean(values),
                            "ci95_percentile": [_quantile(values, 0.025), _quantile(values, 0.975)],
                        }
                        for name, values in sorted(difference_samples.items())
                    },
                }
            )
    return {
        "schema_version": "0.3.0",
        "bootstrap_unit": "evaluation_seed_then_replicate_group",
        "point_estimate": "equal-weight mean of per-seed metrics",
        "configuration_decision_rule": "singleton prediction set; otherwise abstain",
        "iterations": iterations,
        "seed": seed,
        "intervals": intervals,
        "paired_cgii_effects": paired,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Bootstrap VPNGUARD-X prediction records")
    parser.add_argument("results_root", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--iterations", type=int, default=2000)
    parser.add_argument("--seed", type=int, default=26160)
    args = parser.parse_args()
    result = bootstrap(args.results_root, iterations=args.iterations, seed=args.seed)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"interval_count": len(result["intervals"]), "paired_effect_count": len(result["paired_cgii_effects"])}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
