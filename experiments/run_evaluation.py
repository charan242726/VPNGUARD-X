#!/usr/bin/env python3
"""Execute reproducible baselines, CGII ablations, calibration, and evaluation.

This script is intentionally manifest driven.  It never fills placeholder
results: metrics are written only after fitted models produce prediction rows.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import math
import sys
from collections import defaultdict
from pathlib import Path
from statistics import mean, stdev
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from calibration import SplitConformalCalibrator, TemperatureScaler
from cgii import CGIIEngine, PriorDistribution, load_catalogue
from common.evidence import EvidenceLedger, EvidenceRecord, EvidenceStatus
from common.provenance import sha256_file, stable_hash
from common.reproducibility import seed_everything
from experiments.metrics import evaluate_prediction_records
from models.open_world import OpenWorldGate
from models.tcn_baseline import TCNConfig
from models.tcn_classifier import TCNClassifier
from models.xgboost_baseline import XGBoostBaseline


CONFIG_METHODS = ("PARSER_ONLY", "XGB_UNCONSTRAINED", "CGII_XGB_CONFORMAL")


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _ledger(row: dict[str, Any]) -> EvidenceLedger:
    records: list[EvidenceRecord] = []
    for value in row.get("hard_evidence", []):
        records.append(
            EvidenceRecord(
                property_name=str(value["property_name"]),
                value=value.get("value"),
                status=EvidenceStatus(value["status"]),
                source=str(value["source"]),
                rationale=str(value["rationale"]),
                source_locator=value.get("source_locator"),
                reason_code=value.get("reason_code"),
                packet_indices=tuple(int(index) for index in value.get("packet_indices", [])),
            )
        )
    return EvidenceLedger(records)


def _logits(probabilities: list[dict[str, float]], classes: tuple[str, ...]) -> list[list[float]]:
    return [[math.log(max(1e-15, float(row[label]))) for label in classes] for row in probabilities]


def _temperature_calibrate(
    calibration_probabilities: list[dict[str, float]],
    calibration_labels: list[str],
    classes: tuple[str, ...],
) -> TemperatureScaler:
    index = {label: position for position, label in enumerate(classes)}
    if any(label not in index for label in calibration_labels):
        raise ValueError("calibration label is absent from model classes")
    return TemperatureScaler.fit(
        _logits(calibration_probabilities, classes),
        [index[label] for label in calibration_labels],
    )


def _apply_temperature(
    probabilities: list[dict[str, float]],
    classes: tuple[str, ...],
    scaler: TemperatureScaler,
) -> list[dict[str, float]]:
    values = scaler.transform(_logits(probabilities, classes))
    return [
        {label: float(row[index]) for index, label in enumerate(classes)}
        for row in values
    ]


def _expand_candidate_distribution(distribution: dict[str, float], candidate_ids: tuple[str, ...]) -> dict[str, float]:
    expanded = {candidate_id: float(distribution.get(candidate_id, 0.0)) for candidate_id in candidate_ids}
    total = sum(expanded.values())
    if total <= 0:
        raise ValueError("candidate distribution has zero total mass")
    return {candidate_id: value / total for candidate_id, value in expanded.items()}


def _fit_xgboost(
    rows: list[dict[str, Any]],
    *,
    label_key: str,
    seed: int,
    output: Path,
) -> XGBoostBaseline:
    selected = [row for row in rows if row.get(label_key) and (label_key != "application_class" or row[label_key] != "UNKNOWN")]
    classes = tuple(sorted({str(row[label_key]) for row in selected}))
    if len(classes) < 2:
        raise ValueError(f"XGBoost {label_key} training requires at least two classes")
    model = XGBoostBaseline(classes, seed=seed).fit(
        [row["flow_features"] for row in selected],
        [str(row[label_key]) for row in selected],
    )
    model.save(
        output,
        feature_names=selected[0]["flow_feature_names"],
        training_manifest_hash=stable_hash(
            {"artifact_ids": sorted(row["artifact_id"] for row in selected), "label_key": label_key, "seed": seed}
        ),
    )
    return model


def _fit_tcn(rows: list[dict[str, Any]], *, seed: int, epochs: int, output: Path) -> TCNClassifier:
    selected = [row for row in rows if row.get("application_class") not in {None, "UNKNOWN"}]
    classes = tuple(sorted({str(row["application_class"]) for row in selected}))
    if len(classes) < 2:
        raise ValueError("TCN application training requires at least two classes")
    model = TCNClassifier(classes, TCNConfig(class_count=len(classes), seed=seed), epochs=epochs).fit(
        [row["sequence_values"] for row in selected],
        [row["sequence_mask"] for row in selected],
        [str(row["application_class"]) for row in selected],
    )
    model.save(
        output,
        training_manifest_hash=stable_hash(
            {"artifact_ids": sorted(row["artifact_id"] for row in selected), "label_key": "application_class", "seed": seed}
        ),
    )
    return model


def _prediction_function(model: Any, model_name: str) -> Callable[[list[dict[str, Any]]], list[dict[str, float]]]:
    if model_name == "xgboost":
        return lambda rows: model.predict_proba([row["flow_features"] for row in rows])
    if model_name == "tcn":
        return lambda rows: model.predict_proba(
            [row["sequence_values"] for row in rows],
            [row["sequence_mask"] for row in rows],
        )
    raise ValueError(model_name)


def _linked_test_rows(rows: list[dict[str, Any]], test_ids: set[str], include_linked_variants: bool) -> list[dict[str, Any]]:
    base = [row for row in rows if row["artifact_id"] in test_ids]
    if not include_linked_variants:
        return base
    # The lineage source ID is the FULL capture's replicate_group.  The FULL
    # dataset artifact_id also hashes the transformation_seed=None field and
    # therefore does not equal that lineage ID.
    full_groups = {row["replicate_group"] for row in base if row.get("capture_variant") == "FULL"}
    linked = [
        row
        for row in rows
        if row.get("capture_variant") != "FULL"
        and row.get("source_artifact_id") in full_groups
        and row.get("replicate_group") == row.get("source_artifact_id")
    ]
    return base + linked


def _raw_config_prediction_set(calibrator: SplitConformalCalibrator, posterior: dict[str, float]) -> list[str]:
    return calibrator.prediction_set(posterior, calibrator.alpha)


def _run_one_split(
    dataset_rows: list[dict[str, Any]],
    dataset_sha256: str,
    split_path: Path,
    output_root: Path,
    *,
    app_models: tuple[str, ...],
    epochs: int,
    alpha: float,
    include_linked_variants: bool,
) -> list[dict[str, Any]]:
    split = json.loads(split_path.read_text(encoding="utf-8"))
    seed = int(split["seed"])
    runtime = seed_everything(seed)
    rows_by_id = {row["artifact_id"]: row for row in dataset_rows}
    train = [rows_by_id[artifact_id] for artifact_id in split["train_ids"]]
    calibration = [rows_by_id[artifact_id] for artifact_id in split["calibration_ids"]]
    test = _linked_test_rows(dataset_rows, set(split["test_ids"]), include_linked_variants)
    if not train or not calibration or not test:
        raise ValueError(f"split has an empty train/calibration/test partition: {split_path}")
    split_name = split["split_id"].replace("::", "__").replace("->", "_to_").replace("/", "_")
    run_dir = output_root / f"seed-{seed}" / split_name
    run_dir.mkdir(parents=True, exist_ok=True)

    catalogue = load_catalogue(ROOT / "configs/candidate_catalogue.yaml")
    candidate_ids = tuple(candidate.candidate_id for candidate in catalogue.candidates)
    engine = CGIIEngine(catalogue)
    config_model = _fit_xgboost(train, label_key="configuration_id", seed=seed, output=run_dir / "models/xgb-configuration")
    calibration_config_raw = [
        _expand_candidate_distribution(distribution, candidate_ids)
        for distribution in config_model.predict_proba([row["flow_features"] for row in calibration])
    ]
    calibration_truth = [str(row["configuration_id"]) for row in calibration]
    raw_config_calibrator = SplitConformalCalibrator.fit(calibration_config_raw, calibration_truth, alpha=alpha)
    constrained_calibration: list[dict[str, float]] = []
    for row, distribution in zip(calibration, calibration_config_raw, strict=True):
        result = engine.infer(
            _ledger(row),
            PriorDistribution(distribution, config_model.model_id, config_model.model_hash, split["split_id"], True),
            alpha=alpha,
        )
        if result.status != "OK" or row["configuration_id"] not in result.posterior:
            raise ValueError(f"calibration evidence excludes its ground truth: {row['artifact_id']}")
        constrained_calibration.append(result.posterior)
    cgii_calibrator = SplitConformalCalibrator.fit(constrained_calibration, calibration_truth, alpha=alpha)
    test_config_raw = [
        _expand_candidate_distribution(distribution, candidate_ids)
        for distribution in config_model.predict_proba([row["flow_features"] for row in test])
    ]
    config_outputs: dict[str, list[dict[str, Any]]] = {method: [] for method in CONFIG_METHODS}
    for row, raw_distribution in zip(test, test_config_raw, strict=True):
        ledger = _ledger(row)
        parser_result = engine.infer(ledger, alpha=alpha)
        full_result = engine.infer(
            ledger,
            PriorDistribution(raw_distribution, config_model.model_id, config_model.model_hash, split["split_id"], True),
            alpha=alpha,
            calibrator=cgii_calibrator,
        )
        raw_argmax = max(sorted(raw_distribution), key=raw_distribution.get)
        config_outputs["PARSER_ONLY"].append(
            {
                "candidate_posterior": parser_result.posterior,
                "prediction_set": parser_result.prediction_set,
                "predicted_candidate_id": (
                    parser_result.prediction_set[0] if len(parser_result.prediction_set) == 1 else None
                ),
                "configuration_decision_reason": (
                    "SINGLETON_PREDICTION_SET" if len(parser_result.prediction_set) == 1
                    else "ABSTAIN_NON_SINGLETON_PREDICTION_SET"
                ),
                "predicted_constraint_violations": [],
                "evidence_completeness": parser_result.evidence_completeness,
            }
        )
        raw_prediction_set = _raw_config_prediction_set(raw_config_calibrator, raw_distribution)
        config_outputs["XGB_UNCONSTRAINED"].append(
            {
                "candidate_posterior": raw_distribution,
                "prediction_set": raw_prediction_set,
                "predicted_candidate_id": raw_prediction_set[0] if len(raw_prediction_set) == 1 else None,
                "configuration_decision_reason": (
                    "SINGLETON_PREDICTION_SET" if len(raw_prediction_set) == 1
                    else "ABSTAIN_NON_SINGLETON_PREDICTION_SET"
                ),
                "predicted_constraint_violations": [] if raw_argmax in parser_result.feasible_candidate_ids else ["HARD_EVIDENCE"],
                "evidence_completeness": parser_result.evidence_completeness,
            }
        )
        config_outputs["CGII_XGB_CONFORMAL"].append(
            {
                "candidate_posterior": full_result.posterior,
                "prediction_set": full_result.prediction_set,
                "predicted_candidate_id": (
                    full_result.prediction_set[0] if len(full_result.prediction_set) == 1 else None
                ),
                "configuration_decision_reason": (
                    "SINGLETON_PREDICTION_SET" if len(full_result.prediction_set) == 1
                    else "ABSTAIN_NON_SINGLETON_PREDICTION_SET"
                ),
                "predicted_constraint_violations": [] if full_result.status == "OK" else [full_result.status],
                "evidence_completeness": full_result.evidence_completeness,
            }
        )

    completed: list[dict[str, Any]] = []
    for app_model_name in app_models:
        if app_model_name == "xgboost":
            app_model = _fit_xgboost(train, label_key="application_class", seed=seed, output=run_dir / "models/xgb-application")
        elif app_model_name == "tcn":
            app_model = _fit_tcn(train, seed=seed, epochs=epochs, output=run_dir / "models/tcn-application")
        else:
            raise ValueError(app_model_name)
        predict = _prediction_function(app_model, app_model_name)
        calibration_known = [row for row in calibration if row["application_class"] != "UNKNOWN"]
        if not calibration_known:
            raise ValueError("application calibration partition has no in-domain rows")
        calibration_raw = predict(calibration_known)
        app_scaler = _temperature_calibrate(
            calibration_raw,
            [str(row["application_class"]) for row in calibration_known],
            app_model.classes,
        )
        calibration_probabilities = _apply_temperature(calibration_raw, app_model.classes, app_scaler)
        gate = OpenWorldGate.fit([max(values.values()) for values in calibration_probabilities], target_id_rejection_rate=0.05)
        app_probabilities = _apply_temperature(predict(test), app_model.classes, app_scaler)

        for config_method in CONFIG_METHODS:
            method = f"{config_method}+{app_model_name.upper()}_APP"
            prediction_path = run_dir / method / "predictions.jsonl"
            prediction_path.parent.mkdir(parents=True, exist_ok=True)
            records: list[dict[str, Any]] = []
            for row, application_probability, config_output in zip(test, app_probabilities, config_outputs[config_method], strict=True):
                decision = gate.decide(application_probability)
                record = {
                    "artifact_id": row["artifact_id"],
                    "replicate_group": row.get("replicate_group"),
                    "split_id": split["split_id"],
                    "seed": seed,
                    "method": method,
                    "true_candidate_id": row.get("configuration_id"),
                    "true_application": row.get("application_class"),
                    "application_profile": row.get("application_profile"),
                    "application_probabilities": application_probability,
                    "reported_application": decision.label,
                    "is_ood": row.get("application_class") == "UNKNOWN",
                    "ood_score": 1.0 - max(application_probability.values()),
                    "packet_loss_fraction": float(row.get("packet_loss_fraction", 0.0)),
                    "capture_variant": row.get("capture_variant"),
                    "protocol_truth": row.get("protocol_truth"),
                    "protocol_predicted": row.get("protocol_predicted"),
                    "latency_ms": None,
                    "latency_reason": "MEASURE_SEPARATELY_WITH_BENCHMARK_SYSTEM_LATENCY_TO_INCLUDE_PARSING_AND_FEATURES",
                    **config_output,
                }
                records.append(record)
            prediction_path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in records), encoding="utf-8")
            metrics = evaluate_prediction_records(records)
            metadata = {
                "schema_version": "0.2.0",
                "dataset_sha256": dataset_sha256,
                "split_file": str(split_path),
                "split_sha256": sha256_file(split_path),
                "split_id": split["split_id"],
                "seed": seed,
                "method": method,
                "runtime": runtime,
                "configuration_model_hash": config_model.model_hash,
                "application_model_hash": app_model.model_hash,
                "application_temperature": app_scaler.temperature,
                "application_temperature_hash": app_scaler.calibrator_hash,
                "open_world_gate_hash": gate.gate_hash,
                "raw_configuration_calibrator_hash": raw_config_calibrator.calibrator_hash,
                "cgii_calibrator_hash": cgii_calibrator.calibrator_hash,
                "prediction_file": str(prediction_path),
                "prediction_sha256": sha256_file(prediction_path),
                "metrics": metrics,
            }
            metrics_path = prediction_path.parent / "metrics.json"
            metrics_path.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            completed.append(metadata)
    return completed


def _flatten_numeric(value: Any, prefix: str = "") -> dict[str, float]:
    output: dict[str, float] = {}
    if isinstance(value, dict):
        for key, child in value.items():
            name = f"{prefix}.{key}" if prefix else str(key)
            output.update(_flatten_numeric(child, name))
    elif isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(float(value)):
        output[prefix] = float(value)
    return output


def _aggregate(completed: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for run in completed:
        groups[(run["split_id"], run["method"])].append(run)
    output: list[dict[str, Any]] = []
    for (split_id, method), runs in sorted(groups.items()):
        metric_values: dict[str, list[float]] = defaultdict(list)
        for run in runs:
            for name, value in _flatten_numeric(run["metrics"]).items():
                if name != "sample_count":
                    metric_values[name].append(value)
        output.append(
            {
                "split_id": split_id,
                "method": method,
                "seed_count": len(runs),
                "seeds": sorted(int(run["seed"]) for run in runs),
                "metrics": {
                    name: {
                        "mean": mean(values),
                        "sample_standard_deviation": stdev(values) if len(values) > 1 else None,
                        "values": values,
                    }
                    for name, values in sorted(metric_values.items())
                },
            }
        )
    return output


def discover_splits(split_root: Path, pattern: str, max_splits: int | None) -> list[Path]:
    paths = [path for path in sorted(split_root.rglob("*.json")) if fnmatch.fnmatch(path.stem, pattern)]
    return paths[:max_splits] if max_splits is not None else paths


def dry_run(dataset: Path, split_paths: list[Path], include_linked_variants: bool) -> dict[str, Any]:
    rows = _load_jsonl(dataset)
    ids = {row["artifact_id"] for row in rows}
    problems: list[str] = []
    summaries = []
    for path in split_paths:
        split = json.loads(path.read_text(encoding="utf-8"))
        partitions = {name: set(split[name]) for name in ("train_ids", "calibration_ids", "test_ids")}
        if any(not values <= ids for values in partitions.values()):
            problems.append(f"unknown artifact ID in {path}")
        linked = _linked_test_rows(rows, partitions["test_ids"], include_linked_variants)
        variant_counts = {variant: sum(row.get("capture_variant") == variant for row in linked) for variant in ("FULL", "LOSS_10", "LOSS_30", "LOSS_50")}
        if include_linked_variants and any(row.get("capture_variant", "FULL").startswith("LOSS_") for row in rows):
            if variant_counts["FULL"] and not any(variant_counts[variant] for variant in ("LOSS_10", "LOSS_30", "LOSS_50")):
                problems.append(f"no packet-loss derivatives linked to test FULL rows: {path}")
        summaries.append(
            {
                "split": str(path),
                "seed": split["seed"],
                "train": len(partitions["train_ids"]),
                "calibration": len(partitions["calibration_ids"]),
                "test_with_linked_variants": len(linked),
                "test_variant_counts": variant_counts,
            }
        )
    return {
        "valid": not problems,
        "dataset_sha256": sha256_file(dataset),
        "dataset_rows": len(rows),
        "split_count": len(split_paths),
        "include_linked_variants": include_linked_variants,
        "problems": problems,
        "splits": summaries,
        "metrics": "TBD — dry-run performs no model fitting",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run VPNGUARD-X baseline and CGII evaluation")
    parser.add_argument("dataset", type=Path)
    parser.add_argument("splits", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--app-models", nargs="+", choices=["xgboost", "tcn"], default=["xgboost", "tcn"])
    parser.add_argument("--epochs", type=int, default=30)
    parser.add_argument("--alpha", type=float, default=0.10)
    parser.add_argument("--split-pattern", default="*")
    parser.add_argument("--max-splits", type=int)
    parser.add_argument("--exclude-linked-variants", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    split_paths = discover_splits(args.splits, args.split_pattern, args.max_splits)
    if not split_paths:
        raise ValueError("no split manifests matched")
    include_linked = not args.exclude_linked_variants
    args.output.mkdir(parents=True, exist_ok=True)
    if args.dry_run:
        result = dry_run(args.dataset, split_paths, include_linked)
        (args.output / "dry-run.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps({key: value for key, value in result.items() if key != "splits"}, indent=2, sort_keys=True))
        return 0 if result["valid"] else 1
    dataset_rows = _load_jsonl(args.dataset)
    dataset_sha256 = sha256_file(args.dataset)
    completed: list[dict[str, Any]] = []
    for split_path in split_paths:
        completed.extend(
            _run_one_split(
                dataset_rows,
                dataset_sha256,
                split_path,
                args.output,
                app_models=tuple(args.app_models),
                epochs=args.epochs,
                alpha=args.alpha,
                include_linked_variants=include_linked,
            )
        )
    result = {
        "schema_version": "0.2.0",
        "dataset_file": str(args.dataset.resolve()),
        "dataset_sha256": dataset_sha256,
        "split_root": str(args.splits.resolve()),
        "split_count": len(split_paths),
        "completed_method_runs": len(completed),
        "app_models": args.app_models,
        "epochs": args.epochs,
        "alpha": args.alpha,
        "aggregate": _aggregate(completed),
    }
    (args.output / "aggregate-results.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({key: value for key, value in result.items() if key != "aggregate"}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
