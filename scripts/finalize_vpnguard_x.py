#!/usr/bin/env python3
"""Finalize an executed VPNGUARD-X benchmark without rerunning the range.

This command is intentionally post-processing only.  It verifies the existing
dataset, split manifests, predictions, and result lineage; creates a portable
dataset; recomputes the corrected set-valued configuration metrics; performs a
hierarchical bootstrap; revalidates stored cooperative telemetry; and creates
separate SIH and publication evidence packages.  Original artifacts are never
modified.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from common.provenance import sha256_file
from experiments.audit_dataset import audit_dataset
from experiments.recompute_metrics_from_predictions import METRIC_SEMANTICS, recompute
from experiments.revalidate_cooperative_telemetry import audit_telemetry
from experiments.sanitize_dataset import sanitize_dataset
from scripts.build_release import build_archive
from scripts.prepare_analysis_review import prepare_analysis_review
from scripts.validate_repository import validate as validate_repository


RELEASE_VERSION = "0.2.5"
EXPECTED_SEEDS = {11, 22, 33, 44, 55}
EXPECTED_LOSS_LEVELS = {"0.0", "0.1", "0.3", "0.5"}


class FinalizationError(RuntimeError):
    """A user-actionable finalization prerequisite was not met."""


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _rel(path: Path, project: Path) -> str:
    try:
        return path.resolve().relative_to(project.resolve()).as_posix()
    except ValueError:
        return str(path.resolve())


def _find_dataset(project: Path, source_results: Path, explicit: Path | None) -> Path:
    if explicit is not None:
        selected = explicit if explicit.is_absolute() else project / explicit
        if not selected.is_file():
            raise FinalizationError(f"dataset does not exist: {selected}")
        return selected.resolve()

    aggregate_path = source_results / "aggregate-results.json"
    if aggregate_path.is_file():
        aggregate = json.loads(aggregate_path.read_text(encoding="utf-8"))
        recorded = aggregate.get("dataset_file")
        if isinstance(recorded, str) and recorded:
            selected = Path(recorded)
            selected = selected if selected.is_absolute() else project / selected
            if selected.is_file():
                return selected.resolve()

    candidates = sorted(
        path
        for path in (project / "data/generated").glob("*.jsonl")
        if "sanitized" not in path.name.lower() and "portable" not in path.name.lower()
    )
    if len(candidates) == 1:
        return candidates[0].resolve()
    if not candidates:
        raise FinalizationError(
            "full dataset JSONL is missing. The small safe-review ZIP deliberately omits it; "
            "run this command inside the students' full VPNGUARD-X repository."
        )
    # If several generated JSONL files exist, select only the file whose hash
    # is recorded by the immutable result metadata.  This removes a fragile
    # filename guess while retaining a cryptographic selection criterion.
    recorded_hashes: Counter[str] = Counter()
    for metrics_path in source_results.rglob("metrics.json"):
        try:
            value = json.loads(metrics_path.read_text(encoding="utf-8")).get("dataset_sha256")
        except (OSError, ValueError):
            continue
        if isinstance(value, str) and value:
            recorded_hashes[value] += 1
    matching = [path for path in candidates if sha256_file(path) in recorded_hashes]
    if len(matching) == 1:
        return matching[0].resolve()
    if len(matching) > 1 and len({sha256_file(path) for path in matching}) == 1:
        return matching[0].resolve()
    names = ", ".join(path.relative_to(project).as_posix() for path in candidates)
    raise FinalizationError(
        f"multiple dataset JSONL files found and no unique result-hash match exists ({names}); "
        "pass --dataset explicitly"
    )


def _resolve_split(project: Path, metadata: dict[str, Any]) -> Path | None:
    recorded = metadata.get("split_file")
    if isinstance(recorded, str) and recorded:
        path = Path(recorded)
        candidate = path if path.is_absolute() else project / path
        if candidate.is_file():
            return candidate.resolve()
        by_name = list((project / "artifacts/splits").rglob(path.name))
        if len(by_name) == 1:
            return by_name[0].resolve()
    return None


def _audit_lineage(project: Path, source_results: Path, dataset: Path) -> dict[str, Any]:
    prediction_paths = sorted(source_results.rglob("predictions.jsonl"))
    if not prediction_paths:
        raise FinalizationError(
            "no prediction JSONL files were found. Metrics cannot be corrected from the safe-review ZIP; "
            "use the full executed repository containing artifacts/results_corrected/**/predictions.jsonl."
        )
    dataset_hash = sha256_file(dataset)
    issues: list[str] = []
    seeds: Counter[int] = Counter()
    split_ids: Counter[str] = Counter()
    methods: Counter[str] = Counter()
    source_dataset_hashes: Counter[str] = Counter()
    split_hash_verified = 0
    prediction_hash_verified = 0
    for prediction_path in prediction_paths:
        metrics_path = prediction_path.with_name("metrics.json")
        relative = prediction_path.relative_to(project).as_posix()
        if not metrics_path.is_file():
            issues.append(f"missing metrics beside {relative}")
            continue
        try:
            metadata = json.loads(metrics_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            issues.append(f"invalid metrics JSON beside {relative}: {type(exc).__name__}")
            continue
        expected_prediction_hash = metadata.get("prediction_sha256")
        actual_prediction_hash = sha256_file(prediction_path)
        if expected_prediction_hash != actual_prediction_hash:
            issues.append(f"prediction SHA-256 mismatch: {relative}")
        else:
            prediction_hash_verified += 1
        split_path = _resolve_split(project, metadata)
        if split_path is None:
            issues.append(f"split file cannot be resolved: {metadata.get('split_file')!r}")
        elif metadata.get("split_sha256") != sha256_file(split_path):
            issues.append(f"split SHA-256 mismatch: {_rel(split_path, project)}")
        else:
            split_hash_verified += 1
        try:
            seeds[int(metadata["seed"])] += 1
            split_ids[str(metadata["split_id"])] += 1
            methods[str(metadata["method"])] += 1
        except (KeyError, TypeError, ValueError):
            issues.append(f"missing run identity in {metrics_path.relative_to(project).as_posix()}")
        source_dataset_hashes[str(metadata.get("dataset_sha256"))] += 1

    if set(source_dataset_hashes) != {dataset_hash}:
        issues.append(
            "source metric dataset hashes do not all match the selected immutable dataset "
            f"({dataset_hash})"
        )
    return {
        "schema_version": "0.3.0",
        "dataset": _rel(dataset, project),
        "dataset_sha256": dataset_hash,
        "prediction_file_count": len(prediction_paths),
        "prediction_hash_verified_count": prediction_hash_verified,
        "split_hash_verified_count": split_hash_verified,
        "seeds": dict(sorted(seeds.items())),
        "split_ids": dict(sorted(split_ids.items())),
        "methods": dict(sorted(methods.items())),
        "source_dataset_hash_counts": dict(sorted(source_dataset_hashes.items())),
        "issues": issues,
        "valid": not issues,
    }


def _audit_scenario_manifests(project: Path) -> dict[str, Any]:
    # Include derived packet-loss records in the inventory, while restricting
    # manifest provenance checks to their FULL source captures.
    truth_paths = sorted((project / "artifacts/range").rglob("ground_truth.json"))
    full_count = 0
    hash_matches = 0
    hash_mismatches = 0
    missing = 0
    semantic_matches = 0
    semantic_mismatches: list[str] = []
    statuses: Counter[str] = Counter()
    variants: Counter[str] = Counter()
    stacks: Counter[str] = Counter()
    seeds: Counter[int] = Counter()
    for truth_path in truth_paths:
        truth = json.loads(truth_path.read_text(encoding="utf-8"))
        variant = str(truth.get("capture", {}).get("capture_variant"))
        variants[variant] += 1
        stacks[str(truth.get("stack"))] += 1
        if truth.get("seed") is not None:
            seeds[int(truth["seed"])] += 1
        if variant != "FULL":
            continue
        full_count += 1
        manifest_path = truth_path.with_name("scenario_manifest.json")
        if not manifest_path.is_file():
            missing += 1
            continue
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        statuses[str(manifest.get("status"))] += 1
        if manifest.get("manifest_hash") == truth.get("scenario_manifest_hash"):
            hash_matches += 1
        else:
            hash_mismatches += 1
        semantic_fields_match = all(
            (
                manifest.get("scenario_id") == truth.get("scenario_id"),
                manifest.get("source_scenario_id") == truth.get("source_scenario_id"),
                manifest.get("seed") == truth.get("seed"),
                manifest.get("stack") == truth.get("stack"),
                manifest.get("configured_properties") == truth.get("configured_properties"),
            )
        )
        if semantic_fields_match:
            semantic_matches += 1
        else:
            semantic_mismatches.append(truth_path.parent.relative_to(project).as_posix())
    limitation = None
    if hash_mismatches:
        limitation = (
            "Historical scenario manifests were regenerated after execution: their recorded hashes do not "
            "authenticate the executed runs. Semantic equality is reported separately and does not repair "
            "the missing original cryptographic provenance."
        )
    return {
        "schema_version": "0.3.0",
        "ground_truth_count": len(truth_paths),
        "full_capture_count": full_count,
        "capture_variants": dict(sorted(variants.items())),
        "stacks": dict(sorted(stacks.items())),
        "seeds": dict(sorted(seeds.items())),
        "manifest_statuses": dict(sorted(statuses.items())),
        "manifest_hash_match_count": hash_matches,
        "manifest_hash_mismatch_count": hash_mismatches,
        "manifest_missing_count": missing,
        "semantic_match_count": semantic_matches,
        "semantic_mismatch_count": len(semantic_mismatches),
        "semantic_mismatch_examples": semantic_mismatches[:20],
        "known_limitation": limitation,
    }


def _prediction_loss_levels(source_results: Path) -> set[str]:
    levels: set[str] = set()
    for path in sorted(source_results.rglob("predictions.jsonl")):
        with path.open(encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                row = json.loads(line)
                if row.get("packet_loss_fraction") is not None:
                    levels.add(str(float(row["packet_loss_fraction"])))
    return levels


def _run_tests(project: Path, output: Path) -> dict[str, Any]:
    completed = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
        cwd=project,
        text=True,
        capture_output=True,
        check=False,
        timeout=600,
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(completed.stdout + completed.stderr, encoding="utf-8")
    return {
        "command": f"{Path(sys.executable).name} -m unittest discover -s tests -v",
        "returncode": completed.returncode,
        "passed": completed.returncode == 0,
        "log": _rel(output, project),
    }


def _readiness_reports(
    *,
    project: Path,
    run_directory: Path,
    repository: dict[str, Any],
    tests: dict[str, Any],
    dataset_audit: dict[str, Any],
    lineage: dict[str, Any],
    scenario: dict[str, Any],
    telemetry: dict[str, Any],
    recomputation: dict[str, Any],
    review_bundle: dict[str, Any],
    packet_loss_coverage: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    common_failures = []
    if not repository.get("valid"):
        common_failures.append("repository validation failed")
    if not tests.get("passed"):
        common_failures.append("unit tests failed")
    if not dataset_audit.get("valid"):
        common_failures.append("dataset/split audit failed")
    if not lineage.get("valid"):
        common_failures.append("prediction or split lineage audit failed")
    if lineage.get("prediction_file_count") != 840:
        common_failures.append(f"expected 840 prediction files, found {lineage.get('prediction_file_count')}")
    if dataset_audit.get("row_count") != 3600:
        common_failures.append(f"expected 3600 dataset records, found {dataset_audit.get('row_count')}")
    if dataset_audit.get("split_manifest_count") != 140:
        common_failures.append(f"expected 140 split manifests, found {dataset_audit.get('split_manifest_count')}")
    if set(map(int, lineage.get("seeds", {}).keys())) != EXPECTED_SEEDS:
        common_failures.append("five-seed coverage is incomplete")
    if any(count != 168 for count in lineage.get("seeds", {}).values()):
        common_failures.append("each seed must contain exactly 168 method/split prediction files")
    if len(lineage.get("split_ids", {})) != 28 or any(
        count != 30 for count in lineage.get("split_ids", {}).values()
    ):
        common_failures.append("expected 28 split IDs with 30 prediction files each")
    if len(lineage.get("methods", {})) != 6 or any(
        count != 140 for count in lineage.get("methods", {}).values()
    ):
        common_failures.append("expected six methods with 140 prediction files each")
    if scenario.get("ground_truth_count") != 3600 or scenario.get("full_capture_count") != 900:
        common_failures.append("expected 3,600 ground-truth records including 900 FULL captures")
    if scenario.get("capture_variants") != {"FULL": 900, "LOSS_10": 900, "LOSS_30": 900, "LOSS_50": 900}:
        common_failures.append("ground-truth packet-loss variants are incomplete or unbalanced")
    if scenario.get("stacks") != {
        "strongSwan-6.1.0": 3240,
        "strongSwan-6.1.0-to-Libreswan-5.4": 360,
    }:
        common_failures.append("expected strongSwan and strongSwan-to-Libreswan evidence counts are incomplete")
    if set(map(int, scenario.get("seeds", {}).keys())) != EXPECTED_SEEDS or any(
        count != 720 for count in scenario.get("seeds", {}).values()
    ):
        common_failures.append("ground-truth records are not balanced across the five declared seeds")
    if not packet_loss_coverage.get("complete"):
        common_failures.append(
            f"prediction packet-loss coverage is incomplete: {packet_loss_coverage.get('observed_loss_levels')}"
        )

    disclosures = []
    if scenario.get("manifest_hash_mismatch_count"):
        disclosures.append(scenario["known_limitation"])
    disclosures.extend(telemetry.get("publication_claim_blockers", []))
    if scenario.get("semantic_mismatch_count"):
        common_failures.append("scenario manifest semantic fields conflict with executed ground truth")

    sih = {
        "schema_version": "0.3.0",
        "status": "FAIL" if common_failures else "PASS_WITH_DISCLOSED_LIMITATIONS" if disclosures else "PASS",
        "scope": "working prototype and reproducibility package",
        "failures": common_failures,
        "disclosures": disclosures,
        "verified": {
            "repository": repository,
            "tests": tests,
            "dataset_and_splits": dataset_audit,
            "immutable_prediction_lineage": lineage,
            "metric_recomputation_without_retraining": recomputation,
            "review_archives": review_bundle,
        },
    }
    publication_failures = list(common_failures)
    if recomputation.get("hierarchical_interval_count") != 168:
        publication_failures.append(
            f"expected 168 hierarchical interval groups, found {recomputation.get('hierarchical_interval_count')}"
        )
    if recomputation.get("paired_effect_count") != 112:
        publication_failures.append(
            f"expected 112 paired CGII effects, found {recomputation.get('paired_effect_count')}"
        )
    publication = {
        "schema_version": "0.3.0",
        "status": (
            "FAIL"
            if publication_failures
            else "CONDITIONAL_PASS_WITH_MANDATORY_DISCLOSURES"
            if disclosures
            else "PASS_FOR_MANUSCRIPT_DRAFTING"
        ),
        "scope": "evidence package suitable for manuscript analysis; journal acceptance is never guaranteed",
        "failures": publication_failures,
        "mandatory_disclosures": disclosures,
        "claim_boundaries": [
            "Do not claim that regenerated scenario manifests cryptographically authenticate execution.",
            "Do not report PFS, anti-replay, configured lifetime, or other hidden CHILD-SA properties as passively observed.",
            "Report ambiguous configuration outputs as prediction sets/abstentions, not arbitrary point predictions.",
            "Describe the cross-stack result as strongSwan-to-Libreswan interoperability, not broad multi-vendor generalization.",
        ],
        "metric_semantics": METRIC_SEMANTICS,
        "scenario_manifest_audit": scenario,
        "cooperative_telemetry_audit": {
            key: telemetry.get(key)
            for key in (
                "full_run_count",
                "missing_source_file_counts",
                "parse_error_count",
                "property_status_counts",
                "publication_claim_blockers",
                "terminology",
            )
        },
    }
    _write_json(run_directory / "reports/SIH_READINESS.json", sih)
    _write_json(run_directory / "reports/PUBLICATION_READINESS.json", publication)

    def render(title: str, report: dict[str, Any], disclosure_key: str) -> str:
        lines = [f"# {title}", "", f"**Status:** `{report['status']}`", ""]
        failures = report.get("failures", [])
        lines.extend(["## Blocking failures", ""])
        lines.extend([f"- {item}" for item in failures] or ["- None."])
        lines.extend(["", "## Required disclosures", ""])
        lines.extend([f"- {item}" for item in report.get(disclosure_key, [])] or ["- None."])
        lines.extend(
            [
                "",
                "## What was executed",
                "",
                "- Existing prediction records were verified and reused; no model retraining occurred.",
                "- Configuration point metrics use singleton prediction sets; all other sets abstain.",
                "- Corrected per-run metrics and hierarchical confidence intervals were written to a new directory.",
                "- Original captures, predictions, metrics, and ground truth were not modified.",
                "",
                f"Run directory: `{_rel(run_directory, project)}`",
                "",
            ]
        )
        return "\n".join(lines)

    (run_directory / "reports/SIH_READINESS.md").write_text(
        render("VPNGUARD-X SIH Readiness", sih, "disclosures"), encoding="utf-8"
    )
    (run_directory / "reports/PUBLICATION_READINESS.md").write_text(
        render("VPNGUARD-X Publication Readiness", publication, "mandatory_disclosures"), encoding="utf-8"
    )
    return sih, publication


def finalize(
    project: str | Path,
    *,
    source_results: str = "artifacts/results_corrected",
    dataset: Path | None = None,
    bootstrap_iterations: int = 2000,
    bootstrap_seed: int = 26160,
    run_id: str | None = None,
) -> dict[str, Any]:
    selected = Path(project).resolve()
    if not (selected / "pyproject.toml").is_file() or not (selected / "experiments").is_dir():
        raise FinalizationError(f"not a VPNGUARD-X repository: {selected}")
    source_root = selected / source_results
    if not source_root.is_dir():
        raise FinalizationError(f"source result directory is missing: {source_root}")
    selected_dataset = _find_dataset(selected, source_root, dataset)
    identifier = run_id or datetime.now(UTC).strftime("run-%Y%m%dT%H%M%SZ")
    run_directory = selected / "artifacts/finalization" / identifier
    if run_directory.exists():
        raise FinalizationError(
            f"finalization directory already exists: {run_directory}; choose a new --run-id"
        )
    run_directory.mkdir(parents=True)

    repository = validate_repository()
    _write_json(run_directory / "audits/repository-validation.json", repository)
    tests = _run_tests(selected, run_directory / "audits/unit-tests.log")
    _write_json(run_directory / "audits/unit-tests.json", tests)
    if not tests["passed"]:
        raise FinalizationError(f"unit tests failed; see {run_directory / 'audits/unit-tests.log'}")

    lineage = _audit_lineage(selected, source_root, selected_dataset)
    _write_json(run_directory / "audits/prediction-lineage.json", lineage)
    if not lineage["valid"]:
        raise FinalizationError(
            f"prediction lineage audit failed; see {run_directory / 'audits/prediction-lineage.json'}"
        )

    portable_dataset = run_directory / "data/vpnguard_x_combined.sanitized.jsonl"
    portable_manifest = sanitize_dataset(selected_dataset, portable_dataset)
    portable_manifest["original_repository_path"] = _rel(selected_dataset, selected)
    _write_json(portable_dataset.with_suffix(".jsonl.manifest.json"), portable_manifest)

    dataset_report = audit_dataset(portable_dataset, selected / "artifacts/splits")
    _write_json(run_directory / "audits/dataset-and-splits.json", dataset_report)
    if not dataset_report["valid"]:
        raise FinalizationError(
            f"dataset/split audit failed; see {run_directory / 'audits/dataset-and-splits.json'}"
        )

    scenario_report = _audit_scenario_manifests(selected)
    _write_json(run_directory / "audits/scenario-manifest-provenance.json", scenario_report)
    telemetry_report = audit_telemetry(selected)
    _write_json(run_directory / "audits/cooperative-telemetry-validation.json", telemetry_report)

    loss_levels = _prediction_loss_levels(source_root)
    coverage = {
        "observed_loss_levels": sorted(loss_levels),
        "expected_loss_levels": sorted(EXPECTED_LOSS_LEVELS),
        "complete": EXPECTED_LOSS_LEVELS <= loss_levels,
    }
    _write_json(run_directory / "audits/packet-loss-coverage.json", coverage)

    final_results = run_directory / "results"
    recomputation = recompute(
        source_root,
        final_results,
        iterations=bootstrap_iterations,
        bootstrap_seed=bootstrap_seed,
        dataset_file=_rel(portable_dataset, selected),
        dataset_sha256=portable_manifest["sanitized_sha256"],
    )
    _write_json(run_directory / "audits/metric-recomputation.json", recomputation)

    review_output = run_directory / "publication_evidence"
    review_bundle = prepare_analysis_review(
        selected,
        review_output,
        source_results=source_results,
        final_results=_rel(final_results, selected),
        portable_dataset=_rel(portable_dataset, selected),
    )
    source_archive = run_directory / f"VPNGUARD-X_SIH_Source_{RELEASE_VERSION}.zip"
    source_release = build_archive(source_archive, run_tests=False, version=RELEASE_VERSION)

    sih, publication = _readiness_reports(
        project=selected,
        run_directory=run_directory,
        repository=repository,
        tests=tests,
        dataset_audit=dataset_report,
        lineage=lineage,
        scenario=scenario_report,
        telemetry=telemetry_report,
        recomputation=recomputation,
        review_bundle=review_bundle,
        packet_loss_coverage=coverage,
    )

    summary = {
        "schema_version": "0.3.0",
        "release_version": RELEASE_VERSION,
        "created_at_utc": datetime.now(UTC).isoformat(),
        "project": str(selected),
        "run_directory": str(run_directory),
        "model_retraining_performed": False,
        "cyber_range_rerun_performed": False,
        "original_artifacts_modified": False,
        "source_results": source_results,
        "source_dataset": _rel(selected_dataset, selected),
        "sih_status": sih["status"],
        "publication_status": publication["status"],
        "source_release": source_release,
        "publication_archives": review_bundle["archives"],
        "reports": {
            "sih": _rel(run_directory / "reports/SIH_READINESS.md", selected),
            "publication": _rel(run_directory / "reports/PUBLICATION_READINESS.md", selected),
        },
    }
    _write_json(run_directory / "FINALIZATION_SUMMARY.json", summary)
    latest_path = selected / "artifacts/finalization/LATEST.txt"
    latest_path.write_text(identifier + "\n", encoding="utf-8")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", type=Path, default=ROOT)
    parser.add_argument("--source-results", default="artifacts/results_corrected")
    parser.add_argument("--dataset", type=Path)
    parser.add_argument("--bootstrap-iterations", type=int, default=2000)
    parser.add_argument("--bootstrap-seed", type=int, default=26160)
    parser.add_argument("--run-id")
    args = parser.parse_args()
    try:
        result = finalize(
            args.project,
            source_results=args.source_results,
            dataset=args.dataset,
            bootstrap_iterations=args.bootstrap_iterations,
            bootstrap_seed=args.bootstrap_seed,
            run_id=args.run_id,
        )
    except (FinalizationError, OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"FINALIZATION FAILED: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
