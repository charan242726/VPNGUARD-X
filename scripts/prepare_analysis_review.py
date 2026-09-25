#!/usr/bin/env python3
"""Build sanitized, size-bounded publication review archives.

The common archive contains the portable dataset, manifests, split files,
corrected metrics, audits, and redacted ground truth.  Prediction records are
split by evaluation seed so no raw PCAP or endpoint secret is required and
each archive remains practical to transfer.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.prepare_safe_review import FORBIDDEN_NAMES, FORBIDDEN_SUFFIXES, has_secret


PERSONAL_ABSOLUTE_PATH = re.compile(
    r"(?:/home/[^/\s\"']+|/Users/[^/\s\"']+|/workspace/[^/\s\"']+|(?<![A-Za-z0-9+.-])[A-Za-z]:[\\/])"
)
REPOSITORY_MARKERS = (
    "artifacts/", "data/", "configs/", "cyber_range/", "experiments/",
    "features/", "models/", "parser/", "docs/", "scripts/", "tests/",
)
COMMON_PATTERNS = (
    "artifacts/environment/preflight.json",
    "artifacts/audits/*.json",
    "artifacts/plans/*.csv",
    "artifacts/plans/*.manifest.json",
    "artifacts/splits/**/*.json",
    "artifacts/range/**/ground_truth.json",
    "artifacts/range/**/scenario_manifest.json",
    "artifacts/range/**/*.pcap.loss.json",
    "data/generated/*.manifest.json",
    "configs/benchmark_design.yaml",
    "configs/candidate_catalogue.yaml",
    "configs/policy_rules.yaml",
    "data/IPsec_Observability_Matrix.csv",
    "data/CyberRange_Scenario_Matrix.csv",
    "docs/Standards_Rulebook.md",
    "docs/Experiment_and_Evaluation_Plan.md",
)


def _sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _portable_string(value: str) -> str:
    normalized = value.replace("\\", "/")
    for marker in REPOSITORY_MARKERS:
        position = normalized.find(marker)
        if position >= 0:
            return normalized[position:]
    if normalized.startswith("/") or re.match(r"^[A-Za-z]:/", normalized):
        return f"<ABSOLUTE_PATH_REDACTED>/{Path(normalized).name}"
    return value


def _sanitize(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _sanitize(child) for key, child in value.items()}
    if isinstance(value, list):
        return [_sanitize(child) for child in value]
    if isinstance(value, str):
        return _portable_string(value)
    return value


def _sanitized_content(path: Path) -> bytes:
    content = path.read_bytes()
    if path.suffix.lower() == ".json":
        document = _sanitize(json.loads(content))
        content = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()
    elif path.suffix.lower() == ".jsonl":
        rows = [_sanitize(json.loads(line)) for line in content.decode("utf-8").splitlines() if line.strip()]
        content = "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows).encode()
    return content


def _validate_export(path: Path, content: bytes) -> None:
    if path.name in FORBIDDEN_NAMES or path.suffix.lower() in FORBIDDEN_SUFFIXES:
        raise ValueError(f"forbidden file selected: {path}")
    if has_secret(path, content):
        raise ValueError(f"potential credential in selected evidence: {path}")
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        return
    if PERSONAL_ABSOLUTE_PATH.search(text):
        raise ValueError(f"personal absolute path remains after sanitization: {path}")


def _write_archive(path: Path, entries: Iterable[tuple[str, bytes]], *, purpose: str) -> dict[str, Any]:
    selected = list(entries)
    inventory = {
        "schema_version": "0.3.0",
        "purpose": purpose,
        "contains_raw_pcaps": False,
        "contains_endpoint_secrets": False,
        "file_count": len(selected),
        "files": [
            {"path": name, "size_bytes": len(content), "sha256": _sha256_bytes(content)}
            for name, content in selected
        ],
    }
    inventory_content = (json.dumps(inventory, indent=2, sort_keys=True) + "\n").encode()
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, content in selected:
            archive.writestr(name, content)
        archive.writestr("ARCHIVE_INVENTORY.json", inventory_content)
    with zipfile.ZipFile(path) as archive:
        failing = archive.testzip()
        if failing:
            raise ValueError(f"archive CRC validation failed: {failing}")
    return {
        "filename": path.name,
        "size_bytes": path.stat().st_size,
        "sha256": _sha256_file(path),
        "evidence_file_count": len(selected),
    }


def prepare_analysis_review(
    project: str | Path,
    output_directory: str | Path,
    *,
    source_results: str = "artifacts/results_corrected",
    final_results: str = "artifacts/results_final",
    portable_dataset: str = "data/publication/vpnguard_x_combined.jsonl",
) -> dict[str, Any]:
    selected = Path(project).resolve()
    output = Path(output_directory).resolve()
    source_root = selected / source_results
    final_root = selected / final_results
    dataset_path = selected / portable_dataset
    if not dataset_path.is_file():
        raise ValueError(f"portable dataset missing: {dataset_path}")
    prediction_paths = sorted(source_root.glob("seed-*/*/*/predictions.jsonl"))
    if not prediction_paths:
        raise ValueError("prediction files are required; run this on the full student repository")
    final_metric_paths = sorted(final_root.glob("seed-*/*/*/metrics.json"))
    if not final_metric_paths:
        raise ValueError("corrected final metrics are missing")

    common_map: dict[str, Path] = {}
    for pattern in COMMON_PATTERNS:
        for path in selected.glob(pattern):
            if path.is_file():
                common_map[path.relative_to(selected).as_posix()] = path
    common_map["data/publication/vpnguard_x_combined.jsonl"] = dataset_path
    manifest_path = dataset_path.with_suffix(dataset_path.suffix + ".manifest.json")
    if manifest_path.is_file():
        common_map["data/publication/vpnguard_x_combined.jsonl.manifest.json"] = manifest_path
    for path in sorted(final_root.rglob("*")):
        if path.is_file() and path.name != "predictions.jsonl":
            common_map[path.relative_to(selected).as_posix()] = path
    # A finalization run stores the limitation, lineage, dataset, and telemetry
    # audits next to its corrected results.  Include those evidence files even
    # though they are intentionally outside the historical artifacts/audits
    # directory.
    run_audit_root = final_root.parent / "audits"
    if run_audit_root.is_dir():
        for path in sorted(run_audit_root.rglob("*")):
            if path.is_file():
                common_map[path.relative_to(selected).as_posix()] = path

    readme = (
        "VPNGUARD-X publication evidence bundle\n\n"
        "Extract this common archive and every prediction-seed archive into the same directory.\n"
        "No raw PCAP, endpoint secret, or private key is included.\n"
        "The dataset contains normalized repository-relative paths; its manifest links it "
        "to the original dataset hash.\n"
    )
    common_entries: list[tuple[str, bytes]] = [("README_COMBINE_ARCHIVES.txt", readme.encode())]
    for name, path in sorted(common_map.items()):
        content = _sanitized_content(path)
        _validate_export(Path(name), content)
        common_entries.append((name, content))

    output.mkdir(parents=True, exist_ok=True)
    archives = [
        _write_archive(
            output / "VPNGUARD-X_Publication_Evidence_Common.zip",
            common_entries,
            purpose="sanitized dataset, ground truth, split manifests, corrected metrics, and audits",
        )
    ]
    predictions_by_seed: dict[str, list[Path]] = {}
    for path in prediction_paths:
        seed = next((part for part in path.relative_to(source_root).parts if part.startswith("seed-")), "seed-unknown")
        predictions_by_seed.setdefault(seed, []).append(path)
    for seed, paths in sorted(predictions_by_seed.items()):
        entries = []
        for path in paths:
            content = path.read_bytes()
            _validate_export(path, content)
            entries.append((path.relative_to(selected).as_posix(), content))
        archives.append(
            _write_archive(
                output / f"VPNGUARD-X_Publication_Predictions_{seed}.zip",
                entries,
                purpose=f"immutable prediction records for {seed}",
            )
        )

    report = {
        "schema_version": "0.3.0",
        "created_at_utc": datetime.now(UTC).isoformat(),
        "source_results": source_results,
        "final_results": final_results,
        "portable_dataset": portable_dataset,
        "prediction_file_count": len(prediction_paths),
        "final_metric_file_count": len(final_metric_paths),
        "archives": archives,
    }
    index_path = output / "VPNGUARD-X_Publication_Bundle_Index.json"
    index_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", type=Path, default=ROOT)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--source-results", default="artifacts/results_corrected")
    parser.add_argument("--final-results", default="artifacts/results_final")
    parser.add_argument("--portable-dataset", default="data/publication/vpnguard_x_combined.jsonl")
    args = parser.parse_args()
    result = prepare_analysis_review(
        args.project,
        args.output_dir,
        source_results=args.source_results,
        final_results=args.final_results,
        portable_dataset=args.portable_dataset,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
