#!/usr/bin/env python3
"""Compile or execute a generated run plan with resumable audit logging."""

from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from common.provenance import sha256_file
from cyber_range.range import DEFAULT_MATRIX, compile_planned_run, run_scenario, validate_artifacts


def _load_plan(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    if not rows or len({row["run_id"] for row in rows}) != len(rows):
        raise ValueError("run plan must contain unique rows")
    return rows


def execute_plan(
    plan_path: str | Path,
    output_root: str | Path,
    *,
    mode: str,
    matrix_path: str | Path = DEFAULT_MATRIX,
    resume: bool = True,
    fail_fast: bool = False,
    limit: int | None = None,
) -> dict:
    if mode not in {"compile", "run"}:
        raise ValueError("mode must be compile or run")
    plan = Path(plan_path).resolve()
    output = Path(output_root).resolve()
    rows = _load_plan(plan)
    if limit is not None:
        if limit < 1:
            raise ValueError("limit must be positive")
        rows = rows[:limit]
    records: list[dict] = []
    for index, row in enumerate(rows, start=1):
        final_pcap = output / row["run_id"] / f"seed-{row['seed']}" / "capture.pcap"
        final_truth = final_pcap.parent / "ground_truth.json"
        # Compilation writes scenario_manifest.json and endpoint configuration
        # into the run directory.  Recompiling a completed run would overwrite
        # the manifest authenticated by ground_truth.json even when the PCAP is
        # intentionally preserved.  Resume protection therefore applies to
        # both compile and run modes.
        if resume and final_pcap.exists() and final_truth.exists():
            records.append({"run_id": row["run_id"], "status": "SKIPPED_COMPLETED", "index": index})
            continue
        started = time.perf_counter()
        try:
            compiled = compile_planned_run(row, output, matrix_path=matrix_path)
            if mode == "run":
                run_scenario(compiled)
            records.append(
                {
                    "run_id": row["run_id"],
                    "status": "COMPILED" if mode == "compile" else "COMPLETED",
                    "index": index,
                    "elapsed_seconds": time.perf_counter() - started,
                }
            )
        except Exception as exc:
            records.append(
                {
                    "run_id": row["run_id"],
                    "status": "FAILED",
                    "index": index,
                    "elapsed_seconds": time.perf_counter() - started,
                    "reason": f"{type(exc).__name__}: {exc}",
                }
            )
            if fail_fast:
                break
    failures = [record for record in records if record["status"] == "FAILED"]
    artifact_problems = validate_artifacts(output) if mode == "run" and not failures else []
    manifest = {
        "schema_version": "0.2.0",
        "mode": mode,
        "plan_file": str(plan),
        "plan_sha256": sha256_file(plan),
        "matrix_sha256": sha256_file(matrix_path),
        "output_root": str(output),
        "started_row_count": len(records),
        "completed_count": sum(record["status"] == "COMPLETED" for record in records),
        "compiled_count": sum(record["status"] == "COMPILED" for record in records),
        "skipped_count": sum(record["status"] == "SKIPPED_COMPLETED" for record in records),
        "failed_count": len(failures),
        "artifact_validation_problems": artifact_problems,
        "completed_at_utc": datetime.now(timezone.utc).isoformat(),
        "records": records,
        "results": "TBD — requires experiment" if mode == "compile" else "See completed PCAP/ground-truth artifacts",
    }
    output.mkdir(parents=True, exist_ok=True)
    (output / f"batch-{mode}-manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description="Compile or run a VPNGUARD-X benchmark plan")
    parser.add_argument("plan", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
    parser.add_argument("--mode", choices=["compile", "run"], default="compile")
    parser.add_argument("--no-resume", action="store_true")
    parser.add_argument("--fail-fast", action="store_true")
    parser.add_argument("--limit", type=int)
    args = parser.parse_args()
    result = execute_plan(
        args.plan,
        args.output,
        mode=args.mode,
        matrix_path=args.matrix,
        resume=not args.no_resume,
        fail_fast=args.fail_fast,
        limit=args.limit,
    )
    print(json.dumps({key: value for key, value in result.items() if key != "records"}, indent=2, sort_keys=True))
    return 1 if result["failed_count"] or result["artifact_validation_problems"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
