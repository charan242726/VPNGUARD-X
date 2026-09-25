#!/usr/bin/env python3
"""Audit stored VICI/XFRM telemetry without altering executed ground truth."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from observability import cooperative_evidence_from_swanctl, cooperative_evidence_from_xfrm


VALIDATED_PROPERTIES = (
    "ike.version",
    "ike.selected_encryption",
    "ike.selected_integrity",
    "ike.selected_prf",
    "ike.initial_ke_group",
    "child.mode",
    "child.encryption",
    "child.integrity",
    "child.pfs_group",
    "child.esn",
    "child.anti_replay_enabled",
)


def _values(ledger: Any) -> dict[str, list[Any]]:
    result: dict[str, list[Any]] = defaultdict(list)
    for record in ledger.records:
        if record.value is not None and record.value not in result[record.property_name]:
            result[record.property_name].append(record.value)
    return dict(result)


def _merge(destination: dict[str, list[Any]], source: dict[str, list[Any]]) -> None:
    for property_name, values in source.items():
        for value in values:
            if value not in destination[property_name]:
                destination[property_name].append(value)


def audit_telemetry(project: str | Path) -> dict[str, Any]:
    selected = Path(project).resolve()
    range_root = selected / "artifacts/range"
    truth_paths = sorted(range_root.glob("*/seed-*/ground_truth.json"))
    status_counts: dict[str, Counter[str]] = defaultdict(Counter)
    run_results: list[dict[str, Any]] = []
    missing_files: Counter[str] = Counter()
    parse_errors: list[dict[str, str]] = []

    for truth_path in truth_paths:
        truth = json.loads(truth_path.read_text(encoding="utf-8"))
        if truth.get("capture", {}).get("capture_variant") != "FULL":
            continue
        run_directory = truth_path.parent
        observed: dict[str, list[Any]] = defaultdict(list)
        source_files = {
            "left_sas": run_directory / "left_sas.raw",
            "right_sas": run_directory / "right_sas.raw",
            "left_xfrm": run_directory / "left_xfrm.redacted.txt",
            "right_xfrm": run_directory / "right_xfrm.redacted.txt",
        }
        for source_name, source_path in source_files.items():
            if not source_path.is_file():
                missing_files[source_name] += 1
                continue
            try:
                text = source_path.read_text(encoding="utf-8", errors="replace")
                ledger = (
                    cooperative_evidence_from_xfrm(text)
                    if "xfrm" in source_name
                    else cooperative_evidence_from_swanctl(text)
                )
                _merge(observed, _values(ledger))
            except (OSError, ValueError, TypeError) as exc:
                parse_errors.append(
                    {
                        "scenario_id": str(truth.get("scenario_id")),
                        "source": source_name,
                        "error": f"{type(exc).__name__}: {exc}",
                    }
                )

        configured = truth.get("configured_properties", {})
        property_results: dict[str, dict[str, Any]] = {}
        for property_name in VALIDATED_PROPERTIES:
            expected = configured.get(property_name)
            values = observed.get(property_name, [])
            if expected is None:
                status = "NOT_CONFIGURED"
            elif not values:
                status = "UNVALIDATED_NO_ENDPOINT_VALUE"
            elif expected in values:
                status = "VALIDATED"
            else:
                status = "CONFLICT"
            status_counts[property_name][status] += 1
            property_results[property_name] = {
                "status": status,
                "configured": expected,
                "observed_values": values,
            }

        configured_lifetime = configured.get("sa.configured_lifetime")
        remaining_values = [
            int(value) for value in observed.get("sa.remaining_lifetime_seconds", [])
            if isinstance(value, int)
        ]
        if configured_lifetime is None:
            lifetime_status = "NOT_CONFIGURED"
        elif not remaining_values:
            lifetime_status = "UNVALIDATED_NO_ENDPOINT_VALUE"
        elif all(0 <= value <= int(configured_lifetime) for value in remaining_values):
            lifetime_status = "CONSISTENT_REMAINING_TIME_NOT_CONFIGURED_LIFETIME"
        else:
            lifetime_status = "CONFLICT"
        status_counts["sa.configured_lifetime"][lifetime_status] += 1
        property_results["sa.configured_lifetime"] = {
            "status": lifetime_status,
            "configured": configured_lifetime,
            "observed_remaining_seconds": remaining_values,
        }

        run_results.append(
            {
                "scenario_id": truth.get("scenario_id"),
                "seed": truth.get("seed"),
                "stack": truth.get("stack"),
                "run_path": run_directory.relative_to(selected).as_posix(),
                "properties": property_results,
            }
        )

    summaries = {
        property_name: dict(sorted(counts.items()))
        for property_name, counts in sorted(status_counts.items())
    }
    blockers = []
    for property_name in ("child.pfs_group", "child.anti_replay_enabled"):
        summary = summaries.get(property_name, {})
        if summary.get("VALIDATED", 0) != len(run_results):
            blockers.append(
                f"{property_name} is not endpoint-validated for every FULL run; retain UNKNOWN/UNVALIDATED where absent"
            )
    return {
        "schema_version": "0.3.0",
        "created_at_utc": datetime.now(UTC).isoformat(),
        "mode": "READ_ONLY_REVALIDATION_OF_STORED_AUTHORIZED_TELEMETRY",
        "full_run_count": len(run_results),
        "missing_source_file_counts": dict(sorted(missing_files.items())),
        "parse_error_count": len(parse_errors),
        "parse_errors": parse_errors,
        "property_status_counts": summaries,
        "publication_claim_blockers": blockers,
        "terminology": {
            "sa.remaining_lifetime_seconds": "remaining active-SA time reported by VICI",
            "sa.configured_lifetime": "configured lifetime; must not be inferred from remaining time",
        },
        "runs": run_results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", type=Path, default=ROOT)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts/audits/cooperative-telemetry-validation.json"),
    )
    args = parser.parse_args()
    output = args.output if args.output.is_absolute() else args.project / args.output
    result = audit_telemetry(args.project)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "output": str(output.resolve()),
                "full_run_count": result["full_run_count"],
                "parse_error_count": result["parse_error_count"],
                "publication_claim_blockers": result["publication_claim_blockers"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
