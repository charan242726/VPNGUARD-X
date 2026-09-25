#!/usr/bin/env python3
"""Export actual aggregate metrics to manuscript-ready CSV and Markdown tables."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path


def export_results(source: str | Path, csv_path: str | Path, markdown_path: str | Path) -> dict:
    data = json.loads(Path(source).read_text(encoding="utf-8"))
    aggregate = data.get("aggregate")
    if not aggregate:
        raise ValueError("aggregate-results.json contains no executed metrics")
    rows = []
    for group in aggregate:
        for metric, values in group.get("metrics", {}).items():
            rows.append(
                {
                    "split_id": group["split_id"],
                    "method": group["method"],
                    "seed_count": group["seed_count"],
                    "metric": metric,
                    "mean": values["mean"],
                    "sample_standard_deviation": values["sample_standard_deviation"],
                }
            )
    if not rows:
        raise ValueError("aggregate-results.json contains no numeric metrics")
    selected_csv = Path(csv_path).resolve()
    selected_md = Path(markdown_path).resolve()
    selected_csv.parent.mkdir(parents=True, exist_ok=True)
    selected_md.parent.mkdir(parents=True, exist_ok=True)
    with selected_csv.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    lines = [
        "# VPNGUARD-X executed results",
        "",
        "These values were exported from versioned prediction records; they are not placeholders.",
        "",
        "| Split | Method | Seeds | Metric | Mean | Sample SD |",
        "|---|---|---:|---|---:|---:|",
    ]
    for row in rows:
        sd = "NA" if row["sample_standard_deviation"] is None else f"{row['sample_standard_deviation']:.6f}"
        lines.append(
            f"| {row['split_id']} | {row['method']} | {row['seed_count']} | {row['metric']} | {row['mean']:.6f} | {sd} |"
        )
    selected_md.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return {"row_count": len(rows), "csv": str(selected_csv), "markdown": str(selected_md)}


def main() -> int:
    parser = argparse.ArgumentParser(description="Export executed VPNGUARD-X metrics")
    parser.add_argument("aggregate_results", type=Path)
    parser.add_argument("--csv", type=Path, required=True)
    parser.add_argument("--markdown", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(export_results(args.aggregate_results, args.csv, args.markdown), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
