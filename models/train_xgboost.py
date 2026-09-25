#!/usr/bin/env python3
"""Train the XGBoost application or candidate baseline from a split manifest."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from common.provenance import sha256_file, stable_hash
from features import FLOW_FEATURE_NAMES
from models.xgboost_baseline import XGBoostBaseline


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("dataset", type=Path)
    parser.add_argument("split", type=Path)
    parser.add_argument("--task", choices=["application", "configuration"], required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=26160)
    args = parser.parse_args()
    rows = {row["artifact_id"]: row for row in (json.loads(line) for line in args.dataset.read_text(encoding="utf-8").splitlines() if line.strip())}
    split = json.loads(args.split.read_text(encoding="utf-8"))
    training = [rows[artifact_id] for artifact_id in split["train_ids"]]
    label_key = "application_class" if args.task == "application" else "configuration_id"
    training = [row for row in training if row.get(label_key)]
    if not training:
        raise ValueError("split has no usable training rows")
    classes = tuple(sorted({row[label_key] for row in training}))
    model = XGBoostBaseline(classes, seed=args.seed).fit(
        [row["flow_features"] for row in training],
        [row[label_key] for row in training],
    )
    training_manifest_hash = stable_hash({
        "dataset_sha256": sha256_file(args.dataset),
        "split_sha256": sha256_file(args.split),
        "task": args.task,
        "seed": args.seed,
    })
    model.save(args.output, feature_names=FLOW_FEATURE_NAMES, training_manifest_hash=training_manifest_hash)
    print(json.dumps({"model_id": model.model_id, "model_hash": model.model_hash, "classes": classes}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
