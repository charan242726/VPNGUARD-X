#!/usr/bin/env python3
"""Train the TCN application baseline from a split manifest."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from common.provenance import sha256_file, stable_hash
from models.tcn_baseline import TCNConfig
from models.tcn_classifier import TCNClassifier


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("dataset", type=Path)
    parser.add_argument("split", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=26160)
    parser.add_argument("--epochs", type=int, default=30)
    args = parser.parse_args()
    rows = {row["artifact_id"]: row for row in (json.loads(line) for line in args.dataset.read_text(encoding="utf-8").splitlines() if line.strip())}
    split = json.loads(args.split.read_text(encoding="utf-8"))
    training = [rows[artifact_id] for artifact_id in split["train_ids"]]
    classes = tuple(sorted({row["application_class"] for row in training}))
    config = TCNConfig(class_count=len(classes), seed=args.seed)
    model = TCNClassifier(classes, config, epochs=args.epochs).fit(
        [row["sequence_values"] for row in training],
        [row["sequence_mask"] for row in training],
        [row["application_class"] for row in training],
    )
    manifest_hash = stable_hash({
        "dataset_sha256": sha256_file(args.dataset),
        "split_sha256": sha256_file(args.split),
        "seed": args.seed,
        "epochs": args.epochs,
    })
    model.save(args.output, training_manifest_hash=manifest_hash)
    print(json.dumps({"model_id": model.model_id, "model_hash": model.model_hash, "classes": classes}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
