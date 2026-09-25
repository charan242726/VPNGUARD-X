#!/usr/bin/env python3
"""Create a path-sanitized dataset with a verifiable scientific projection."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any


PATH_KEYS = {"ground_truth_path", "pcap_path"}
REPOSITORY_MARKERS = (
    "artifacts/",
    "data/",
    "configs/",
    "cyber_range/",
    "experiments/",
)


def _portable_path(value: str) -> str:
    normalized = value.replace("\\", "/")
    for marker in REPOSITORY_MARKERS:
        position = normalized.find(marker)
        if position >= 0:
            return normalized[position:]
    if normalized.startswith("/") or re.match(r"^[A-Za-z]:/", normalized):
        return f"<ABSOLUTE_PATH_REDACTED>/{Path(normalized).name}"
    return normalized


def _scientific_projection(row: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in row.items() if key not in PATH_KEYS}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sanitize_dataset(source: str | Path, destination: str | Path) -> dict[str, Any]:
    source_path = Path(source).resolve()
    destination_path = Path(destination).resolve()
    rows = [json.loads(line) for line in source_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not rows:
        raise ValueError("dataset is empty")
    before_projection = hashlib.sha256()
    after_projection = hashlib.sha256()
    modifications = 0
    sanitized_rows = []
    for original in rows:
        before_projection.update(
            (json.dumps(_scientific_projection(original), sort_keys=True, separators=(",", ":")) + "\n").encode()
        )
        sanitized = dict(original)
        for key in PATH_KEYS:
            if isinstance(sanitized.get(key), str):
                portable = _portable_path(sanitized[key])
                modifications += portable != sanitized[key]
                sanitized[key] = portable
        after_projection.update(
            (json.dumps(_scientific_projection(sanitized), sort_keys=True, separators=(",", ":")) + "\n").encode()
        )
        sanitized_rows.append(sanitized)
    if before_projection.hexdigest() != after_projection.hexdigest():
        raise AssertionError("sanitization changed scientific/model fields")
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    destination_path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in sanitized_rows),
        encoding="utf-8",
    )
    return {
        "schema_version": "0.3.0",
        "source_file": source_path.name,
        "source_sha256": _sha256(source_path),
        "sanitized_file": destination_path.name,
        "sanitized_sha256": _sha256(destination_path),
        "row_count": len(rows),
        "modified_path_field_count": modifications,
        "scientific_projection_sha256": before_projection.hexdigest(),
        "scientific_fields_unchanged": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path)
    args = parser.parse_args()
    result = sanitize_dataset(args.source, args.output)
    if args.manifest:
        args.manifest.parent.mkdir(parents=True, exist_ok=True)
        args.manifest.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
