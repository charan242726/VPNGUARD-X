"""Hashing and run-manifest helpers."""

from __future__ import annotations

import hashlib
import json
import platform
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def sha256_file(path: str | Path, chunk_size: int = 1 << 20) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def stable_hash(data: Any) -> str:
    blob = json.dumps(data, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(blob).hexdigest()


def base_manifest(run_id: str, seed: int, inputs: dict[str, str]) -> dict[str, Any]:
    return {
        "schema_version": "0.1.0",
        "run_id": run_id,
        "created_utc": datetime.now(UTC).isoformat(),
        "seed": seed,
        "inputs": inputs,
        "python": sys.version,
        "platform": platform.platform(),
        "empirical_results_status": "TBD — requires experiment",
    }

