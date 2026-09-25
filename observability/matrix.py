"""Load and validate the executable observability matrix."""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ObservabilityRule:
    property_id: str
    property: str
    scope: str
    passive_class: str
    passive_status: str
    minimum_evidence: str
    derivation_or_inference: str
    cooperative_source: str
    limitations: str
    authoritative_source: str
    source_section: str


def default_matrix_path() -> Path:
    return Path(__file__).resolve().parents[1] / "data" / "IPsec_Observability_Matrix.csv"


def load_observability_matrix(path: str | Path | None = None) -> dict[str, ObservabilityRule]:
    selected = Path(path) if path else default_matrix_path()
    with selected.open(newline="", encoding="utf-8") as handle:
        rows = [ObservabilityRule(**row) for row in csv.DictReader(handle)]
    by_property: dict[str, ObservabilityRule] = {}
    ids: set[str] = set()
    for row in rows:
        if row.property_id in ids:
            raise ValueError(f"duplicate observability property_id: {row.property_id}")
        if row.property in by_property:
            raise ValueError(f"duplicate observability property: {row.property}")
        ids.add(row.property_id)
        by_property[row.property] = row
    return by_property

