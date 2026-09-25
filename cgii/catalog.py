"""Versioned candidate catalogue loader."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from common.provenance import sha256_file

from .types import CandidateConfiguration


@dataclass(frozen=True)
class CandidateCatalogue:
    catalogue_id: str
    catalogue_hash: str
    source_path: str
    candidates: tuple[CandidateConfiguration, ...]

    def __post_init__(self) -> None:
        ids = [candidate.candidate_id for candidate in self.candidates]
        if not ids:
            raise ValueError("candidate catalogue cannot be empty")
        if len(ids) != len(set(ids)):
            raise ValueError("candidate IDs must be unique")

    @property
    def by_id(self) -> dict[str, CandidateConfiguration]:
        return {candidate.candidate_id: candidate for candidate in self.candidates}


def _load_structured(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        return json.loads(text)
    try:
        import yaml  # type: ignore
    except ImportError as exc:  # pragma: no cover - dependency message
        raise RuntimeError("PyYAML is required for YAML candidate catalogues") from exc
    value = yaml.safe_load(text)
    if not isinstance(value, dict):
        raise ValueError("catalogue root must be a mapping")
    return value


def load_catalogue(path: str | Path) -> CandidateCatalogue:
    selected = Path(path).resolve()
    data = _load_structured(selected)
    catalogue_id = str(data.get("catalogue_id", ""))
    if not catalogue_id:
        raise ValueError("catalogue_id is required")
    records = data.get("candidates")
    if not isinstance(records, list):
        raise ValueError("candidates must be a list")
    candidates: list[CandidateConfiguration] = []
    for raw in records:
        if not isinstance(raw, dict):
            raise ValueError("each candidate must be a mapping")
        normalized = dict(raw)
        normalized["tags"] = tuple(normalized.get("tags", ()))
        if normalized.get("encapsulation") == "NAT_T":
            normalized["encapsulation"] = "UDP_ENCAPSULATED_ESP"
        candidates.append(CandidateConfiguration(**normalized))
    return CandidateCatalogue(
        catalogue_id=catalogue_id,
        catalogue_hash=sha256_file(selected),
        source_path=str(selected),
        candidates=tuple(candidates),
    )
