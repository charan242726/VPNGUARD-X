"""Evidence types and invariants.

The enum values are the exact user-facing epistemic labels required by the
project.  Code uses UNKNOWN_UNOBSERVABLE as a valid Python identifier while
serializing the value ``UNKNOWN/UNOBSERVABLE``.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Iterable


class EvidenceStatus(str, Enum):
    OBSERVED = "OBSERVED"
    DETERMINISTICALLY_DERIVED = "DETERMINISTICALLY_DERIVED"
    AI_INFERRED = "AI_INFERRED"
    UNKNOWN_UNOBSERVABLE = "UNKNOWN/UNOBSERVABLE"


@dataclass(frozen=True)
class EvidenceRecord:
    property_name: str
    value: Any
    status: EvidenceStatus
    source: str
    rationale: str
    source_locator: str | None = None
    confidence: float | None = None
    model_id: str | None = None
    model_hash: str | None = None
    training_domain_id: str | None = None
    reason_code: str | None = None
    packet_indices: tuple[int, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not self.property_name:
            raise ValueError("property_name is required")
        if not self.source or not self.rationale:
            raise ValueError("every evidence record requires source and rationale")
        if self.confidence is not None and not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be in [0, 1]")
        if self.status is EvidenceStatus.AI_INFERRED:
            if self.confidence is None or not self.model_id or not self.model_hash:
                raise ValueError("AI_INFERRED requires confidence, model_id, and model_hash")
        elif self.confidence is not None:
            raise ValueError("confidence is reserved for AI_INFERRED evidence")
        if self.status is EvidenceStatus.UNKNOWN_UNOBSERVABLE and not self.reason_code:
            raise ValueError("UNKNOWN/UNOBSERVABLE requires a reason_code")

    @property
    def is_hard(self) -> bool:
        return self.status in {
            EvidenceStatus.OBSERVED,
            EvidenceStatus.DETERMINISTICALLY_DERIVED,
        }

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        data["packet_indices"] = list(self.packet_indices)
        return data


@dataclass
class EvidenceLedger:
    records: list[EvidenceRecord] = field(default_factory=list)

    def add(self, record: EvidenceRecord, *, replace: bool = False) -> None:
        existing = [r for r in self.records if r.property_name == record.property_name]
        if not existing:
            self.records.append(record)
            return
        if replace:
            self.records = [r for r in self.records if r.property_name != record.property_name]
            self.records.append(record)
            return
        if any(r.value == record.value and r.status == record.status for r in existing):
            return
        self.records.append(record)

    def extend(self, records: Iterable[EvidenceRecord], *, replace: bool = False) -> None:
        for record in records:
            self.add(record, replace=replace)

    def by_property(self, property_name: str) -> list[EvidenceRecord]:
        return [r for r in self.records if r.property_name == property_name]

    def best(self, property_name: str) -> EvidenceRecord | None:
        priority = {
            EvidenceStatus.OBSERVED: 3,
            EvidenceStatus.DETERMINISTICALLY_DERIVED: 2,
            EvidenceStatus.AI_INFERRED: 1,
            EvidenceStatus.UNKNOWN_UNOBSERVABLE: 0,
        }
        values = self.by_property(property_name)
        return max(values, key=lambda r: priority[r.status], default=None)

    def hard_records(self) -> list[EvidenceRecord]:
        return [r for r in self.records if r.is_hard]

    def conflicts(self) -> dict[str, list[EvidenceRecord]]:
        conflicts: dict[str, list[EvidenceRecord]] = {}
        for name in {r.property_name for r in self.records}:
            hard = [r for r in self.by_property(name) if r.is_hard]
            distinct = {repr(r.value) for r in hard}
            if len(distinct) > 1:
                conflicts[name] = hard
        return conflicts

    def to_list(self) -> list[dict[str, Any]]:
        return [record.to_dict() for record in self.records]


DEFAULT_COMPLETENESS_WEIGHTS = {
    EvidenceStatus.OBSERVED: 1.0,
    EvidenceStatus.DETERMINISTICALLY_DERIVED: 0.95,
    EvidenceStatus.AI_INFERRED: 0.5,
    EvidenceStatus.UNKNOWN_UNOBSERVABLE: 0.0,
}


def evidence_completeness(
    ledger: EvidenceLedger,
    requested_properties: Iterable[str],
    property_weights: dict[str, float] | None = None,
) -> float:
    weights = property_weights or {}
    numerator = 0.0
    denominator = 0.0
    for property_name in requested_properties:
        weight = float(weights.get(property_name, 1.0))
        if weight < 0:
            raise ValueError("property weights must be non-negative")
        denominator += weight
        record = ledger.best(property_name)
        if record is None:
            continue
        contribution = DEFAULT_COMPLETENESS_WEIGHTS[record.status]
        if record.status is EvidenceStatus.AI_INFERRED:
            contribution *= float(record.confidence or 0.0)
        numerator += weight * contribution
    return numerator / denominator if denominator else 0.0
