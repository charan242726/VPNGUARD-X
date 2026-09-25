"""Typed CGII inputs and outputs."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from math import isfinite, log
from typing import Any, Mapping

from common.evidence import EvidenceStatus


@dataclass(frozen=True)
class CandidateConfiguration:
    candidate_id: str
    ike_version: str
    outer_ip_version: int
    encapsulation: str
    ike_encryption: str
    ike_integrity: str
    ike_prf: str
    ike_ke_group: int
    child_mode: str
    child_encryption: str
    child_integrity: str
    child_pfs_group: int | str
    esn: bool
    anti_replay: bool
    child_lifetime_seconds: int
    authentication_family: str
    tags: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.candidate_id:
            raise ValueError("candidate_id is required")
        if self.ike_version not in {"IKEV1", "IKEV2"}:
            raise ValueError(f"unsupported IKE version: {self.ike_version}")
        if self.outer_ip_version not in {4, 6}:
            raise ValueError("outer_ip_version must be 4 or 6")
        if self.encapsulation not in {"NATIVE_ESP", "UDP_ENCAPSULATED_ESP"}:
            raise ValueError(f"unsupported encapsulation: {self.encapsulation}")
        if self.child_mode not in {"TUNNEL", "TRANSPORT"}:
            raise ValueError(f"unsupported CHILD-SA mode: {self.child_mode}")
        if self.child_lifetime_seconds <= 0:
            raise ValueError("child_lifetime_seconds must be positive")

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["tags"] = list(self.tags)
        return value

    def field_value(self, field_name: str) -> Any:
        if not hasattr(self, field_name):
            raise KeyError(field_name)
        return getattr(self, field_name)


@dataclass(frozen=True)
class PriorDistribution:
    scores: Mapping[str, float]
    model_id: str = "UNIFORM_BASELINE"
    model_hash: str = "NOT_APPLICABLE"
    domain_id: str = "REFERENCE_CATALOGUE"
    is_learned: bool = False

    def validated(self, candidate_ids: set[str]) -> dict[str, float]:
        unknown = set(self.scores) - candidate_ids
        if unknown:
            raise ValueError(f"prior contains unknown candidate IDs: {sorted(unknown)}")
        output: dict[str, float] = {}
        for candidate_id in candidate_ids:
            score = float(self.scores.get(candidate_id, 0.0))
            if score < 0 or not isfinite(score):
                raise ValueError("prior scores must be finite and non-negative")
            output[candidate_id] = score
        return output


@dataclass(frozen=True)
class ConstraintTrace:
    constraint_id: str
    property_name: str
    expected: Any
    field_name: str | None
    rationale: str
    source_locator: str | None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CGIIResult:
    status: str
    inference_status: EvidenceStatus
    catalogue_id: str
    catalogue_hash: str
    total_candidates: int
    feasible_candidate_ids: list[str]
    eliminated: dict[str, list[str]]
    activated_constraints: list[ConstraintTrace]
    posterior: dict[str, float]
    prediction_set: list[str]
    prediction_set_method: str
    prediction_set_mass: float
    alpha: float
    entropy_nats: float
    max_probability: float
    unresolved_fields: list[str]
    evidence_completeness: float
    flags: list[str] = field(default_factory=list)
    conflicts: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    prior_model_id: str = "UNIFORM_BASELINE"
    prior_model_hash: str = "NOT_APPLICABLE"
    prior_domain_id: str = "REFERENCE_CATALOGUE"
    calibrator_id: str | None = None
    calibrator_hash: str | None = None

    @property
    def feasible_count(self) -> int:
        return len(self.feasible_candidate_ids)

    @staticmethod
    def distribution_entropy(distribution: Mapping[str, float]) -> float:
        return -sum(p * log(p) for p in distribution.values() if p > 0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "inference_status": self.inference_status.value,
            "catalogue_id": self.catalogue_id,
            "catalogue_hash": self.catalogue_hash,
            "total_candidates": self.total_candidates,
            "feasible_candidate_count": self.feasible_count,
            "feasible_candidate_ids": self.feasible_candidate_ids,
            "eliminated": self.eliminated,
            "activated_constraints": [trace.to_dict() for trace in self.activated_constraints],
            "posterior": self.posterior,
            "prediction_set": self.prediction_set,
            "prediction_set_method": self.prediction_set_method,
            "prediction_set_mass": self.prediction_set_mass,
            "alpha": self.alpha,
            "entropy_nats": self.entropy_nats,
            "max_probability": self.max_probability,
            "unresolved_fields": self.unresolved_fields,
            "evidence_completeness": self.evidence_completeness,
            "flags": self.flags,
            "conflicts": self.conflicts,
            "prior": {
                "model_id": self.prior_model_id,
                "model_hash": self.prior_model_hash,
                "domain_id": self.prior_domain_id,
            },
            "calibration": {
                "calibrator_id": self.calibrator_id,
                "calibrator_hash": self.calibrator_hash,
            },
        }
