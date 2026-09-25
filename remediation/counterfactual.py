"""Exhaustive, reproducible remediation search over a tested catalogue."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from cgii.catalog import CandidateCatalogue
from cgii.engine import INFERENCE_FIELDS
from cgii.types import CandidateConfiguration
from common.evidence import EvidenceStatus
from policy.engine import PolicyEngine


DEFAULT_EDIT_COSTS = {
    "ike_version": 5.0,
    "outer_ip_version": 3.0,
    "encapsulation": 2.0,
    "ike_encryption": 2.0,
    "ike_integrity": 1.0,
    "ike_prf": 1.0,
    "ike_ke_group": 2.0,
    "child_mode": 4.0,
    "child_encryption": 2.0,
    "child_integrity": 1.0,
    "child_pfs_group": 2.0,
    "esn": 1.0,
    "anti_replay": 1.0,
    "child_lifetime_seconds": 1.0,
    "authentication_family": 3.0,
}


@dataclass(frozen=True)
class CandidateRemediation:
    source_candidate_id: str
    minimum_cost: float
    target_candidate_ids: tuple[str, ...]
    alternatives: tuple[dict[str, dict[str, Any]], ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_candidate_id": self.source_candidate_id,
            "minimum_cost": self.minimum_cost,
            "target_candidate_ids": list(self.target_candidate_ids),
            "alternatives": list(self.alternatives),
        }


@dataclass(frozen=True)
class CounterfactualResult:
    status: str
    evidence_status: str
    profile_id: str
    minimum_cost: float | None
    maximum_cost: float | None
    robust_common_changes: dict[str, dict[str, Any]]
    candidate_contingent: tuple[CandidateRemediation, ...]
    compliant_catalogue_candidate_ids: tuple[str, ...]
    caveat: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "evidence_status": self.evidence_status,
            "profile_id": self.profile_id,
            "minimum_cost": self.minimum_cost,
            "maximum_cost": self.maximum_cost,
            "robust_common_changes": self.robust_common_changes,
            "candidate_contingent": [item.to_dict() for item in self.candidate_contingent],
            "compliant_catalogue_candidate_ids": list(self.compliant_catalogue_candidate_ids),
            "caveat": self.caveat,
        }


def _changes(source: CandidateConfiguration, target: CandidateConfiguration) -> dict[str, dict[str, Any]]:
    return {
        field_name: {"from": source.field_value(field_name), "to": target.field_value(field_name)}
        for field_name in INFERENCE_FIELDS
        if source.field_value(field_name) != target.field_value(field_name)
    }


def _distance(
    source: CandidateConfiguration,
    target: CandidateConfiguration,
    costs: Mapping[str, float],
) -> float:
    return sum(costs.get(field_name, 1.0) for field_name in INFERENCE_FIELDS if source.field_value(field_name) != target.field_value(field_name))


def find_minimum_changes(
    candidates: Iterable[CandidateConfiguration],
    catalogue: CandidateCatalogue,
    policy: PolicyEngine,
    profile_id: str,
    *,
    edit_costs: Mapping[str, float] | None = None,
    basis_status: EvidenceStatus = EvidenceStatus.DETERMINISTICALLY_DERIVED,
) -> CounterfactualResult:
    sources = list(candidates)
    if not sources:
        return CounterfactualResult(
            "NOT_EVALUABLE",
            EvidenceStatus.UNKNOWN_UNOBSERVABLE.value,
            profile_id,
            None,
            None,
            {},
            (),
            (),
            "No supported source candidate exists.",
        )
    costs = dict(DEFAULT_EDIT_COSTS)
    if edit_costs:
        for field_name, cost in edit_costs.items():
            if cost < 0:
                raise ValueError("edit costs must be non-negative")
            costs[field_name] = float(cost)
    compliant = [candidate for candidate in catalogue.candidates if policy.is_compliant(candidate, profile_id)]
    if not compliant:
        return CounterfactualResult(
            "NO_COMPLIANT_CATALOGUE_TARGET",
            basis_status.value,
            profile_id,
            None,
            None,
            {},
            (),
            (),
            "Expand and validate the deployment catalogue; no compliant target was silently invented.",
        )

    per_source: list[CandidateRemediation] = []
    all_alternatives: list[dict[str, dict[str, Any]]] = []
    for source in sources:
        distances = [(target, _distance(source, target, costs)) for target in compliant]
        minimum = min(distance for _, distance in distances)
        targets = sorted(
            [target for target, distance in distances if abs(distance - minimum) <= 1e-12],
            key=lambda candidate: candidate.candidate_id,
        )
        alternatives = tuple(_changes(source, target) for target in targets)
        all_alternatives.extend(alternatives)
        per_source.append(
            CandidateRemediation(
                source.candidate_id,
                minimum,
                tuple(target.candidate_id for target in targets),
                alternatives,
            )
        )

    robust: dict[str, dict[str, Any]] = {}
    if all_alternatives:
        common_fields = set(all_alternatives[0])
        for alternative in all_alternatives[1:]:
            common_fields &= set(alternative)
        for field_name in sorted(common_fields):
            targets = {repr(alternative[field_name]["to"]) for alternative in all_alternatives}
            if len(targets) == 1:
                robust[field_name] = {
                    "to": all_alternatives[0][field_name]["to"],
                    "reason": "Present with the same target value in every minimum-cost alternative",
                }

    minimum_costs = [item.minimum_cost for item in per_source]
    return CounterfactualResult(
        "OK",
        basis_status.value,
        profile_id,
        min(minimum_costs),
        max(minimum_costs),
        robust,
        tuple(per_source),
        tuple(candidate.candidate_id for candidate in compliant),
        "Counterfactuals are catalogue-bounded configuration suggestions; validate interoperability and operational impact before deployment.",
    )
