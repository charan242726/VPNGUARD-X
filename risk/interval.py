"""Risk bounds across a set of supported candidate configurations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from policy.types import PolicyEvaluation


@dataclass(frozen=True)
class RiskInterval:
    status: str
    evidence_status: str
    minimum: float | None
    maximum: float | None
    candidate_risk: dict[str, float]
    expected_model_dependent: float | None
    interpretation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "evidence_status": self.evidence_status,
            "minimum": self.minimum,
            "maximum": self.maximum,
            "candidate_risk": self.candidate_risk,
            "expected_model_dependent": self.expected_model_dependent,
            "interpretation": self.interpretation,
        }


def compute_risk_interval(
    evaluation: PolicyEvaluation,
    posterior: Mapping[str, float] | None = None,
) -> RiskInterval:
    if not evaluation.candidate_ids:
        return RiskInterval(
            "NOT_EVALUABLE",
            "UNKNOWN/UNOBSERVABLE",
            None,
            None,
            {},
            None,
            "No supported candidate set exists; no risk value is asserted.",
        )
    evaluable = [finding for finding in evaluation.findings if not finding.unevaluable_candidate_ids]
    denominator = sum(finding.rule.weight for finding in evaluable)
    if denominator <= 0:
        return RiskInterval(
            "NOT_EVALUABLE",
            "UNKNOWN/UNOBSERVABLE",
            None,
            None,
            {},
            None,
            "No positive-weight evaluable rules exist.",
        )
    risk: dict[str, float] = {}
    for candidate_id in evaluation.candidate_ids:
        numerator = sum(
            finding.rule.weight
            for finding in evaluable
            if candidate_id in finding.violating_candidate_ids
        )
        risk[candidate_id] = numerator / denominator
    expectation = None
    if posterior:
        mass = sum(float(posterior.get(candidate_id, 0.0)) for candidate_id in risk)
        if mass > 0:
            expectation = sum(risk[candidate_id] * float(posterior.get(candidate_id, 0.0)) for candidate_id in risk) / mass
    return RiskInterval(
        "BOUNDED",
        evaluation.basis_status.value,
        min(risk.values()),
        max(risk.values()),
        risk,
        expectation,
        "Normalized policy-loss bounds over the candidate set; not a probability of compromise.",
    )
