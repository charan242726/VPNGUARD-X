"""Policy data contracts."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

from common.evidence import EvidenceStatus


class FindingStatus(str, Enum):
    CERTAIN_VIOLATION = "CERTAIN_VIOLATION"
    POSSIBLE_VIOLATION = "POSSIBLE_VIOLATION"
    NOT_SUPPORTED = "NOT_SUPPORTED"
    NOT_EVALUABLE = "NOT_EVALUABLE"


@dataclass(frozen=True)
class PolicyRule:
    rule_id: str
    profiles: tuple[str, ...]
    enabled: bool
    field: str
    operator: str
    value: Any
    severity: str
    weight: float
    source_id: str
    source_section: str
    normative_level: str
    rationale: str
    remediation: str
    observability_requirement: str
    introduced: str
    last_reviewed: str

    def __post_init__(self) -> None:
        if not self.rule_id or not self.profiles:
            raise ValueError("rule_id and profiles are required")
        if self.weight < 0:
            raise ValueError("rule weight must be non-negative")
        required_text = (self.source_id, self.source_section, self.rationale, self.remediation)
        if not all(required_text):
            raise ValueError(f"rule {self.rule_id} lacks provenance or rationale")


@dataclass(frozen=True)
class RuleFinding:
    rule: PolicyRule
    status: FindingStatus
    violating_candidate_ids: tuple[str, ...]
    nonviolating_candidate_ids: tuple[str, ...]
    unevaluable_candidate_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule.rule_id,
            "status": self.status.value,
            "severity": self.rule.severity,
            "weight": self.rule.weight,
            "source": {
                "source_id": self.rule.source_id,
                "section": self.rule.source_section,
                "normative_level": self.rule.normative_level,
            },
            "rationale": self.rule.rationale,
            "remediation": self.rule.remediation,
            "observability_requirement": self.rule.observability_requirement,
            "violating_candidate_ids": list(self.violating_candidate_ids),
            "nonviolating_candidate_ids": list(self.nonviolating_candidate_ids),
            "unevaluable_candidate_ids": list(self.unevaluable_candidate_ids),
        }


@dataclass
class PolicyEvaluation:
    profile_id: str
    policy_hash: str
    candidate_ids: list[str]
    findings: list[RuleFinding]
    basis_status: EvidenceStatus = EvidenceStatus.DETERMINISTICALLY_DERIVED
    flags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile_id": self.profile_id,
            "policy_hash": self.policy_hash,
            "candidate_ids": self.candidate_ids,
            "basis_status": self.basis_status.value,
            "findings": [dict(finding.to_dict(), basis_status=self.basis_status.value) for finding in self.findings],
            "summary": {
                status.value: sum(finding.status is status for finding in self.findings)
                for status in FindingStatus
            },
            "flags": self.flags,
        }
