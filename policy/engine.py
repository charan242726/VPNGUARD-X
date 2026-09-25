"""Set-valued policy evaluation over CGII candidates."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

from common.provenance import sha256_file
from common.evidence import EvidenceStatus
from cgii.types import CandidateConfiguration

from .types import FindingStatus, PolicyEvaluation, PolicyRule, RuleFinding


VALID_OPERATORS = {"equals", "not_equals", "in", "not_in", "greater_than", "less_than", "is_none"}


def _load_yaml(path: Path) -> dict[str, Any]:
    try:
        import yaml  # type: ignore
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("PyYAML is required for policy configuration") from exc
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("policy configuration root must be a mapping")
    return value


def _violates(actual: Any, operator: str, expected: Any) -> bool:
    if operator == "equals":
        return actual == expected
    if operator == "not_equals":
        return actual != expected
    if operator == "in":
        return actual in expected
    if operator == "not_in":
        return actual not in expected
    if operator == "greater_than":
        return actual > expected
    if operator == "less_than":
        return actual < expected
    if operator == "is_none":
        return actual is None or str(actual).upper() in {"NONE", "DISABLED", "0"}
    raise ValueError(f"unsupported operator: {operator}")


class PolicyEngine:
    def __init__(self, rules: Iterable[PolicyRule], *, policy_hash: str):
        self.rules = tuple(rules)
        self.policy_hash = policy_hash
        ids = [rule.rule_id for rule in self.rules]
        if len(ids) != len(set(ids)):
            raise ValueError("policy rule IDs must be unique")

    @classmethod
    def from_yaml(cls, path: str | Path) -> "PolicyEngine":
        selected = Path(path).resolve()
        data = _load_yaml(selected)
        raw_rules = data.get("rules")
        if not isinstance(raw_rules, list):
            raise ValueError("rules must be a list")
        rules: list[PolicyRule] = []
        for raw in raw_rules:
            if not isinstance(raw, dict):
                raise ValueError("each policy rule must be a mapping")
            normalized = dict(raw)
            normalized["profiles"] = tuple(normalized["profiles"])
            if normalized.get("operator") not in VALID_OPERATORS:
                raise ValueError(f"invalid operator in {normalized.get('rule_id')}")
            rules.append(PolicyRule(**normalized))
        return cls(rules, policy_hash=sha256_file(selected))

    def rules_for_profile(self, profile_id: str) -> tuple[PolicyRule, ...]:
        selected = tuple(rule for rule in self.rules if rule.enabled and profile_id in rule.profiles)
        if not selected:
            raise KeyError(f"unknown or empty policy profile: {profile_id}")
        return selected

    @staticmethod
    def candidate_violates(candidate: CandidateConfiguration, rule: PolicyRule) -> bool | None:
        try:
            actual = candidate.field_value(rule.field)
        except KeyError:
            return None
        if actual is None and rule.operator != "is_none":
            return None
        return _violates(actual, rule.operator, rule.value)

    def evaluate(
        self,
        candidates: Iterable[CandidateConfiguration],
        profile_id: str,
        *,
        basis_status: EvidenceStatus = EvidenceStatus.DETERMINISTICALLY_DERIVED,
    ) -> PolicyEvaluation:
        selected_candidates = list(candidates)
        rules = self.rules_for_profile(profile_id)
        if not selected_candidates:
            findings = [
                RuleFinding(rule, FindingStatus.NOT_EVALUABLE, (), (), ())
                for rule in rules
            ]
            return PolicyEvaluation(profile_id, self.policy_hash, [], findings, EvidenceStatus.UNKNOWN_UNOBSERVABLE, ["EMPTY_CANDIDATE_SET"])

        findings: list[RuleFinding] = []
        for rule in rules:
            violating: list[str] = []
            nonviolating: list[str] = []
            unevaluable: list[str] = []
            for candidate in selected_candidates:
                result = self.candidate_violates(candidate, rule)
                target = unevaluable if result is None else violating if result else nonviolating
                target.append(candidate.candidate_id)
            if unevaluable:
                status = FindingStatus.NOT_EVALUABLE
            elif violating and not nonviolating:
                status = FindingStatus.CERTAIN_VIOLATION
            elif violating:
                status = FindingStatus.POSSIBLE_VIOLATION
            else:
                status = FindingStatus.NOT_SUPPORTED
            findings.append(
                RuleFinding(
                    rule,
                    status,
                    tuple(violating),
                    tuple(nonviolating),
                    tuple(unevaluable),
                )
            )
        return PolicyEvaluation(
            profile_id,
            self.policy_hash,
            [candidate.candidate_id for candidate in selected_candidates],
            findings,
            basis_status,
        )

    def is_compliant(self, candidate: CandidateConfiguration, profile_id: str) -> bool:
        return all(self.candidate_violates(candidate, rule) is False for rule in self.rules_for_profile(profile_id))
