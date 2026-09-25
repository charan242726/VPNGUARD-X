"""Reference implementation of the CGII projection algorithm."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol

from common.evidence import EvidenceLedger, EvidenceStatus, evidence_completeness

from .catalog import CandidateCatalogue
from .constraints import compile_constraints
from .types import CGIIResult, CandidateConfiguration, PriorDistribution


class PredictionSetCalibrator(Protocol):
    calibrator_id: str
    calibrator_hash: str

    def prediction_set(self, posterior: Mapping[str, float], alpha: float) -> list[str]: ...


CORE_PROPERTIES = (
    "ike.version",
    "outer.ip_version",
    "encapsulation",
    "ike.selected_encryption",
    "ike.selected_integrity",
    "ike.selected_prf",
    "ike.initial_ke_group",
    "child.mode",
    "child.encryption",
    "child.integrity",
    "child.pfs_group",
    "child.esn",
    "child.anti_replay_enabled",
    "sa.configured_lifetime",
    "ike.authentication_family",
)

INFERENCE_FIELDS = (
    "ike_version",
    "outer_ip_version",
    "encapsulation",
    "ike_encryption",
    "ike_integrity",
    "ike_prf",
    "ike_ke_group",
    "child_mode",
    "child_encryption",
    "child_integrity",
    "child_pfs_group",
    "esn",
    "anti_replay",
    "child_lifetime_seconds",
    "authentication_family",
)


def _heuristic_mass_set(posterior: Mapping[str, float], alpha: float) -> list[str]:
    target = 1.0 - alpha
    selected: list[str] = []
    cumulative = 0.0
    for candidate_id, probability in sorted(posterior.items(), key=lambda item: (-item[1], item[0])):
        selected.append(candidate_id)
        cumulative += probability
        if cumulative + 1e-15 >= target:
            break
    return selected


def _unresolved_fields(candidates: list[CandidateConfiguration]) -> list[str]:
    if not candidates:
        return list(INFERENCE_FIELDS)
    return [
        field_name
        for field_name in INFERENCE_FIELDS
        if len({repr(candidate.field_value(field_name)) for candidate in candidates}) > 1
    ]


class CGIIEngine:
    def __init__(self, catalogue: CandidateCatalogue):
        self.catalogue = catalogue

    def infer(
        self,
        evidence: EvidenceLedger,
        prior: PriorDistribution | None = None,
        *,
        alpha: float = 0.1,
        calibrator: PredictionSetCalibrator | None = None,
    ) -> CGIIResult:
        if not 0.0 < alpha < 1.0:
            raise ValueError("alpha must be in (0, 1)")

        conflicts = evidence.conflicts()
        if conflicts:
            return self._empty_result(
                evidence,
                status="EVIDENCE_CONFLICT",
                alpha=alpha,
                flags=["CONTRADICTORY_HARD_EVIDENCE"],
                conflicts={name: [record.to_dict() for record in records] for name, records in conflicts.items()},
            )

        constraints = compile_constraints(evidence)
        feasible: list[CandidateConfiguration] = []
        eliminated: dict[str, list[str]] = {}
        for candidate in self.catalogue.candidates:
            failed = [constraint.trace.constraint_id for constraint in constraints if not constraint.accepts(candidate)]
            if failed:
                eliminated[candidate.candidate_id] = failed
            else:
                feasible.append(candidate)

        if not feasible:
            return self._empty_result(
                evidence,
                status="EVIDENCE_CONFLICT",
                alpha=alpha,
                flags=["NO_CATALOGUE_CANDIDATE_SATISFIES_EVIDENCE"],
                eliminated=eliminated,
                traces=[constraint.trace for constraint in constraints],
            )

        candidate_ids = {candidate.candidate_id for candidate in self.catalogue.candidates}
        supplied_prior = prior or PriorDistribution(
            scores={candidate_id: 1.0 for candidate_id in candidate_ids},
        )
        raw = supplied_prior.validated(candidate_ids)
        feasible_mass = sum(raw[candidate.candidate_id] for candidate in feasible)
        flags: list[str] = []
        if feasible_mass <= 0.0:
            posterior = {candidate.candidate_id: 1.0 / len(feasible) for candidate in feasible}
            flags.append("ZERO_MASS_FALLBACK")
        else:
            posterior = {
                candidate.candidate_id: raw[candidate.candidate_id] / feasible_mass
                for candidate in feasible
            }

        if calibrator is None and not supplied_prior.is_learned:
            prediction_set = sorted(posterior)
            method = "EVIDENCE_FEASIBLE_SET"
            flags.append("NO_STATISTICAL_COVERAGE_GUARANTEE")
            calibrator_id = None
            calibrator_hash = None
        elif calibrator is None:
            prediction_set = _heuristic_mass_set(posterior, alpha)
            method = "HEURISTIC_MASS_SET"
            flags.append("NO_COVERAGE_GUARANTEE")
            calibrator_id = None
            calibrator_hash = None
        else:
            prediction_set = calibrator.prediction_set(posterior, alpha)
            prediction_set = [candidate_id for candidate_id in prediction_set if candidate_id in posterior]
            method = "SPLIT_CONFORMAL"
            calibrator_id = calibrator.calibrator_id
            calibrator_hash = calibrator.calibrator_hash
            if not prediction_set:
                flags.append("EMPTY_CONFORMAL_SET_ABSTAIN")

        selected = [self.catalogue.by_id[candidate_id] for candidate_id in prediction_set]
        inference_status = EvidenceStatus.AI_INFERRED if supplied_prior.is_learned else EvidenceStatus.DETERMINISTICALLY_DERIVED
        return CGIIResult(
            status="OK",
            inference_status=inference_status,
            catalogue_id=self.catalogue.catalogue_id,
            catalogue_hash=self.catalogue.catalogue_hash,
            total_candidates=len(self.catalogue.candidates),
            feasible_candidate_ids=[candidate.candidate_id for candidate in feasible],
            eliminated=eliminated,
            activated_constraints=[constraint.trace for constraint in constraints],
            posterior=posterior,
            prediction_set=prediction_set,
            prediction_set_method=method,
            prediction_set_mass=sum(posterior[candidate_id] for candidate_id in prediction_set),
            alpha=alpha,
            entropy_nats=CGIIResult.distribution_entropy(posterior),
            max_probability=max(posterior.values()),
            unresolved_fields=_unresolved_fields(selected),
            evidence_completeness=evidence_completeness(evidence, CORE_PROPERTIES),
            flags=flags,
            prior_model_id=supplied_prior.model_id,
            prior_model_hash=supplied_prior.model_hash,
            prior_domain_id=supplied_prior.domain_id,
            calibrator_id=calibrator_id,
            calibrator_hash=calibrator_hash,
        )

    def _empty_result(
        self,
        evidence: EvidenceLedger,
        *,
        status: str,
        alpha: float,
        flags: list[str],
        conflicts: dict[str, list[dict]] | None = None,
        eliminated: dict[str, list[str]] | None = None,
        traces: list | None = None,
    ) -> CGIIResult:
        return CGIIResult(
            status=status,
            inference_status=EvidenceStatus.UNKNOWN_UNOBSERVABLE,
            catalogue_id=self.catalogue.catalogue_id,
            catalogue_hash=self.catalogue.catalogue_hash,
            total_candidates=len(self.catalogue.candidates),
            feasible_candidate_ids=[],
            eliminated=eliminated or {},
            activated_constraints=traces or [],
            posterior={},
            prediction_set=[],
            prediction_set_method="NOT_AVAILABLE",
            prediction_set_mass=0.0,
            alpha=alpha,
            entropy_nats=0.0,
            max_probability=0.0,
            unresolved_fields=list(INFERENCE_FIELDS),
            evidence_completeness=evidence_completeness(evidence, CORE_PROPERTIES),
            flags=flags,
            conflicts=conflicts or {},
        )
