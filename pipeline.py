"""End-to-end VPNGUARD-X assessment pipeline."""

from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Protocol

from cgii import CGIIEngine, PriorDistribution, load_catalogue
from common.evidence import EvidenceRecord, EvidenceStatus
from common.version import VERSION
from deployment import DeploymentBundle
from features import FLOW_FEATURE_NAMES, extract_capture_features, extract_flow_features, extract_sequence_features
from crypto_agility import assess_multiple_key_exchanges
from models.open_world import OpenWorldGate
from observability import cooperative_evidence_from_json
from parser import analyze_pcap
from policy import PolicyEngine
from policy.threats import build_threat_matrix
from remediation import find_minimum_changes
from risk import compute_risk_interval


REPOSITORY_ROOT = Path(__file__).resolve().parent
LOGGER = logging.getLogger("vpnguardx.pipeline")


class ProbabilityModel(Protocol):
    model_id: str
    model_hash: str
    is_calibrated: bool

    def predict_proba(self, x: list[list[float]]) -> list[dict[str, float]]: ...


@dataclass
class AnalysisBundle:
    mode: str
    run: dict[str, Any]
    capture: dict[str, Any]
    features: dict[str, Any]
    application: dict[str, Any]
    crypto_agility: dict[str, Any]
    cgii: dict[str, Any]
    policy: dict[str, Any]
    risk: dict[str, Any]
    remediation: dict[str, Any]
    threat_matrix: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "0.3.0",
            "mode": self.mode,
            "run": self.run,
            "capture": self.capture,
            "features": self.features,
            "application": self.application,
            "crypto_agility": self.crypto_agility,
            "cgii": self.cgii,
            "policy": self.policy,
            "risk": self.risk,
            "remediation": self.remediation,
            "threat_matrix": self.threat_matrix,
        }


class VPNGuardXPipeline:
    def __init__(
        self,
        *,
        catalogue_path: str | Path | None = None,
        policy_path: str | Path = REPOSITORY_ROOT / "configs/policy_rules.yaml",
        profile_id: str = "nist_800_77r1",
        alpha: float | None = None,
        deployment: DeploymentBundle | None = None,
    ) -> None:
        self.deployment = deployment
        self.catalogue = load_catalogue(catalogue_path or (deployment.catalogue_path if deployment else REPOSITORY_ROOT / "configs/candidate_catalogue.yaml"))
        if deployment and self.catalogue.catalogue_hash != deployment.manifest["catalogue_hash"]:
            raise ValueError("pipeline catalogue differs from deployment")
        self.policy_engine = PolicyEngine.from_yaml(policy_path)
        self.profile_id = profile_id
        self.alpha = alpha if alpha is not None else (deployment.conformal.alpha if deployment else 0.1)
        if deployment and self.alpha != deployment.conformal.alpha:
            raise ValueError("pipeline alpha differs from fitted calibration")
        self.policy_engine.rules_for_profile(profile_id)

    def analyze(
        self,
        pcap_path: str | Path,
        *,
        cooperative_properties: Mapping[str, Any] | None = None,
        cooperative_source: str = "SCENARIO_GROUND_TRUTH",
        capture_metadata: Mapping[str, Any] | None = None,
        candidate_prior: PriorDistribution | None = None,
        calibrator: Any = None,
        application_model: ProbabilityModel | None = None,
        open_world_gate: OpenWorldGate | None = None,
        include_packets: bool = False,
    ) -> AnalysisBundle:
        total_started = time.perf_counter()
        parse_started = time.perf_counter()
        capture = analyze_pcap(pcap_path)
        parse_ms = (time.perf_counter() - parse_started) * 1000
        mode = "COOPERATIVE_VALIDATION" if cooperative_properties is not None else "PASSIVE_BLACK_BOX"
        if cooperative_properties is not None:
            capture.evidence.extend(cooperative_evidence_from_json(dict(cooperative_properties), source=cooperative_source).records)

        feature_started = time.perf_counter()
        feature_vector = extract_capture_features(capture.packets)
        flow_feature_map = extract_flow_features(capture.packets)
        sequence = extract_sequence_features(capture.packets)
        crypto_agility = assess_multiple_key_exchanges(capture.packets, capture.evidence)
        feature_ms = (time.perf_counter() - feature_started) * 1000

        model_started = time.perf_counter()
        engine = CGIIEngine(self.catalogue)
        deterministic = engine.infer(capture.evidence, alpha=self.alpha)
        pairs = {tuple(sorted((p.source_ip, p.destination_ip))) for p in capture.packets if (p.ike or p.esp) and p.source_ip and p.destination_ip}
        scope_reason = None
        if not capture.esp_flows:
            scope_reason = "NO_ESP_TRAFFIC_FOR_CLASSIFICATION"
        elif len(capture.ike_sessions) > 1 or len(pairs) > 1:
            scope_reason = "MULTI_SESSION_CAPTURE_NOT_SUPPORTED_FOR_AGGREGATE_INFERENCE"
        elif len(capture.packets) < 4:
            scope_reason = "INSUFFICIENT_PACKETS"
        configuration_reason = "MODEL_NOT_SUPPLIED"
        if self.deployment:
            if any(x is not None for x in (application_model, candidate_prior, calibrator, open_world_gate)):
                raise ValueError("verified deployment cannot be mixed with model overrides")
            application_model, open_world_gate = self.deployment.application, self.deployment.gate
            if scope_reason:
                configuration_reason = scope_reason
            elif cooperative_properties is not None:
                configuration_reason = "COOPERATIVE_EVIDENCE_USES_FULL_FEASIBLE_SET"
            elif deterministic.status != "OK":
                configuration_reason = "EVIDENCE_CONFLICT_OR_OUTSIDE_CATALOGUE"
            elif not set(deterministic.feasible_candidate_ids) <= set(self.deployment.configuration.classes):
                configuration_reason = "CONFIGURATION_OUTSIDE_TRAINED_LABEL_SUPPORT"
            else:
                from models.candidate_prior import candidate_prior_from_model
                candidate_prior = candidate_prior_from_model(self.deployment.configuration, feature_vector, domain_id=self.deployment.manifest["domain_id"])
                calibrator = self.deployment.conformal
                configuration_reason = "LEARNED_PRIOR_AND_SPLIT_CONFORMAL_LOADED"

        application: dict[str, Any]
        if scope_reason:
            application = {"label": "UNKNOWN", "status": EvidenceStatus.UNKNOWN_UNOBSERVABLE.value, "reason_code": scope_reason, "probabilities": {}}
        elif application_model is None:
            application = {
                "label": None,
                "status": EvidenceStatus.UNKNOWN_UNOBSERVABLE.value,
                "reason_code": "MODEL_NOT_SUPPLIED",
                "probabilities": {},
            }
        else:
            probabilities = application_model.predict_proba([feature_vector])[0]
            if not application_model.is_calibrated:
                application = {
                    "label": None,
                    "status": EvidenceStatus.UNKNOWN_UNOBSERVABLE.value,
                    "reason_code": "PROBABILITY_CALIBRATION_REQUIRED",
                    "probabilities": probabilities,
                }
            elif open_world_gate is None:
                application = {
                    "label": None,
                    "status": EvidenceStatus.UNKNOWN_UNOBSERVABLE.value,
                    "reason_code": "OPEN_WORLD_GATE_NOT_CALIBRATED",
                    "probabilities": probabilities,
                }
            else:
                decision = open_world_gate.decide(probabilities)
                application = decision.to_dict()
                application["status"] = EvidenceStatus.AI_INFERRED.value if decision.accepted else EvidenceStatus.UNKNOWN_UNOBSERVABLE.value
                if decision.accepted:
                    capture.evidence.add(
                        EvidenceRecord(
                            "inner.application_class",
                            decision.label,
                            EvidenceStatus.AI_INFERRED,
                            "TRAFFIC_CLASSIFIER",
                            "Payload-free flow metadata classified by a calibrated model and held-out open-world gate",
                            "features/ and models/",
                            confidence=decision.max_probability,
                            model_id=application_model.model_id,
                            model_hash=application_model.model_hash,
                            training_domain_id=self.deployment.manifest["domain_id"] if self.deployment else "CALLER_SUPPLIED_MODEL",
                        ),
                        replace=False,
                    )

        application["scope"] = "CAPTURE_AGGREGATE_SINGLE_VPN"
        application["ood_caveat"] = "Confidence rejection is a heuristic; high confidence does not prove in-domain traffic."
        if application_model:
            application["model_id"], application["model_hash"] = application_model.model_id, application_model.model_hash
        model_ms = (time.perf_counter() - model_started) * 1000

        inference_started = time.perf_counter()
        cgii_result = engine.infer(
            capture.evidence,
            candidate_prior,
            alpha=self.alpha,
            calibrator=calibrator,
        )
        if scope_reason == "MULTI_SESSION_CAPTURE_NOT_SUPPORTED_FOR_AGGREGATE_INFERENCE":
            cgii_result = engine._empty_result(capture.evidence, status="UNSUPPORTED_SCOPE", alpha=self.alpha, flags=[scope_reason])
        if self.deployment and configuration_reason != "LEARNED_PRIOR_AND_SPLIT_CONFORMAL_LOADED":
            cgii_result.flags.append(configuration_reason)
        candidates = [self.catalogue.by_id[candidate_id] for candidate_id in cgii_result.prediction_set]
        policy_result = self.policy_engine.evaluate(
            candidates,
            self.profile_id,
            basis_status=cgii_result.inference_status,
        )
        risk_result = compute_risk_interval(
            policy_result,
            cgii_result.posterior if cgii_result.inference_status is EvidenceStatus.AI_INFERRED else None,
        )
        remediation_result = find_minimum_changes(
            candidates,
            self.catalogue,
            self.policy_engine,
            self.profile_id,
            basis_status=cgii_result.inference_status,
        )
        inference_ms = (time.perf_counter() - inference_started) * 1000
        total_ms = (time.perf_counter() - total_started) * 1000
        completed = datetime.now(timezone.utc).isoformat()
        deployment_id = self.deployment.manifest["bundle_id"] if self.deployment else "NO_DEPLOYMENT"
        evidence_hash = hashlib.sha256(json.dumps(capture.evidence.to_list(), sort_keys=True).encode()).hexdigest()
        run_seed_material = f"{VERSION}:{capture.sha256}:{self.catalogue.catalogue_hash}:{self.policy_engine.policy_hash}:{self.profile_id}:{deployment_id}:{self.alpha}:{evidence_hash}"
        run_id = "vgx-" + hashlib.sha256(run_seed_material.encode()).hexdigest()[:16]
        LOGGER.info(
            "assessment completed",
            extra={"run_id": run_id, "stage": "pipeline", "event": "ASSESSMENT_COMPLETED"},
        )
        capture_data = capture.to_dict(include_packets=include_packets)
        if capture_metadata:
            allowed_capture_metadata = {
                key: capture_metadata[key]
                for key in ("interface", "filter", "duration_seconds", "started_at_utc", "completed_at_utc", "capture_sha256", "authorization_acknowledged", "active_probe_performed")
                if key in capture_metadata
            }
            if allowed_capture_metadata:
                capture_data["collection"] = allowed_capture_metadata
        return AnalysisBundle(
            mode=mode,
            run={
                "run_id": run_id,
                "product_version": VERSION,
                "deployment": self.deployment.to_dict() if self.deployment else {"state": "NOT_CONFIGURED"},
                "configuration_inference_reason": configuration_reason,
                "assessment_scope": "CAPTURE_AGGREGATE_SINGLE_VPN",
                "completed_at_utc": completed,
                "profile_id": self.profile_id,
                "alpha": self.alpha,
                "catalogue_hash": self.catalogue.catalogue_hash,
                "policy_hash": self.policy_engine.policy_hash,
                "latency_ms": {
                    "parse": parse_ms,
                    "features_and_observability": feature_ms,
                    "model_inference_and_domain_checks": model_ms,
                    "cgii_policy_risk_remediation": inference_ms,
                    "total": total_ms,
                },
            },
            capture=capture_data,
            features={
                "status": EvidenceStatus.DETERMINISTICALLY_DERIVED.value,
                "flow_schema": list(FLOW_FEATURE_NAMES),
                "flow_values": flow_feature_map,
                "sequence_shape": [len(sequence.values), len(sequence.schema)],
                "sequence_observed_packets": sum(sequence.mask),
                "payload_decrypted": False,
            },
            application=application,
            crypto_agility=crypto_agility,
            cgii=cgii_result.to_dict(),
            policy=policy_result.to_dict(),
            risk=risk_result.to_dict(),
            remediation=remediation_result.to_dict(),
            threat_matrix=build_threat_matrix(policy_result, capture.evidence, self.policy_engine),
        )
