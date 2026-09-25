"""Open-world abstention based on held-out in-domain scores."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from math import ceil, isfinite
from typing import Any, Mapping, Sequence


@dataclass(frozen=True)
class OpenWorldDecision:
    label: str
    accepted: bool
    max_probability: float
    threshold: float
    reason_code: str
    probabilities: dict[str, float]

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "accepted": self.accepted,
            "max_probability": self.max_probability,
            "threshold": self.threshold,
            "reason_code": self.reason_code,
            "probabilities": self.probabilities,
        }


@dataclass(frozen=True)
class OpenWorldGate:
    threshold: float
    target_id_rejection_rate: float
    calibration_count: int
    gate_hash: str

    @classmethod
    def fit(
        cls,
        in_domain_max_probabilities: Sequence[float],
        *,
        target_id_rejection_rate: float = 0.05,
    ) -> "OpenWorldGate":
        if not in_domain_max_probabilities:
            raise ValueError("in-domain validation scores are required")
        if not 0.0 < target_id_rejection_rate < 1.0:
            raise ValueError("target rejection rate must be in (0, 1)")
        ordered = sorted(float(value) for value in in_domain_max_probabilities)
        if any(value < 0 or value > 1 for value in ordered):
            raise ValueError("probabilities must be in [0, 1]")
        rank = max(1, ceil(target_id_rejection_rate * len(ordered)))
        threshold = ordered[rank - 1]
        payload = {
            "threshold": threshold,
            "target_id_rejection_rate": target_id_rejection_rate,
            "calibration_count": len(ordered),
        }
        gate_hash = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
        return cls(threshold, target_id_rejection_rate, len(ordered), gate_hash)

    def decide(self, probabilities: Mapping[str, float]) -> OpenWorldDecision:
        if not probabilities:
            return OpenWorldDecision("UNKNOWN", False, 0.0, self.threshold, "EMPTY_DISTRIBUTION", {})
        normalized = {str(label): float(value) for label, value in probabilities.items()}
        if any(not isfinite(value) or value < 0 or value > 1 for value in normalized.values()):
            raise ValueError("probabilities must be in [0, 1]")
        if abs(sum(normalized.values()) - 1.0) > 1e-6:
            raise ValueError("probabilities must sum to one")
        label = max(sorted(normalized), key=normalized.get)
        confidence = normalized[label]
        accepted = confidence >= self.threshold
        return OpenWorldDecision(
            label if accepted else "UNKNOWN",
            accepted,
            confidence,
            self.threshold,
            "IN_DOMAIN_CONFIDENCE" if accepted else "LOW_MAX_PROBABILITY_OOD_OR_UNCERTAIN",
            normalized,
        )
