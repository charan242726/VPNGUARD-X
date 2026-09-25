"""Finite-sample split-conformal prediction sets for candidate probabilities."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from math import ceil
from typing import Mapping, Sequence


@dataclass(frozen=True)
class SplitConformalCalibrator:
    calibrator_id: str
    alpha: float
    threshold: float
    sample_count: int
    calibrator_hash: str

    @classmethod
    def fit(
        cls,
        probabilities: Sequence[Mapping[str, float]],
        labels: Sequence[str],
        *,
        alpha: float = 0.1,
        calibrator_id: str = "SPLIT_CONFORMAL_1_MINUS_P_TRUE",
    ) -> "SplitConformalCalibrator":
        if len(probabilities) != len(labels) or not labels:
            raise ValueError("non-empty probabilities and labels must have equal length")
        if not 0.0 < alpha < 1.0:
            raise ValueError("alpha must be in (0, 1)")
        scores: list[float] = []
        for distribution, label in zip(probabilities, labels, strict=True):
            if label not in distribution:
                raise ValueError(f"true label {label!r} is absent from a calibration distribution")
            probability = float(distribution[label])
            if not 0.0 <= probability <= 1.0:
                raise ValueError("probabilities must be in [0, 1]")
            scores.append(1.0 - probability)
        scores.sort()
        rank = ceil((len(scores) + 1) * (1.0 - alpha))
        threshold = 1.0 if rank > len(scores) else scores[rank - 1]
        payload = {
            "id": calibrator_id,
            "alpha": alpha,
            "threshold": threshold,
            "sample_count": len(scores),
            "scores": scores,
        }
        digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
        return cls(calibrator_id, alpha, threshold, len(scores), digest)

    def prediction_set(self, posterior: Mapping[str, float], alpha: float) -> list[str]:
        if abs(alpha - self.alpha) > 1e-12:
            raise ValueError("requested alpha differs from fitted calibrator alpha")
        return sorted(
            [candidate_id for candidate_id, probability in posterior.items() if 1.0 - probability <= self.threshold],
            key=lambda candidate_id: (-posterior[candidate_id], candidate_id),
        )

    def to_dict(self) -> dict[str, float | int | str]:
        return {
            "calibrator_id": self.calibrator_id,
            "alpha": self.alpha,
            "threshold": self.threshold,
            "sample_count": self.sample_count,
            "calibrator_hash": self.calibrator_hash,
        }
