"""Dependency-free scalar temperature calibration for multiclass logits."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from math import exp, log
from typing import Sequence


def _softmax(row: Sequence[float], temperature: float) -> list[float]:
    scaled = [float(value) / temperature for value in row]
    maximum = max(scaled)
    exponentials = [exp(value - maximum) for value in scaled]
    denominator = sum(exponentials)
    return [value / denominator for value in exponentials]


@dataclass(frozen=True)
class TemperatureScaler:
    temperature: float
    calibration_count: int
    calibrator_hash: str

    @classmethod
    def fit(
        cls,
        logits: Sequence[Sequence[float]],
        labels: Sequence[int],
        *,
        grid_points: int = 400,
        minimum: float = 0.05,
        maximum: float = 10.0,
    ) -> "TemperatureScaler":
        if len(logits) != len(labels) or not labels:
            raise ValueError("non-empty logits and labels must have equal length")
        if grid_points < 2 or minimum <= 0 or maximum <= minimum:
            raise ValueError("invalid temperature search range")
        width = len(logits[0])
        if width < 2 or any(len(row) != width for row in logits):
            raise ValueError("logit rows require a common width >= 2")
        if any(label < 0 or label >= width for label in labels):
            raise ValueError("label outside logit width")

        def nll(temperature: float) -> float:
            return -sum(
                log(max(1e-15, _softmax(row, temperature)[label]))
                for row, label in zip(logits, labels, strict=True)
            ) / len(labels)

        log_minimum = log(minimum)
        log_maximum = log(maximum)
        candidates = [
            exp(log_minimum + index * (log_maximum - log_minimum) / (grid_points - 1))
            for index in range(grid_points)
        ]
        temperature = min(candidates, key=lambda value: (nll(value), value))
        payload = {"temperature": temperature, "calibration_count": len(labels), "method": "log_grid_nll"}
        digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
        return cls(temperature, len(labels), digest)

    def transform(self, logits: Sequence[Sequence[float]]) -> list[list[float]]:
        return [_softmax(row, self.temperature) for row in logits]
