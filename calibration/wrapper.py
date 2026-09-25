"""Attach fitted temperature scaling to a probability-producing classifier."""

from __future__ import annotations

import hashlib
from math import log
from typing import Any, Sequence

from .temperature import TemperatureScaler


class TemperatureCalibratedModel:
    def __init__(self, base_model: Any, scaler: TemperatureScaler):
        self.base_model = base_model
        self.scaler = scaler

    @property
    def model_id(self) -> str:
        return f"{self.base_model.model_id}+TEMPERATURE_SCALING"

    @property
    def model_hash(self) -> str:
        material = f"{self.base_model.model_hash}:{self.scaler.calibrator_hash}"
        return hashlib.sha256(material.encode()).hexdigest()

    @property
    def is_calibrated(self) -> bool:
        return True

    def predict_proba(self, x: Sequence[Sequence[float]]) -> list[dict[str, float]]:
        raw = self.base_model.predict_proba(x)
        labels = list(self.base_model.classes)
        logits = [[log(max(1e-15, distribution[label])) for label in labels] for distribution in raw]
        calibrated = self.scaler.transform(logits)
        return [
            {label: float(row[index]) for index, label in enumerate(labels)}
            for row in calibrated
        ]
