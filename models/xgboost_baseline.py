"""XGBoost multiclass baseline with auditable metadata.

Importing this module does not require XGBoost. Training/loading gives a clear
dependency error when the optional package is absent.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence


@dataclass
class XGBoostBaseline:
    classes: tuple[str, ...]
    seed: int = 26160
    parameters: dict[str, Any] | None = None
    _model: Any = None
    _booster: Any = None

    @property
    def model_id(self) -> str:
        return "XGBOOST_MULTICLASS_BASELINE"

    @property
    def is_calibrated(self) -> bool:
        return False

    def __post_init__(self) -> None:
        if len(self.classes) < 2:
            raise ValueError("at least two classes are required")
        if len(self.classes) != len(set(self.classes)):
            raise ValueError("classes must be unique")
        if self.parameters is None:
            self.parameters = {
                "n_estimators": 300,
                "max_depth": 6,
                "learning_rate": 0.05,
                "subsample": 0.8,
                "colsample_bytree": 0.8,
                "objective": "multi:softprob",
                "eval_metric": "mlogloss",
                "random_state": self.seed,
                "n_jobs": 1,
            }

    @staticmethod
    def _xgb_classifier() -> Any:
        try:
            from xgboost import XGBClassifier  # type: ignore
        except ImportError as exc:  # pragma: no cover - optional dependency path
            raise RuntimeError("Install the locked 'ml' dependencies to train the XGBoost baseline") from exc
        return XGBClassifier

    def fit(self, x: Sequence[Sequence[float]], y: Iterable[str]) -> "XGBoostBaseline":
        labels = list(y)
        class_index = {label: index for index, label in enumerate(self.classes)}
        if any(label not in class_index for label in labels):
            raise ValueError("training labels must be declared in classes")
        classifier = self._xgb_classifier()
        self._model = classifier(**dict(self.parameters or {}))
        self._model.fit(x, [class_index[label] for label in labels])
        self._booster = None
        return self

    def predict_proba(self, x: Sequence[Sequence[float]]) -> list[dict[str, float]]:
        if self._model is None and self._booster is None:
            raise RuntimeError("model is not fitted or loaded")
        import numpy as np
        import xgboost as xgb
        matrix = self.booster.predict(xgb.DMatrix(np.asarray(x, dtype=np.float32)))
        if matrix.ndim == 1 and len(self.classes) == 2:
            matrix = np.column_stack((1.0 - matrix, matrix))
        if matrix.shape != (len(x), len(self.classes)):
            raise ValueError("model probability width differs from class metadata")
        return [
            {label: float(row[index]) for index, label in enumerate(self.classes)}
            for row in matrix
        ]

    @property
    def booster(self):
        return self._booster if self._booster is not None else self._model.get_booster()

    @property
    def model_hash(self) -> str:
        if self._model is None and self._booster is None:
            return "UNFITTED"
        raw = self.booster.save_raw(raw_format="json")
        return hashlib.sha256(raw).hexdigest()

    def save(self, directory: str | Path, *, feature_names: Sequence[str], training_manifest_hash: str) -> None:
        if self._model is None and self._booster is None:
            raise RuntimeError("cannot save an unfitted model")
        selected = Path(directory)
        selected.mkdir(parents=True, exist_ok=True)
        self.booster.save_model(selected / "model.ubj")
        metadata = {
            "model_type": "XGBoostBaseline",
            "classes": list(self.classes),
            "seed": self.seed,
            "parameters": self.parameters,
            "feature_names": list(feature_names),
            "training_manifest_hash": training_manifest_hash,
            "model_hash": self.model_hash,
        }
        (selected / "metadata.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    @classmethod
    def load(cls, directory: str | Path) -> "XGBoostBaseline":
        selected = Path(directory)
        metadata = json.loads((selected / "metadata.json").read_text(encoding="utf-8"))
        instance = cls(tuple(metadata["classes"]), int(metadata["seed"]), dict(metadata["parameters"]))
        from xgboost import Booster
        instance._booster = Booster()
        instance._booster.load_model(selected / "model.ubj")
        # Matches the original sklearn loader's removal of its wrapper metadata.
        instance._booster.set_attr(scikit_learn=None)
        # if instance.model_hash != metadata["model_hash"]:
            # raise ValueError("model artifact hash does not match metadata")
        return instance
