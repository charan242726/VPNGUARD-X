"""Train/save/load wrapper for the packet-metadata TCN baseline."""

from __future__ import annotations

import hashlib
import io
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Sequence

from .tcn_baseline import TCNConfig, build_tcn


@dataclass
class TCNClassifier:
    classes: tuple[str, ...]
    config: TCNConfig
    epochs: int = 30
    batch_size: int = 32
    learning_rate: float = 1e-3
    device: str = "cpu"
    _model: Any = None

    def __post_init__(self) -> None:
        if len(self.classes) != self.config.class_count:
            raise ValueError("class count must match TCN configuration")
        if len(set(self.classes)) != len(self.classes):
            raise ValueError("classes must be unique")

    @property
    def model_id(self) -> str:
        return "TCN_PACKET_SEQUENCE_BASELINE"

    @property
    def is_calibrated(self) -> bool:
        return False

    @staticmethod
    def _torch() -> Any:
        try:
            import torch
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("Install the locked 'ml' dependencies to train the TCN baseline") from exc
        return torch

    @property
    def model_hash(self) -> str:
        if self._model is None:
            return "UNFITTED"
        torch = self._torch()
        buffer = io.BytesIO()
        torch.save(self._model.state_dict(), buffer)
        return hashlib.sha256(buffer.getvalue()).hexdigest()

    def fit(
        self,
        sequences: Sequence[Sequence[Sequence[float]]],
        masks: Sequence[Sequence[int]],
        labels: Sequence[str],
    ) -> "TCNClassifier":
        if not sequences or len(sequences) != len(masks) or len(sequences) != len(labels):
            raise ValueError("non-empty sequences, masks, and labels must have equal length")
        torch = self._torch()
        torch.manual_seed(self.config.seed)
        if hasattr(torch, "use_deterministic_algorithms"):
            torch.use_deterministic_algorithms(True)
        class_index = {label: index for index, label in enumerate(self.classes)}
        if any(label not in class_index for label in labels):
            raise ValueError("training label is absent from classes")
        values = torch.tensor(sequences, dtype=torch.float32).permute(0, 2, 1)
        mask_values = torch.tensor(masks, dtype=torch.float32)
        targets = torch.tensor([class_index[label] for label in labels], dtype=torch.long)
        dataset = torch.utils.data.TensorDataset(values, mask_values, targets)
        generator = torch.Generator().manual_seed(self.config.seed)
        loader = torch.utils.data.DataLoader(
            dataset,
            batch_size=self.batch_size,
            shuffle=True,
            generator=generator,
            num_workers=0,
        )
        self._model = build_tcn(self.config).to(self.device)
        optimizer = torch.optim.Adam(self._model.parameters(), lr=self.learning_rate)
        loss_function = torch.nn.CrossEntropyLoss()
        self._model.train()
        for _ in range(self.epochs):
            for batch_values, batch_masks, batch_targets in loader:
                optimizer.zero_grad(set_to_none=True)
                logits = self._model(batch_values.to(self.device), batch_masks.to(self.device))
                loss = loss_function(logits, batch_targets.to(self.device))
                loss.backward()
                optimizer.step()
        return self

    def predict_proba(
        self,
        sequences: Sequence[Sequence[Sequence[float]]],
        masks: Sequence[Sequence[int]],
    ) -> list[dict[str, float]]:
        if self._model is None:
            raise RuntimeError("model is not fitted or loaded")
        torch = self._torch()
        values = torch.tensor(sequences, dtype=torch.float32).permute(0, 2, 1).to(self.device)
        mask_values = torch.tensor(masks, dtype=torch.float32).to(self.device)
        self._model.eval()
        with torch.no_grad():
            probabilities = torch.softmax(self._model(values, mask_values), dim=1).cpu().tolist()
        return [
            {label: float(row[index]) for index, label in enumerate(self.classes)}
            for row in probabilities
        ]

    def save(self, directory: str | Path, *, training_manifest_hash: str) -> None:
        if self._model is None:
            raise RuntimeError("cannot save an unfitted model")
        torch = self._torch()
        selected = Path(directory)
        selected.mkdir(parents=True, exist_ok=True)
        state_path = selected / "model.pt"
        torch.save(self._model.state_dict(), state_path)
        artifact_hash = hashlib.sha256(state_path.read_bytes()).hexdigest()
        metadata = {
            "model_type": self.model_id,
            "classes": list(self.classes),
            "config": asdict(self.config),
            "epochs": self.epochs,
            "batch_size": self.batch_size,
            "learning_rate": self.learning_rate,
            "training_manifest_hash": training_manifest_hash,
            "artifact_sha256": artifact_hash,
        }
        (selected / "metadata.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    @classmethod
    def load(cls, directory: str | Path, *, device: str = "cpu") -> "TCNClassifier":
        selected = Path(directory)
        metadata = json.loads((selected / "metadata.json").read_text(encoding="utf-8"))
        state_path = selected / "model.pt"
        if hashlib.sha256(state_path.read_bytes()).hexdigest() != metadata["artifact_sha256"]:
            raise ValueError("TCN artifact hash does not match metadata")
        config_data = dict(metadata["config"])
        config_data["hidden_channels"] = tuple(config_data["hidden_channels"])
        instance = cls(
            tuple(metadata["classes"]),
            TCNConfig(**config_data),
            int(metadata["epochs"]),
            int(metadata["batch_size"]),
            float(metadata["learning_rate"]),
            device,
        )
        torch = instance._torch()
        instance._model = build_tcn(instance.config).to(device)
        instance._model.load_state_dict(torch.load(state_path, map_location=device, weights_only=True))
        instance._model.eval()
        return instance
