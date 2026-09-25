"""Temporal Convolutional Network baseline for packet-metadata sequences."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class TCNConfig:
    input_channels: int = 5
    hidden_channels: tuple[int, ...] = (64, 64, 128)
    kernel_size: int = 3
    dropout: float = 0.15
    class_count: int = 7
    seed: int = 26160


def build_tcn(config: TCNConfig) -> Any:
    """Build the PyTorch model lazily so parser/core users need not install torch."""
    try:
        import torch
        from torch import nn
    except ImportError as exc:  # pragma: no cover - optional dependency path
        raise RuntimeError("Install the locked 'ml' dependencies to build the TCN baseline") from exc

    torch.manual_seed(config.seed)

    class ResidualBlock(nn.Module):
        def __init__(self, in_channels: int, out_channels: int, dilation: int):
            super().__init__()
            padding = (config.kernel_size - 1) * dilation // 2
            self.network = nn.Sequential(
                nn.Conv1d(in_channels, out_channels, config.kernel_size, padding=padding, dilation=dilation),
                nn.BatchNorm1d(out_channels),
                nn.ReLU(),
                nn.Dropout(config.dropout),
                nn.Conv1d(out_channels, out_channels, config.kernel_size, padding=padding, dilation=dilation),
                nn.BatchNorm1d(out_channels),
                nn.ReLU(),
                nn.Dropout(config.dropout),
            )
            self.residual = nn.Identity() if in_channels == out_channels else nn.Conv1d(in_channels, out_channels, 1)

        def forward(self, value: Any) -> Any:
            return torch.relu(self.network(value) + self.residual(value))

    class TCN(nn.Module):
        def __init__(self) -> None:
            super().__init__()
            layers = []
            current = config.input_channels
            for index, channels in enumerate(config.hidden_channels):
                layers.append(ResidualBlock(current, channels, 2**index))
                current = channels
            self.encoder = nn.Sequential(*layers)
            self.head = nn.Linear(current, config.class_count)

        def forward(self, value: Any, mask: Any | None = None) -> Any:
            encoded = self.encoder(value)
            if mask is None:
                pooled = encoded.mean(dim=-1)
            else:
                weights = mask.unsqueeze(1).to(encoded.dtype)
                pooled = (encoded * weights).sum(dim=-1) / weights.sum(dim=-1).clamp_min(1.0)
            return self.head(pooled)

    return TCN()
