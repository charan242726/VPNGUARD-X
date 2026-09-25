"""Fixed-length metadata sequences for temporal models."""

from __future__ import annotations

from dataclasses import dataclass
from math import log1p
from typing import Any, Iterable

from parser.records import PacketRecord

from .flow import PACKET_KINDS, canonical_endpoints


KIND_INDEX = {kind: index + 1 for index, kind in enumerate(PACKET_KINDS)}


@dataclass(frozen=True)
class SequenceFeatures:
    values: tuple[tuple[float, float, float, float, float], ...]
    mask: tuple[int, ...]
    packet_indices: tuple[int, ...]
    schema: tuple[str, ...] = ("signed_log_length", "log_iat", "kind_id", "is_esp", "is_ike")

    def to_dict(self) -> dict[str, Any]:
        return {
            "values": [list(row) for row in self.values],
            "mask": list(self.mask),
            "packet_indices": list(self.packet_indices),
            "schema": list(self.schema),
        }


def extract_sequence_features(
    packets: Iterable[PacketRecord],
    *,
    sequence_length: int = 128,
) -> SequenceFeatures:
    if sequence_length <= 0:
        raise ValueError("sequence_length must be positive")
    selected = sorted(list(packets), key=lambda packet: (packet.timestamp, packet.index))[:sequence_length]
    pair = canonical_endpoints(selected[0]) if selected else ("", "")
    rows: list[tuple[float, float, float, float, float]] = []
    indices: list[int] = []
    previous_time: float | None = None
    for packet in selected:
        direction = 1.0 if (packet.source_ip or "") == pair[0] else -1.0
        signed_length = direction * log1p(max(0, packet.original_length))
        iat = 0.0 if previous_time is None else log1p(max(0.0, packet.timestamp - previous_time))
        kind = packet.packet_kind if packet.packet_kind in KIND_INDEX else "OTHER"
        rows.append(
            (
                signed_length,
                iat,
                float(KIND_INDEX[kind]),
                float(packet.esp is not None),
                float(packet.ike is not None),
            )
        )
        indices.append(packet.index)
        previous_time = packet.timestamp
    observed = len(rows)
    rows.extend([(0.0, 0.0, 0.0, 0.0, 0.0)] * (sequence_length - observed))
    mask = [1] * observed + [0] * (sequence_length - observed)
    indices.extend([-1] * (sequence_length - observed))
    return SequenceFeatures(tuple(rows), tuple(mask), tuple(indices))
