"""Deterministic statistical features derived only from packet metadata."""

from __future__ import annotations

from collections import Counter
from math import sqrt
from statistics import mean
from typing import Iterable

from parser.records import PacketRecord


PACKET_KINDS = ("IKE", "IKE_NATT", "ESP_NATIVE", "ESP_UDP", "NAT_KEEPALIVE", "OTHER")
FLOW_FEATURE_NAMES = (
    "packet_count",
    "byte_count",
    "duration_seconds",
    "packet_rate",
    "byte_rate",
    "size_mean",
    "size_std",
    "size_min",
    "size_max",
    "size_q25",
    "size_median",
    "size_q75",
    "iat_mean",
    "iat_std",
    "iat_min",
    "iat_max",
    "forward_packet_fraction",
    "direction_switch_rate",
    "esp_sequence_gap_count",
    "truncated_packet_fraction",
) + tuple(f"kind_fraction_{kind.lower()}" for kind in PACKET_KINDS)


def _quantile(values: list[float], probability: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    position = probability * (len(ordered) - 1)
    lower = int(position)
    upper = min(len(ordered) - 1, lower + 1)
    fraction = position - lower
    return ordered[lower] * (1 - fraction) + ordered[upper] * fraction


def _std(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    average = mean(values)
    return sqrt(sum((value - average) ** 2 for value in values) / len(values))


def canonical_endpoints(packet: PacketRecord) -> tuple[str, str]:
    left = packet.source_ip or ""
    right = packet.destination_ip or ""
    return tuple(sorted((left, right)))  # type: ignore[return-value]


def extract_flow_features(packets: Iterable[PacketRecord]) -> dict[str, float]:
    selected = sorted(list(packets), key=lambda packet: (packet.timestamp, packet.index))
    if not selected:
        return {name: 0.0 for name in FLOW_FEATURE_NAMES}
    sizes = [float(packet.original_length) for packet in selected]
    iats = [max(0.0, selected[index].timestamp - selected[index - 1].timestamp) for index in range(1, len(selected))]
    duration = max(0.0, selected[-1].timestamp - selected[0].timestamp)
    rate_denominator = max(duration, 1e-9)
    endpoint_pair = canonical_endpoints(selected[0])
    directions = [0 if (packet.source_ip or "") == endpoint_pair[0] else 1 for packet in selected]
    switches = sum(directions[index] != directions[index - 1] for index in range(1, len(directions)))
    kinds = Counter(packet.packet_kind if packet.packet_kind in PACKET_KINDS else "OTHER" for packet in selected)
    sequence_gaps = 0
    last_sequence: dict[tuple[str | None, str | None, int], int] = {}
    for packet in selected:
        if packet.esp is None:
            continue
        key = (packet.source_ip, packet.destination_ip, packet.esp.spi)
        previous = last_sequence.get(key)
        if previous is not None and packet.esp.sequence > previous + 1:
            sequence_gaps += packet.esp.sequence - previous - 1
        last_sequence[key] = max(previous or 0, packet.esp.sequence)
    values = {
        "packet_count": float(len(selected)),
        "byte_count": sum(sizes),
        "duration_seconds": duration,
        "packet_rate": len(selected) / rate_denominator,
        "byte_rate": sum(sizes) / rate_denominator,
        "size_mean": mean(sizes),
        "size_std": _std(sizes),
        "size_min": min(sizes),
        "size_max": max(sizes),
        "size_q25": _quantile(sizes, 0.25),
        "size_median": _quantile(sizes, 0.5),
        "size_q75": _quantile(sizes, 0.75),
        "iat_mean": mean(iats) if iats else 0.0,
        "iat_std": _std(iats),
        "iat_min": min(iats) if iats else 0.0,
        "iat_max": max(iats) if iats else 0.0,
        "forward_packet_fraction": sum(direction == 0 for direction in directions) / len(directions),
        "direction_switch_rate": switches / max(1, len(directions) - 1),
        "esp_sequence_gap_count": float(sequence_gaps),
        "truncated_packet_fraction": sum(packet.truncated for packet in selected) / len(selected),
    }
    values.update({f"kind_fraction_{kind.lower()}": kinds[kind] / len(selected) for kind in PACKET_KINDS})
    return values


def extract_capture_features(packets: Iterable[PacketRecord]) -> list[float]:
    values = extract_flow_features(packets)
    return [values[name] for name in FLOW_FEATURE_NAMES]
