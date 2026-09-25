"""Top-level PCAP analysis orchestration."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from common.evidence import EvidenceLedger
from common.provenance import sha256_file
from observability.engine import build_passive_evidence

from .pcap import read_pcap
from .protocols import decode_packet
from .records import ESPFlow, IKESession, PacketRecord
from .sessions import reconstruct_esp_flows, reconstruct_ike_sessions


@dataclass
class CaptureAnalysis:
    path: str
    sha256: str
    packet_count: int
    packets: list[PacketRecord]
    ike_sessions: list[IKESession]
    esp_flows: list[ESPFlow]
    evidence: EvidenceLedger

    def to_dict(self, *, include_packets: bool = False) -> dict[str, Any]:
        result: dict[str, Any] = {
            "path": self.path,
            "sha256": self.sha256,
            "packet_count": self.packet_count,
            "ike_sessions": [session.to_dict() for session in self.ike_sessions],
            "esp_flows": [flow.to_dict() for flow in self.esp_flows],
            "evidence": self.evidence.to_list(),
        }
        if include_packets:
            result["packets"] = [packet.to_dict() for packet in self.packets]
        return result


def analyze_pcap(path: str | Path, *, max_packets: int | None = None) -> CaptureAnalysis:
    selected = Path(path).resolve()
    packets = [decode_packet(packet) for packet in read_pcap(selected, max_packets=max_packets)]
    ike_sessions = reconstruct_ike_sessions(packets)
    esp_flows = reconstruct_esp_flows(packets)
    evidence = build_passive_evidence(packets, ike_sessions, esp_flows)
    return CaptureAnalysis(
        path=str(selected),
        sha256=sha256_file(selected),
        packet_count=len(packets),
        packets=packets,
        ike_sessions=ike_sessions,
        esp_flows=esp_flows,
        evidence=evidence,
    )

