"""Normalized parser records."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class PcapPacket:
    index: int
    timestamp: float
    captured_length: int
    original_length: int
    data: bytes
    link_type: int

    @property
    def truncated(self) -> bool:
        return self.captured_length < self.original_length


@dataclass(frozen=True)
class Transform:
    transform_type: int
    transform_id: int
    key_length: int | None = None
    name: str | None = None


@dataclass(frozen=True)
class Proposal:
    number: int
    protocol_id: int
    spi: bytes
    transforms: tuple[Transform, ...]


@dataclass(frozen=True)
class IKEPayload:
    payload_type: int
    next_payload: int
    critical: bool
    length: int
    parsed: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class IKEHeader:
    initiator_spi: int
    responder_spi: int
    next_payload: int
    major_version: int
    minor_version: int
    exchange_type: int
    flags: int
    message_id: int
    length: int
    is_response: bool
    from_initiator: bool
    payloads: tuple[IKEPayload, ...] = field(default_factory=tuple)
    complete: bool = True


@dataclass(frozen=True)
class ESPHeader:
    spi: int
    sequence: int
    udp_encapsulated: bool


@dataclass
class PacketRecord:
    index: int
    timestamp: float
    captured_length: int
    original_length: int
    link_type: int
    ip_version: int | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    ip_protocol: int | None = None
    source_port: int | None = None
    destination_port: int | None = None
    packet_kind: str = "OTHER"
    transport_payload_length: int = 0
    ike: IKEHeader | None = None
    esp: ESPHeader | None = None
    errors: list[str] = field(default_factory=list)

    @property
    def truncated(self) -> bool:
        return self.captured_length < self.original_length

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        if self.ike is not None:
            result["ike"]["initiator_spi"] = f"0x{self.ike.initiator_spi:016x}"
            result["ike"]["responder_spi"] = f"0x{self.ike.responder_spi:016x}"
        if self.esp is not None:
            result["esp"]["spi"] = f"0x{self.esp.spi:08x}"
        return result


@dataclass
class IKESession:
    initiator_spi: int
    responder_spi: int | None = None
    packet_indices: list[int] = field(default_factory=list)
    endpoints: set[tuple[str, str]] = field(default_factory=set)
    exchanges: list[tuple[int, int, bool]] = field(default_factory=list)
    retransmissions: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "initiator_spi": f"0x{self.initiator_spi:016x}",
            "responder_spi": None if self.responder_spi is None else f"0x{self.responder_spi:016x}",
            "packet_indices": self.packet_indices,
            "endpoints": sorted([list(x) for x in self.endpoints]),
            "exchanges": [
                {"exchange_type": e, "message_id": m, "is_response": r}
                for e, m, r in self.exchanges
            ],
            "retransmissions": self.retransmissions,
        }


@dataclass
class ESPFlow:
    source_ip: str
    destination_ip: str
    spi: int
    udp_encapsulated: bool
    packet_indices: list[int] = field(default_factory=list)
    sequences: list[int] = field(default_factory=list)
    observed_gap_count: int = 0
    duplicate_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "spi": f"0x{self.spi:08x}",
            "udp_encapsulated": self.udp_encapsulated,
            "packet_indices": self.packet_indices,
            "sequences": self.sequences,
            "observed_gap_count": self.observed_gap_count,
            "duplicate_count": self.duplicate_count,
        }

