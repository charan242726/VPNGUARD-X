"""Conservative IKE/ESP session reconstruction."""

from __future__ import annotations

from collections import defaultdict
from typing import Iterable

from .records import ESPFlow, IKESession, PacketRecord


def reconstruct_ike_sessions(packets: Iterable[PacketRecord]) -> list[IKESession]:
    sessions: dict[tuple[int, str, str], IKESession] = {}
    seen_messages: dict[tuple[int, str, str], set[tuple[int, int, bool, int]]] = defaultdict(set)
    for packet in packets:
        if packet.ike is None or packet.source_ip is None or packet.destination_ip is None:
            continue
        ike = packet.ike
        endpoint_pair = tuple(sorted((packet.source_ip, packet.destination_ip)))
        key = (ike.initiator_spi, endpoint_pair[0], endpoint_pair[1])
        session = sessions.setdefault(key, IKESession(initiator_spi=ike.initiator_spi))
        if ike.responder_spi:
            if session.responder_spi is None:
                session.responder_spi = ike.responder_spi
            elif session.responder_spi != ike.responder_spi:
                # SPI reuse/collision is represented as a separate synthetic key.
                key = (ike.initiator_spi ^ ike.responder_spi, endpoint_pair[0], endpoint_pair[1])
                session = sessions.setdefault(
                    key,
                    IKESession(initiator_spi=ike.initiator_spi, responder_spi=ike.responder_spi),
                )
        session.packet_indices.append(packet.index)
        session.endpoints.add((packet.source_ip, packet.destination_ip))
        signature = (ike.exchange_type, ike.message_id, ike.is_response, ike.length)
        if signature in seen_messages[key]:
            session.retransmissions += 1
        else:
            seen_messages[key].add(signature)
            session.exchanges.append((ike.exchange_type, ike.message_id, ike.is_response))
    return sorted(sessions.values(), key=lambda s: s.packet_indices[0] if s.packet_indices else -1)


def reconstruct_esp_flows(packets: Iterable[PacketRecord]) -> list[ESPFlow]:
    flows: dict[tuple[str, str, int, bool], ESPFlow] = {}
    for packet in packets:
        if packet.esp is None or packet.source_ip is None or packet.destination_ip is None:
            continue
        key = (packet.source_ip, packet.destination_ip, packet.esp.spi, packet.esp.udp_encapsulated)
        flow = flows.setdefault(
            key,
            ESPFlow(
                source_ip=packet.source_ip,
                destination_ip=packet.destination_ip,
                spi=packet.esp.spi,
                udp_encapsulated=packet.esp.udp_encapsulated,
            ),
        )
        flow.packet_indices.append(packet.index)
        flow.sequences.append(packet.esp.sequence)

    for flow in flows.values():
        gaps = 0
        duplicates = 0
        seen: set[int] = set()
        previous: int | None = None
        for sequence in flow.sequences:
            if sequence in seen:
                duplicates += 1
            seen.add(sequence)
            if previous is not None:
                delta = (sequence - previous) & 0xFFFFFFFF
                if 1 < delta < 0x80000000:
                    gaps += delta - 1
            previous = sequence
        flow.observed_gap_count = gaps
        flow.duplicate_count = duplicates
    return sorted(flows.values(), key=lambda f: f.packet_indices[0] if f.packet_indices else -1)

