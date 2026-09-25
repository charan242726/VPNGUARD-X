"""Convert parsed packets and sessions into an evidence ledger."""

from __future__ import annotations

from collections import defaultdict
from typing import Iterable

from common.evidence import EvidenceLedger, EvidenceRecord, EvidenceStatus
from parser.records import ESPFlow, IKESession, PacketRecord


RFC7296 = "https://www.rfc-editor.org/rfc/rfc7296"
RFC4303 = "https://www.rfc-editor.org/rfc/rfc4303"
RFC3948 = "https://www.rfc-editor.org/rfc/rfc3948"


def _single_or_list(values: Iterable[object]) -> object | None:
    unique = []
    for value in values:
        if value not in unique:
            unique.append(value)
    if not unique:
        return None
    return unique[0] if len(unique) == 1 else unique


def _unknown(name: str, rationale: str, locator: str, reason: str = "PROTECTED_OR_NOT_CAPTURED") -> EvidenceRecord:
    return EvidenceRecord(
        property_name=name,
        value=None,
        status=EvidenceStatus.UNKNOWN_UNOBSERVABLE,
        source="IPSEC_OBSERVABILITY_MATRIX",
        source_locator=locator,
        rationale=rationale,
        reason_code=reason,
    )


def _selected_ike_transforms(packets: list[PacketRecord]) -> dict[int, list[tuple[str, int]]]:
    selected: dict[int, list[tuple[str, int]]] = defaultdict(list)
    for packet in packets:
        ike = packet.ike
        if ike is None or ike.major_version != 2 or ike.exchange_type != 34 or not ike.is_response:
            continue
        for payload in ike.payloads:
            if payload.payload_type != 33:
                continue
            for proposal in payload.parsed.get("proposals", []):
                for transform in proposal.get("transforms", []):
                    value = (str(transform["name"]), packet.index)
                    if value not in selected[int(transform["type"])]:
                        selected[int(transform["type"])].append(value)
    return selected


def build_passive_evidence(
    packets: list[PacketRecord],
    ike_sessions: list[IKESession],
    esp_flows: list[ESPFlow],
) -> EvidenceLedger:
    ledger = EvidenceLedger()
    if not packets:
        ledger.add(_unknown("capture.packet_count", "Capture contains no packets", "PCAP", "EMPTY_CAPTURE"))
        return ledger

    ip_versions = [p.ip_version for p in packets if p.ip_version is not None]
    if ip_versions:
        packet_ids = tuple(p.index for p in packets if p.ip_version is not None)
        ledger.add(
            EvidenceRecord(
                "outer.ip_version",
                _single_or_list(ip_versions),
                EvidenceStatus.OBSERVED,
                "PACKET_IP_HEADER",
                "IP version nibble was parsed from captured outer headers",
                "IPv4/IPv6 base header",
                packet_indices=packet_ids,
            )
        )
    source_addresses = [p.source_ip for p in packets if p.source_ip]
    destination_addresses = [p.destination_ip for p in packets if p.destination_ip]
    if source_addresses:
        ledger.add(EvidenceRecord("outer.source_address", sorted(set(source_addresses)), EvidenceStatus.OBSERVED, "PACKET_IP_HEADER", "Outer source addresses are present in captured IP headers", "IPv4/IPv6 header"))
    if destination_addresses:
        ledger.add(EvidenceRecord("outer.destination_address", sorted(set(destination_addresses)), EvidenceStatus.OBSERVED, "PACKET_IP_HEADER", "Outer destination addresses are present in captured IP headers", "IPv4/IPv6 header"))

    ike_packets = [p for p in packets if p.ike is not None]
    if ike_packets:
        versions = _single_or_list([f"IKEV{p.ike.major_version}" for p in ike_packets if p.ike])
        ledger.add(
            EvidenceRecord(
                "ike.version",
                versions,
                EvidenceStatus.OBSERVED,
                "IKE_HEADER",
                "The IKE major version is encoded in the fixed IKE header",
                "RFC 7296 Section 3.1",
                packet_indices=tuple(p.index for p in ike_packets),
            )
        )
        ledger.add(
            EvidenceRecord(
                "ike.exchange_type",
                sorted({p.ike.exchange_type for p in ike_packets if p.ike}),
                EvidenceStatus.OBSERVED,
                "IKE_HEADER",
                "Exchange Type is a fixed-header field; protected payload contents are not implied",
                "RFC 7296 Section 3.1",
                packet_indices=tuple(p.index for p in ike_packets),
            )
        )
        ledger.add(
            EvidenceRecord(
                "ike.initiator_spi",
                sorted({f"0x{p.ike.initiator_spi:016x}" for p in ike_packets if p.ike}),
                EvidenceStatus.OBSERVED,
                "IKE_HEADER",
                "Initiator SPI is present in the IKE fixed header",
                "RFC 7296 Section 3.1",
            )
        )
        responder_spis = {p.ike.responder_spi for p in ike_packets if p.ike and p.ike.responder_spi}
        if responder_spis:
            ledger.add(EvidenceRecord("ike.responder_spi", sorted(f"0x{x:016x}" for x in responder_spis), EvidenceStatus.OBSERVED, "IKE_HEADER", "Non-zero responder SPI is present in the IKE fixed header", "RFC 7296 Section 3.1"))

    selected = _selected_ike_transforms(packets)
    transform_properties = {
        1: "ike.selected_encryption",
        2: "ike.selected_prf",
        3: "ike.selected_integrity",
        4: "ike.selected_ke_group_transform",
    }
    for transform_type, property_name in transform_properties.items():
        values = selected.get(transform_type, [])
        if values:
            ledger.add(
                EvidenceRecord(
                    property_name,
                    _single_or_list([name for name, _ in values]),
                    EvidenceStatus.OBSERVED,
                    "IKE_SA_INIT_RESPONDER_SA_PAYLOAD",
                    "Responder IKE_SA_INIT selection was parsed from the unencrypted SAr1 payload",
                    "RFC 7296 Sections 1.2 and 3.3",
                    packet_indices=tuple(index for _, index in values),
                )
            )

    ke_values: list[tuple[int, int]] = []
    for packet in ike_packets:
        if packet.ike is None or packet.ike.major_version != 2 or packet.ike.exchange_type != 34:
            continue
        for payload in packet.ike.payloads:
            if payload.payload_type == 34 and "ke_group" in payload.parsed:
                ke_values.append((int(payload.parsed["ke_group"]), packet.index))
    if ke_values:
        ledger.add(
            EvidenceRecord(
                "ike.initial_ke_group",
                _single_or_list([value for value, _ in ke_values]),
                EvidenceStatus.OBSERVED,
                "IKE_SA_INIT_KE_PAYLOAD",
                "Key Exchange method/group is encoded in the visible IKE_SA_INIT KE payload",
                "RFC 7296 Sections 1.2 and 3.4",
                packet_indices=tuple(index for _, index in ke_values),
            )
        )

    natt_ike = [p.index for p in packets if p.packet_kind == "IKE_NATT"]
    if natt_ike:
        ledger.add(EvidenceRecord("natt.non_esp_marker", True, EvidenceStatus.OBSERVED, "UDP_4500_PAYLOAD", "Four zero octets preceded a structurally valid IKE header", "RFC 3948 Section 2.1", packet_indices=tuple(natt_ike)))

    has_udp_esp = any(p.packet_kind == "ESP_UDP" for p in packets)
    has_native_esp = any(p.packet_kind == "ESP_NATIVE" for p in packets)
    if has_udp_esp and not has_native_esp:
        ledger.add(EvidenceRecord("encapsulation", "UDP_ENCAPSULATED_ESP", EvidenceStatus.DETERMINISTICALLY_DERIVED, "RFC3948_FRAMING", "Non-zero SPI ESP records were parsed inside UDP/4500", "RFC 3948 Section 2.1", packet_indices=tuple(p.index for p in packets if p.packet_kind == "ESP_UDP")))
    elif has_native_esp and not has_udp_esp:
        ledger.add(EvidenceRecord("encapsulation", "NATIVE_ESP", EvidenceStatus.DETERMINISTICALLY_DERIVED, "IP_PROTOCOL_50", "ESP records were carried directly as IP protocol 50", "RFC 4303; IP protocol registry", packet_indices=tuple(p.index for p in packets if p.packet_kind == "ESP_NATIVE")))
    elif has_udp_esp and has_native_esp:
        ledger.add(EvidenceRecord("encapsulation", ["NATIVE_ESP", "UDP_ENCAPSULATED_ESP"], EvidenceStatus.DETERMINISTICALLY_DERIVED, "MIXED_CAPTURE_FRAMING", "Both native and UDP-encapsulated ESP were present; sessions must be assessed separately", "RFC 4303; RFC 3948"))

    if esp_flows:
        ledger.add(EvidenceRecord("esp.spi", sorted({f"0x{flow.spi:08x}" for flow in esp_flows}), EvidenceStatus.OBSERVED, "ESP_HEADER", "SPI is the first 32-bit ESP header field", "RFC 4303 Section 2.1"))
        ledger.add(EvidenceRecord("esp.sequence_low32", {f"0x{flow.spi:08x}": flow.sequences for flow in esp_flows}, EvidenceStatus.OBSERVED, "ESP_HEADER", "The low-order 32-bit sequence field is visible in each ESP header", "RFC 4303 Sections 2.2 and 2.2.1"))
        ledger.add(EvidenceRecord("esp.sequence_gap_count", sum(flow.observed_gap_count for flow in esp_flows), EvidenceStatus.DETERMINISTICALLY_DERIVED, "ESP_SEQUENCE_ANALYSIS", "Positive sequence gaps were counted per direction and SPI; this is a capture-loss proxy, not proof of network loss", "RFC 4303 Section 2.2"))

    truncation_rate = sum(1 for p in packets if p.truncated) / len(packets)
    ledger.add(EvidenceRecord("capture.packet_truncation_rate", truncation_rate, EvidenceStatus.DETERMINISTICALLY_DERIVED, "PCAP_RECORD_METADATA", "Computed from captured length versus original length", "Classic PCAP per-packet header"))
    ledger.add(EvidenceRecord("capture.packet_count", len(packets), EvidenceStatus.DETERMINISTICALLY_DERIVED, "PCAP_RECORDS", "Counted successfully read packet records", "Classic PCAP records"))
    ledger.add(EvidenceRecord("session.ike_session_count", len(ike_sessions), EvidenceStatus.DETERMINISTICALLY_DERIVED, "IKE_SESSIONIZER", "Grouped IKE headers by initiator SPI and endpoint pair", "RFC 7296 Section 3.1"))

    init_complete = False
    for session in ike_sessions:
        exchange_zero = {(exchange, message, response) for exchange, message, response in session.exchanges}
        if (34, 0, False) in exchange_zero and (34, 0, True) in exchange_zero:
            init_complete = True
            break
    ledger.add(EvidenceRecord("session.ike_sa_init_complete", init_complete, EvidenceStatus.DETERMINISTICALLY_DERIVED, "IKE_STATE_MACHINE", "Matched IKE_SA_INIT request and response with Message ID zero" if init_complete else "No complete matched IKE_SA_INIT request/response was reconstructed", "RFC 7296 Section 1.2"))

    hidden = {
        "ike.peer_identity": ("Peer identity is carried in protected IKE_AUTH content", "RFC 7296 Sections 1.2 and 2.15"),
        "ike.authentication_family": ("Authentication payload/method is protected after IKE_SA_INIT", "RFC 7296 Sections 1.2 and 2.15-2.16"),
        "child.encryption": ("CHILD-SA transforms are inside protected IKE_AUTH/CREATE_CHILD_SA payloads", "RFC 7296 Sections 1.3.1 and 3.14"),
        "child.integrity": ("CHILD-SA transforms are inside protected IKE_AUTH/CREATE_CHILD_SA payloads", "RFC 7296 Sections 1.3.1 and 3.14"),
        "child.mode": ("USE_TRANSPORT_MODE is inside protected CHILD-SA negotiation", "RFC 7296 Sections 1.3.1 and 2.23"),
        "child.traffic_selectors": ("Traffic selectors are inside protected CHILD-SA negotiation", "RFC 7296 Sections 1.3.1 and 3.13"),
        "child.pfs_group": ("Optional fresh KE for CHILD-SA is inside protected CREATE_CHILD_SA", "RFC 7296 Sections 1.3.1 and 2.17"),
        "sa.configured_lifetime": ("IKEv2 lifetimes are locally enforced rather than negotiated", "RFC 7296 Section 2.8"),
        "child.esn": ("Only low 32 sequence bits are transmitted under ESN", "RFC 4303 Section 2.2.1"),
        "child.anti_replay_enabled": ("Anti-replay enablement is receiver-local per SA", "RFC 4303 Section 3.4.3"),
        "child.replay_window_size": ("Replay-window state is maintained by the receiver", "RFC 4303 Section 3.4.3"),
        "inner.ip_version": ("The ESP inner payload is protected", "RFC 4303 Section 2"),
        "inner.application_class": ("No application model was supplied to passive evidence construction", "VPNGUARD-X model contract"),
        "session.child_sa_to_spi_mapping": ("Passive SPI does not expose the endpoint SAD mapping", "RFC 4303 Section 3.4.2"),
    }
    for name, (rationale, locator) in hidden.items():
        if ledger.best(name) is None:
            reason = "MODEL_NOT_RUN" if name == "inner.application_class" else "PROTECTED_OR_ENDPOINT_LOCAL"
            ledger.add(_unknown(name, rationale, locator, reason))
    return ledger

