"""Conservative multiple-key-exchange observability assessment."""

from __future__ import annotations

from typing import Any, Iterable

from common.evidence import EvidenceLedger, EvidenceRecord, EvidenceStatus
from parser.records import PacketRecord


MKE_EXCHANGES = {43: "IKE_INTERMEDIATE", 44: "IKE_FOLLOWUP_KE"}


def assess_multiple_key_exchanges(packets: Iterable[PacketRecord], ledger: EvidenceLedger) -> dict[str, Any]:
    events = [
        {
            "packet_index": packet.index,
            "exchange_type": packet.ike.exchange_type,
            "exchange_name": MKE_EXCHANGES[packet.ike.exchange_type],
            "message_id": packet.ike.message_id,
            "is_response": packet.ike.is_response,
        }
        for packet in packets
        if packet.ike is not None and packet.ike.major_version == 2 and packet.ike.exchange_type in MKE_EXCHANGES
    ]
    if events:
        ledger.add(
            EvidenceRecord(
                "ike.multiple_ke_exchange_headers",
                events,
                EvidenceStatus.OBSERVED,
                "IKE_FIXED_HEADER",
                "RFC 9370 exchange types are visible in IKE headers; protected KE payload algorithms are not exposed",
                "RFC 9370 Sections 2-3; RFC 7296 protected-exchange boundary",
                packet_indices=tuple(event["packet_index"] for event in events),
            )
        )
    existing_algorithms = ledger.best("ike.additional_ke_algorithms")
    if existing_algorithms is None:
        ledger.add(
            EvidenceRecord(
                "ike.additional_ke_algorithms",
                None,
                EvidenceStatus.UNKNOWN_UNOBSERVABLE,
                "RFC9370_OBSERVABILITY",
                "Additional KE payload contents are protected; packet size or exchange presence does not identify ML-KEM or another method",
                "RFC 9370 Sections 2-3",
                reason_code="PROTECTED_OR_ENDPOINT_LOCAL",
            )
        )
        existing_algorithms = ledger.best("ike.additional_ke_algorithms")
    algorithm_known = existing_algorithms is not None and existing_algorithms.is_hard and existing_algorithms.value is not None
    return {
        "status": EvidenceStatus.OBSERVED.value if events or algorithm_known else EvidenceStatus.UNKNOWN_UNOBSERVABLE.value,
        "mke_header_events": events,
        "additional_ke_algorithms": existing_algorithms.value if algorithm_known else None,
        "algorithm_status": existing_algorithms.status.value if existing_algorithms is not None else EvidenceStatus.UNKNOWN_UNOBSERVABLE.value,
        "pqc_claimed": False,
        "rationale": "MKE exchange headers alone do not reveal the protected additional key-exchange algorithm.",
    }
