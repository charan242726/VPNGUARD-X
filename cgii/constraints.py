"""Compile audited hard evidence into executable candidate predicates."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from common.evidence import EvidenceLedger, EvidenceRecord

from .types import CandidateConfiguration, ConstraintTrace


FIELD_MAP = {
    "ike.version": "ike_version",
    "outer.ip_version": "outer_ip_version",
    "encapsulation": "encapsulation",
    "ike.selected_encryption": "ike_encryption",
    "ike.selected_integrity": "ike_integrity",
    "ike.selected_prf": "ike_prf",
    "ike.initial_ke_group": "ike_ke_group",
    "ike.selected_ke_group_transform": "ike_ke_group",
    "child.mode": "child_mode",
    "child.encryption": "child_encryption",
    "child.integrity": "child_integrity",
    "child.pfs_group": "child_pfs_group",
    "child.esn": "esn",
    "child.anti_replay_enabled": "anti_replay",
    "sa.configured_lifetime": "child_lifetime_seconds",
    "ike.authentication_family": "authentication_family",
}

KE_NAME_TO_ID = {
    "MODP_768": 1,
    "MODP_1024": 2,
    "MODP_1536": 5,
    "MODP_2048": 14,
    "MODP_3072": 15,
    "MODP_4096": 16,
    "MODP_6144": 17,
    "MODP_8192": 18,
    "ECP_256": 19,
    "ECP_384": 20,
    "ECP_521": 21,
    "CURVE_25519": 31,
    "CURVE_448": 32,
}


def is_aead(name: str) -> bool:
    upper = name.upper()
    return "GCM" in upper or "CCM" in upper or "POLY1305" in upper


def _canonical(value: Any, property_name: str) -> Any:
    if property_name == "encapsulation" and value == "NAT_T":
        return "UDP_ENCAPSULATED_ESP"
    if property_name == "ike.selected_ke_group_transform" and isinstance(value, str):
        return KE_NAME_TO_ID.get(value, value)
    if property_name in {"child.esn", "child.anti_replay_enabled"} and isinstance(value, str):
        return value.strip().lower() in {"true", "yes", "1", "enabled", "esn"}
    if property_name in {"outer.ip_version", "ike.initial_ke_group", "sa.configured_lifetime"}:
        if isinstance(value, str) and value.isdigit():
            return int(value)
    if property_name in {"child.mode", "ike.authentication_family"} and isinstance(value, str):
        return value.upper()
    return value


def _allowed_values(value: Any, property_name: str) -> tuple[Any, ...]:
    values = value if isinstance(value, (list, tuple, set)) else [value]
    return tuple(_canonical(item, property_name) for item in values)


@dataclass(frozen=True)
class CompiledConstraint:
    trace: ConstraintTrace
    predicate: Callable[[CandidateConfiguration], bool]

    def accepts(self, candidate: CandidateConfiguration) -> bool:
        return bool(self.predicate(candidate))


def _evidence_constraint(record: EvidenceRecord) -> CompiledConstraint | None:
    field_name = FIELD_MAP.get(record.property_name)
    if field_name is None:
        return None
    allowed = _allowed_values(record.value, record.property_name)
    constraint_id = f"EVIDENCE_EQ::{record.property_name}"
    trace = ConstraintTrace(
        constraint_id=constraint_id,
        property_name=record.property_name,
        expected=list(allowed) if len(allowed) > 1 else allowed[0],
        field_name=field_name,
        rationale=f"Hard {record.status.value} evidence must match candidate field; {record.rationale}",
        source_locator=record.source_locator,
    )
    return CompiledConstraint(trace, lambda c: c.field_value(field_name) in allowed)


def _structural_constraints() -> list[CompiledConstraint]:
    return [
        CompiledConstraint(
            ConstraintTrace(
                "PROTO::IKE_AEAD_NO_SEPARATE_INTEGRITY",
                "ike.proposal_consistency",
                "AUTH_NONE for AEAD; non-NONE for non-AEAD",
                None,
                "IKE AEAD proposals do not use a separate integrity transform; non-AEAD encryption requires integrity in this catalogue",
                "RFC 7296 Section 3.3; RFC 8247",
            ),
            lambda c: (is_aead(c.ike_encryption) and c.ike_integrity == "AUTH_NONE")
            or (not is_aead(c.ike_encryption) and c.ike_integrity != "AUTH_NONE"),
        ),
        CompiledConstraint(
            ConstraintTrace(
                "PROTO::ESP_AEAD_NO_SEPARATE_INTEGRITY",
                "child.proposal_consistency",
                "AUTH_NONE for AEAD; non-NONE for non-AEAD",
                None,
                "ESP AEAD uses combined integrity; non-AEAD encryption requires an integrity algorithm in the reference catalogue",
                "RFC 8221 Sections 4-5",
            ),
            lambda c: (is_aead(c.child_encryption) and c.child_integrity == "AUTH_NONE")
            or (not is_aead(c.child_encryption) and c.child_integrity != "AUTH_NONE"),
        ),
        CompiledConstraint(
            ConstraintTrace(
                "PROTO::IKEV1_LEGACY_TAG",
                "ike.version",
                "legacy tag when IKEV1",
                None,
                "The reference catalogue marks IKEv1 scenarios as deliberately legacy",
                "RFC 9395",
            ),
            lambda c: c.ike_version != "IKEV1" or "legacy" in c.tags,
        ),
    ]


def compile_constraints(ledger: EvidenceLedger) -> list[CompiledConstraint]:
    constraints = _structural_constraints()
    seen: set[tuple[str, str]] = set()
    for record in ledger.hard_records():
        key = (record.property_name, repr(record.value))
        if key in seen:
            continue
        seen.add(key)
        compiled = _evidence_constraint(record)
        if compiled is not None:
            constraints.append(compiled)
    return constraints
