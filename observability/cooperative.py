"""Authorized strongSwan/VICI and Linux XFRM telemetry adapters.

These parsers intentionally extract a conservative subset.  Raw telemetry is
retained by the caller for audit; unknown syntax is not guessed.
"""

from __future__ import annotations

import re
from typing import Any

from common.evidence import EvidenceLedger, EvidenceRecord, EvidenceStatus


VICI_ENCRYPTION_NAMES = {
    "AES_CBC": "ENCR_AES_CBC",
    "AES_CTR": "ENCR_AES_CTR",
    "AES_GCM_8": "ENCR_AES_GCM_8",
    "AES_GCM_12": "ENCR_AES_GCM_12",
    "AES_GCM_16": "ENCR_AES_GCM_16",
    "CHACHA20_POLY1305": "ENCR_CHACHA20_POLY1305",
    "3DES": "ENCR_3DES",
    "DES": "ENCR_DES",
    "NULL": "ENCR_NULL",
}
VICI_INTEGRITY_NAMES = {
    "HMAC_MD5_96": "AUTH_HMAC_MD5_96",
    "HMAC_SHA1_96": "AUTH_HMAC_SHA1_96",
    "HMAC_SHA2_256_128": "AUTH_HMAC_SHA2_256_128",
    "HMAC_SHA2_384_192": "AUTH_HMAC_SHA2_384_192",
    "HMAC_SHA2_512_256": "AUTH_HMAC_SHA2_512_256",
    "NONE": "AUTH_NONE",
}
VICI_KE_NAMES = {
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


def parse_swanctl_raw(text: str) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for key, value in re.findall(r"([A-Za-z][A-Za-z0-9-]*)=([^\s{}]+|\[[^\]]*\])", text):
        result.setdefault(key, []).append(value.strip("[]"))
    return result


def _section_body(text: str, section_name: str) -> tuple[str | None, int | None, int | None]:
    """Return a brace-balanced VICI section without guessing malformed input."""
    match = re.search(rf"\b{re.escape(section_name)}\s*\{{", text)
    if not match:
        return None, None, None
    opening = text.find("{", match.start())
    depth = 0
    for index in range(opening, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[opening + 1 : index], match.start(), index + 1
    return None, None, None


def _one(values: list[str] | None) -> str | None:
    if not values:
        return None
    unique = sorted(set(values))
    return unique[0] if len(unique) == 1 else None


def _normalized_encryption(fields: dict[str, list[str]]) -> str | None:
    raw = _one(fields.get("encr-alg"))
    if raw is None:
        return None
    base = VICI_ENCRYPTION_NAMES.get(raw.upper())
    key_size = _one(fields.get("encr-keysize"))
    if base and key_size and key_size.isdigit() and base not in {
        "ENCR_3DES", "ENCR_DES", "ENCR_NULL", "ENCR_CHACHA20_POLY1305"
    }:
        return f"{base}_{key_size}"
    return base


def _normalized_integrity(fields: dict[str, list[str]]) -> str | None:
    value = _one(fields.get("integ-alg"))
    return VICI_INTEGRITY_NAMES.get(value.upper()) if value else None


def _normalized_ke(fields: dict[str, list[str]]) -> int | None:
    value = _one(fields.get("dh-group"))
    if value is None:
        return None
    return VICI_KE_NAMES.get(value.upper(), int(value) if value.isdigit() else None)


def parse_xfrm_state(text: str) -> list[dict[str, Any]]:
    states: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        match = re.match(r"src (\S+) dst (\S+)", line)
        if match:
            if current:
                states.append(current)
            current = {"source": match.group(1), "destination": match.group(2)}
            continue
        if current is None:
            continue
        match = re.search(r"proto (esp|ah) spi (0x[0-9a-fA-F]+).*mode (tunnel|transport)", line)
        if match:
            current.update(protocol=match.group(1).upper(), spi=match.group(2).lower(), mode=match.group(3).upper())
        # The SA header reports ``replay-window N seq ...``.  Do not treat
        # the later statistics counter (``replay-window 0 replay ...``) as
        # configuration: it is a count of rejected packets, not the window.
        match = re.match(r"replay-window\s+(\d+)\s+seq\b", line)
        if match:
            current["legacy_replay_window"] = int(match.group(1))
        # iproute2 prints the effective extended replay bitmap as
        # ``replay_window`` inside an anti-replay/ESN context.  It may coexist
        # with a legacy ``replay-window 0`` line, so the two forms must not
        # overwrite each other.
        match = re.search(r"\breplay_window\s+(\d+)", line)
        if match:
            current["extended_replay_window"] = int(match.group(1))
        match = re.match(r"(aead|auth-trunc|auth|enc)\s+(\S+).*?(\d+)?$", line)
        if match:
            current.setdefault("algorithms", []).append({"kind": match.group(1), "name": match.group(2), "key_bits": int(match.group(3)) if match.group(3) else None})
    if current:
        states.append(current)
    return states


def _observed(name: str, value: Any, source: str, rationale: str) -> EvidenceRecord:
    return EvidenceRecord(name, value, EvidenceStatus.OBSERVED, source, rationale, source)


def cooperative_evidence_from_json(data: dict[str, Any], source: str = "SCENARIO_GROUND_TRUTH") -> EvidenceLedger:
    """Convert normalized, authorized telemetry to evidence.

    Accepted keys use canonical evidence property names.  Secrets and raw keys
    are rejected by name as a defense-in-depth measure.
    """
    forbidden = {"key", "keys", "secret", "secrets", "psk", "private_key", "key_material", "session_key"}

    def contains_forbidden_key(value: Any) -> bool:
        if isinstance(value, dict):
            for key, nested in value.items():
                lowered = str(key).lower()
                if lowered in forbidden or "secret" in lowered or lowered.endswith("_key") or "key_material" in lowered:
                    return True
                if contains_forbidden_key(nested):
                    return True
        elif isinstance(value, (list, tuple)):
            return any(contains_forbidden_key(item) for item in value)
        return False

    if contains_forbidden_key(data):
        raise ValueError("secret/key material must not enter cooperative evidence")
    ledger = EvidenceLedger()
    for property_name, value in data.items():
        if value is None:
            continue
        ledger.add(_observed(property_name, value, source, "Authorized endpoint/scenario telemetry supplied this value"))
    return ledger


def cooperative_evidence_from_swanctl(text: str) -> EvidenceLedger:
    child_body, child_start, child_end = _section_body(text, "child-sas")
    if child_body is None:
        # Retain compatibility with compact test/adapter records that contain
        # a single flat set of fields.
        ike_fields = parse_swanctl_raw(text)
        # A flat IKE record contains no CHILD-SA scope.
        child_fields = {}
    else:
        ike_text = text[: int(child_start)] + text[int(child_end) :]
        ike_fields = parse_swanctl_raw(ike_text)
        child_fields = parse_swanctl_raw(child_body)
    normalized: dict[str, Any] = {}
    version = _one(ike_fields.get("version"))
    if version:
        version = version.upper().replace("IKE", "").replace("V", "")
        if version in {"1", "2"}:
            normalized["ike.version"] = f"IKEV{version}"
    for field, property_name in (("local-id", "ike.local_identity"), ("remote-id", "ike.remote_identity")):
        if value := _one(ike_fields.get(field)):
            normalized[property_name] = value
    if value := _normalized_encryption(ike_fields):
        normalized["ike.selected_encryption"] = value
    if value := _normalized_integrity(ike_fields):
        normalized["ike.selected_integrity"] = value
    if value := _one(ike_fields.get("prf-alg")):
        normalized["ike.selected_prf"] = value.upper() if value.upper().startswith("PRF_") else value
    if value := _normalized_ke(ike_fields):
        normalized["ike.initial_ke_group"] = value

    if value := _one(child_fields.get("mode")):
        upper = value.upper()
        if upper in {"TUNNEL", "TRANSPORT"}:
            normalized["child.mode"] = upper
    if value := _normalized_encryption(child_fields):
        normalized["child.encryption"] = value
    if value := _normalized_integrity(child_fields):
        normalized["child.integrity"] = value
    if value := _normalized_ke(child_fields):
        normalized["child.pfs_group"] = value
    # An installed initial CHILD-SA may omit ``dh-group`` even when the
    # configured ESP proposal includes a DH group.  Its absence is therefore
    # not evidence that PFS is disabled; leave this field unknown unless the
    # endpoint explicitly supplies an active CHILD-SA DH group or a separate
    # policy/configuration connector establishes the configured setting.
    if value := _one(child_fields.get("esn")):
        lowered = value.lower()
        if lowered in {"0", "1", "no", "yes", "false", "true"}:
            normalized["child.esn"] = lowered in {"1", "yes", "true"}
    # VICI list-sas reports seconds remaining until expiry, not the configured
    # SA lifetime.  Keeping a distinct property prevents false deterministic
    # claims about the original configuration.
    if value := _one(child_fields.get("life-time")):
        if value.isdigit():
            normalized["sa.remaining_lifetime_seconds"] = int(value)
    return cooperative_evidence_from_json(normalized, source="STRONGSWAN_VICI")


def cooperative_evidence_from_xfrm(text: str) -> EvidenceLedger:
    states = parse_xfrm_state(text)
    normalized: dict[str, Any] = {}
    modes = sorted({state["mode"] for state in states if state.get("mode")})
    replay_windows = sorted({
        int(state.get("extended_replay_window", state.get("legacy_replay_window")))
        for state in states
        if state.get("extended_replay_window", state.get("legacy_replay_window")) is not None
    })
    protocols = sorted({state["protocol"] for state in states if state.get("protocol")})
    if modes:
        normalized["child.mode"] = modes[0] if len(modes) == 1 else modes
    if replay_windows:
        # A gateway has one outbound state (normally a zero receive window)
        # and one or more inbound states.  Report effective receive windows;
        # including the outbound zero would falsely make a protected SA look
        # ambiguous or disabled.
        effective_windows = [value for value in replay_windows if value > 0]
        normalized["child.anti_replay_enabled"] = bool(effective_windows)
        selected_windows = effective_windows or replay_windows
        normalized["child.replay_window_size"] = (
            selected_windows[0] if len(selected_windows) == 1 else selected_windows
        )
    if protocols:
        normalized["child.protocol"] = protocols[0] if len(protocols) == 1 else protocols
    normalized["endpoint.xfrm_state_count"] = len(states)
    return cooperative_evidence_from_json(normalized, source="LINUX_XFRM")
