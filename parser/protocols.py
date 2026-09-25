"""Ethernet/IP/UDP/IKE/ESP parsing with conservative failure behavior."""

from __future__ import annotations

import ipaddress
import struct
from typing import Any

from .records import ESPHeader, IKEHeader, IKEPayload, PacketRecord, PcapPacket


DLT_EN10MB = 1
DLT_RAW = 101
DLT_LINUX_SLL = 113
DLT_LINUX_SLL2 = 276

IKE_PAYLOAD_NAMES = {
    33: "SA",
    34: "KE",
    35: "IDi",
    36: "IDr",
    37: "CERT",
    38: "CERTREQ",
    39: "AUTH",
    40: "NONCE",
    41: "NOTIFY",
    42: "DELETE",
    43: "VENDOR",
    44: "TSi",
    45: "TSr",
    46: "SK",
    47: "CP",
    48: "EAP",
    53: "SKF",
}

IKE_EXCHANGE_NAMES = {
    34: "IKE_SA_INIT",
    35: "IKE_AUTH",
    36: "CREATE_CHILD_SA",
    37: "INFORMATIONAL",
    43: "IKE_INTERMEDIATE",
    44: "IKE_FOLLOWUP_KE",
}

TRANSFORM_TYPE_NAMES = {1: "ENCR", 2: "PRF", 3: "INTEG", 4: "KE", 5: "ESN"}
TRANSFORM_NAMES = {
    1: {
        2: "ENCR_DES",
        3: "ENCR_3DES",
        11: "ENCR_NULL",
        12: "ENCR_AES_CBC",
        13: "ENCR_AES_CTR",
        18: "ENCR_AES_GCM_8",
        19: "ENCR_AES_GCM_12",
        20: "ENCR_AES_GCM_16",
        28: "ENCR_CHACHA20_POLY1305",
    },
    2: {
        1: "PRF_HMAC_MD5",
        2: "PRF_HMAC_SHA1",
        4: "PRF_AES128_XCBC",
        5: "PRF_HMAC_SHA2_256",
        6: "PRF_HMAC_SHA2_384",
        7: "PRF_HMAC_SHA2_512",
    },
    3: {
        0: "AUTH_NONE",
        1: "AUTH_HMAC_MD5_96",
        2: "AUTH_HMAC_SHA1_96",
        5: "AUTH_AES_XCBC_96",
        12: "AUTH_HMAC_SHA2_256_128",
        13: "AUTH_HMAC_SHA2_384_192",
        14: "AUTH_HMAC_SHA2_512_256",
    },
    4: {
        1: "MODP_768",
        2: "MODP_1024",
        5: "MODP_1536",
        14: "MODP_2048",
        15: "MODP_3072",
        16: "MODP_4096",
        17: "MODP_6144",
        18: "MODP_8192",
        19: "ECP_256",
        20: "ECP_384",
        21: "ECP_521",
        31: "CURVE_25519",
        32: "CURVE_448",
    },
    5: {0: "NO_ESN", 1: "ESN"},
}


def canonical_transform_name(transform_type: int, transform_id: int, key_length: int | None) -> str:
    name = TRANSFORM_NAMES.get(transform_type, {}).get(
        transform_id, f"{TRANSFORM_TYPE_NAMES.get(transform_type, 'TYPE'+str(transform_type))}_{transform_id}"
    )
    if key_length and transform_type == 1:
        return f"{name}_{key_length}"
    return name


def _link_payload(packet: PcapPacket, errors: list[str]) -> tuple[int, int] | None:
    data = packet.data
    if packet.link_type == DLT_EN10MB:
        if len(data) < 14:
            errors.append("TRUNCATED_ETHERNET")
            return None
        ethertype = struct.unpack("!H", data[12:14])[0]
        offset = 14
        while ethertype in {0x8100, 0x88A8}:
            if len(data) < offset + 4:
                errors.append("TRUNCATED_VLAN")
                return None
            ethertype = struct.unpack("!H", data[offset + 2 : offset + 4])[0]
            offset += 4
        return ethertype, offset
    if packet.link_type == DLT_RAW:
        if not data:
            errors.append("EMPTY_RAW_IP")
            return None
        version = data[0] >> 4
        return (0x0800 if version == 4 else 0x86DD if version == 6 else 0), 0
    if packet.link_type == DLT_LINUX_SLL:
        if len(data) < 16:
            errors.append("TRUNCATED_LINUX_SLL")
            return None
        return struct.unpack("!H", data[14:16])[0], 16
    if packet.link_type == DLT_LINUX_SLL2:
        if len(data) < 20:
            errors.append("TRUNCATED_LINUX_SLL2")
            return None
        return struct.unpack("!H", data[0:2])[0], 20
    errors.append(f"UNSUPPORTED_LINKTYPE_{packet.link_type}")
    return None


def _decode_ipv4(data: bytes, offset: int, record: PacketRecord) -> tuple[int, int, int] | None:
    if len(data) < offset + 20:
        record.errors.append("TRUNCATED_IPV4")
        return None
    version_ihl = data[offset]
    if version_ihl >> 4 != 4:
        record.errors.append("INVALID_IPV4_VERSION")
        return None
    ihl = (version_ihl & 0x0F) * 4
    if ihl < 20 or len(data) < offset + ihl:
        record.errors.append("INVALID_IPV4_IHL")
        return None
    total_length = struct.unpack("!H", data[offset + 2 : offset + 4])[0]
    protocol = data[offset + 9]
    record.ip_version = 4
    record.source_ip = str(ipaddress.IPv4Address(data[offset + 12 : offset + 16]))
    record.destination_ip = str(ipaddress.IPv4Address(data[offset + 16 : offset + 20]))
    record.ip_protocol = protocol
    fragment_field = struct.unpack("!H", data[offset + 6 : offset + 8])[0]
    fragment_offset = fragment_field & 0x1FFF
    payload_offset = offset + ihl
    payload_end = min(len(data), offset + total_length) if total_length else len(data)
    if total_length and offset + total_length > len(data):
        record.errors.append("TRUNCATED_IPV4_PAYLOAD")
    if fragment_offset:
        record.packet_kind = "IP_FRAGMENT_NONINITIAL"
        return None
    return protocol, payload_offset, payload_end


def _decode_ipv6(data: bytes, offset: int, record: PacketRecord) -> tuple[int, int, int] | None:
    if len(data) < offset + 40:
        record.errors.append("TRUNCATED_IPV6")
        return None
    if data[offset] >> 4 != 6:
        record.errors.append("INVALID_IPV6_VERSION")
        return None
    payload_length = struct.unpack("!H", data[offset + 4 : offset + 6])[0]
    next_header = data[offset + 6]
    record.ip_version = 6
    record.source_ip = str(ipaddress.IPv6Address(data[offset + 8 : offset + 24]))
    record.destination_ip = str(ipaddress.IPv6Address(data[offset + 24 : offset + 40]))
    cursor = offset + 40
    payload_end = min(len(data), cursor + payload_length) if payload_length else len(data)
    if payload_length and cursor + payload_length > len(data):
        record.errors.append("TRUNCATED_IPV6_PAYLOAD")

    extension_count = 0
    while next_header in {0, 43, 44, 51, 60}:
        extension_count += 1
        if extension_count > 12:
            record.errors.append("IPV6_EXTENSION_LIMIT")
            return None
        if next_header == 44:
            if cursor + 8 > payload_end:
                record.errors.append("TRUNCATED_IPV6_FRAGMENT")
                return None
            following = data[cursor]
            fragment_field = struct.unpack("!H", data[cursor + 2 : cursor + 4])[0]
            if fragment_field & 0xFFF8:
                record.packet_kind = "IP_FRAGMENT_NONINITIAL"
                return None
            next_header, cursor = following, cursor + 8
        elif next_header == 51:
            if cursor + 2 > payload_end:
                record.errors.append("TRUNCATED_AH")
                return None
            following = data[cursor]
            length = (data[cursor + 1] + 2) * 4
            next_header, cursor = following, cursor + length
        else:
            if cursor + 2 > payload_end:
                record.errors.append("TRUNCATED_IPV6_EXTENSION")
                return None
            following = data[cursor]
            length = (data[cursor + 1] + 1) * 8
            next_header, cursor = following, cursor + length
        if cursor > payload_end:
            record.errors.append("INVALID_IPV6_EXTENSION_LENGTH")
            return None
    record.ip_protocol = next_header
    return next_header, cursor, payload_end


def _parse_attributes(blob: bytes) -> dict[int, int | bytes]:
    attrs: dict[int, int | bytes] = {}
    cursor = 0
    while cursor + 4 <= len(blob):
        raw_type, raw_value = struct.unpack("!HH", blob[cursor : cursor + 4])
        attr_type = raw_type & 0x7FFF
        if raw_type & 0x8000:
            attrs[attr_type] = raw_value
            cursor += 4
        else:
            length = raw_value
            if length < 4 or cursor + length > len(blob):
                break
            attrs[attr_type] = blob[cursor + 4 : cursor + length]
            cursor += length
    return attrs


def _parse_sa(body: bytes) -> dict[str, Any]:
    proposals: list[dict[str, Any]] = []
    cursor = 0
    while cursor + 8 <= len(body):
        last, _reserved, proposal_length, number, protocol_id, spi_size, _num = struct.unpack(
            "!BBHBBBB", body[cursor : cursor + 8]
        )
        if proposal_length < 8 or cursor + proposal_length > len(body):
            break
        spi_start = cursor + 8
        spi_end = spi_start + spi_size
        if spi_end > cursor + proposal_length:
            break
        spi = body[spi_start:spi_end]
        transforms: list[dict[str, Any]] = []
        t_cursor = spi_end
        while t_cursor + 8 <= cursor + proposal_length:
            t_last, _tres, t_len, t_type, _tres2, t_id = struct.unpack(
                "!BBHBBH", body[t_cursor : t_cursor + 8]
            )
            if t_len < 8 or t_cursor + t_len > cursor + proposal_length:
                break
            attrs = _parse_attributes(body[t_cursor + 8 : t_cursor + t_len])
            key_length = attrs.get(14)
            if not isinstance(key_length, int):
                key_length = None
            transforms.append(
                {
                    "type": t_type,
                    "type_name": TRANSFORM_TYPE_NAMES.get(t_type, f"TYPE_{t_type}"),
                    "id": t_id,
                    "key_length": key_length,
                    "name": canonical_transform_name(t_type, t_id, key_length),
                }
            )
            t_cursor += t_len
            if t_last == 0:
                break
        proposals.append(
            {
                "number": number,
                "protocol_id": protocol_id,
                "spi_hex": spi.hex(),
                "transforms": transforms,
            }
        )
        cursor += proposal_length
        if last == 0:
            break
    return {"proposals": proposals}


def _parse_ike_payload(payload_type: int, body: bytes) -> dict[str, Any]:
    if payload_type == 33:
        return _parse_sa(body)
    if payload_type == 34 and len(body) >= 4:
        group, _reserved = struct.unpack("!HH", body[:4])
        return {"ke_group": group, "ke_name": TRANSFORM_NAMES[4].get(group, f"KE_{group}"), "data_length": len(body) - 4}
    if payload_type == 40:
        return {"nonce_length": len(body)}
    if payload_type == 41 and len(body) >= 4:
        protocol_id, spi_size, notify_type = struct.unpack("!BBH", body[:4])
        spi = body[4 : 4 + spi_size]
        data = body[4 + spi_size :]
        return {
            "protocol_id": protocol_id,
            "notify_type": notify_type,
            "spi_hex": spi.hex(),
            "data_hex": data.hex(),
            "data_length": len(data),
        }
    if payload_type in {46, 53}:
        return {"protected": True, "protected_length": len(body)}
    return {"body_length": len(body)}


def parse_ike(data: bytes) -> IKEHeader | None:
    if len(data) < 28:
        return None
    init_spi, resp_spi, next_payload, version, exchange, flags, message_id, length = struct.unpack(
        "!QQBBBBII", data[:28]
    )
    major, minor = version >> 4, version & 0x0F
    if major not in {1, 2} or length < 28:
        return None
    complete = length <= len(data)
    end = min(length, len(data))
    payloads: list[IKEPayload] = []
    if major == 2:
        current_type = next_payload
        cursor = 28
        seen = 0
        while current_type and cursor + 4 <= end and seen < 64:
            following, payload_flags, payload_length = struct.unpack("!BBH", data[cursor : cursor + 4])
            if payload_length < 4 or cursor + payload_length > end:
                complete = False
                break
            body = data[cursor + 4 : cursor + payload_length]
            payloads.append(
                IKEPayload(
                    payload_type=current_type,
                    next_payload=following,
                    critical=bool(payload_flags & 0x80),
                    length=payload_length,
                    parsed=_parse_ike_payload(current_type, body),
                )
            )
            cursor += payload_length
            seen += 1
            if current_type in {46, 53}:
                break
            current_type = following
        if seen >= 64:
            complete = False
    return IKEHeader(
        initiator_spi=init_spi,
        responder_spi=resp_spi,
        next_payload=next_payload,
        major_version=major,
        minor_version=minor,
        exchange_type=exchange,
        flags=flags,
        message_id=message_id,
        length=length,
        is_response=bool(flags & 0x20),
        from_initiator=bool(flags & 0x08),
        payloads=tuple(payloads),
        complete=complete,
    )


def _parse_esp(data: bytes, udp_encapsulated: bool) -> ESPHeader | None:
    if len(data) < 8:
        return None
    spi, sequence = struct.unpack("!II", data[:8])
    if spi == 0:
        return None
    return ESPHeader(spi=spi, sequence=sequence, udp_encapsulated=udp_encapsulated)


def decode_packet(packet: PcapPacket) -> PacketRecord:
    record = PacketRecord(
        index=packet.index,
        timestamp=packet.timestamp,
        captured_length=packet.captured_length,
        original_length=packet.original_length,
        link_type=packet.link_type,
    )
    link = _link_payload(packet, record.errors)
    if link is None:
        return record
    ethertype, network_offset = link
    if ethertype == 0x0800:
        decoded = _decode_ipv4(packet.data, network_offset, record)
    elif ethertype == 0x86DD:
        decoded = _decode_ipv6(packet.data, network_offset, record)
    else:
        record.packet_kind = "NON_IP"
        return record
    if decoded is None:
        return record
    protocol, transport_offset, transport_end = decoded
    if transport_offset > transport_end:
        record.errors.append("INVALID_TRANSPORT_OFFSET")
        return record
    transport = packet.data[transport_offset:transport_end]

    if protocol == 50:
        record.packet_kind = "ESP_NATIVE"
        record.transport_payload_length = len(transport)
        record.esp = _parse_esp(transport, False)
        if record.esp is None:
            record.errors.append("TRUNCATED_OR_ZERO_SPI_ESP")
        return record
    if protocol == 51:
        record.packet_kind = "AH"
        record.transport_payload_length = len(transport)
        return record
    if protocol != 17:
        record.packet_kind = "OTHER_IP"
        record.transport_payload_length = len(transport)
        return record
    if len(transport) < 8:
        record.packet_kind = "UDP_TRUNCATED"
        record.errors.append("TRUNCATED_UDP")
        return record

    source_port, destination_port, udp_length, _checksum = struct.unpack("!HHHH", transport[:8])
    record.source_port = source_port
    record.destination_port = destination_port
    udp_end = min(len(transport), udp_length) if udp_length >= 8 else len(transport)
    udp_payload = transport[8:udp_end]
    record.transport_payload_length = len(udp_payload)
    if udp_length and udp_length > len(transport):
        record.errors.append("TRUNCATED_UDP_PAYLOAD")

    ports = {source_port, destination_port}
    if 4500 in ports:
        if udp_payload == b"\xff":
            record.packet_kind = "NAT_KEEPALIVE"
            return record
        if len(udp_payload) >= 4 and udp_payload[:4] == b"\x00\x00\x00\x00":
            record.packet_kind = "IKE_NATT"
            record.ike = parse_ike(udp_payload[4:])
            if record.ike is None:
                record.packet_kind = "UDP_4500_UNKNOWN"
                record.errors.append("INVALID_IKE_AFTER_NON_ESP_MARKER")
            return record
        record.esp = _parse_esp(udp_payload, True)
        if record.esp is not None:
            record.packet_kind = "ESP_UDP"
        else:
            record.packet_kind = "UDP_4500_UNKNOWN"
            record.errors.append("INVALID_ESP_IN_UDP")
        return record
    if 500 in ports:
        record.ike = parse_ike(udp_payload)
        if record.ike is not None:
            record.packet_kind = "IKE"
        else:
            record.packet_kind = "UDP_500_UNKNOWN"
            record.errors.append("INVALID_IKE_ON_UDP_500")
        return record

    record.packet_kind = "UDP_OTHER"
    return record

