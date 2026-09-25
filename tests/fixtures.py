"""Small synthetic classic-PCAP fixtures containing no real traffic."""

from __future__ import annotations

import ipaddress
import struct
from pathlib import Path


def _transform(transform_type: int, transform_id: int, *, key_length: int | None, more: bool) -> bytes:
    attributes = b"" if key_length is None else struct.pack("!HH", 0x800E, key_length)
    length = 8 + len(attributes)
    return struct.pack("!BBHBBH", 3 if more else 0, 0, length, transform_type, 0, transform_id) + attributes


def ike_sa_init(*, response: bool, initiator_spi: int = 0x1122334455667788, responder_spi: int = 0x8877665544332211) -> bytes:
    transforms = b"".join(
        [
            _transform(1, 12, key_length=256, more=True),
            _transform(2, 5, key_length=None, more=True),
            _transform(3, 12, key_length=None, more=True),
            _transform(4, 14, key_length=None, more=False),
        ]
    )
    proposal = struct.pack("!BBHBBBB", 0, 0, 8 + len(transforms), 1, 1, 0, 4) + transforms
    sa = struct.pack("!BBH", 34, 0, 4 + len(proposal)) + proposal
    ke_body = struct.pack("!HH", 14, 0) + bytes(range(16))
    ke = struct.pack("!BBH", 40, 0, 4 + len(ke_body)) + ke_body
    nonce_body = bytes(range(32))
    nonce = struct.pack("!BBH", 0, 0, 4 + len(nonce_body)) + nonce_body
    payload = sa + ke + nonce
    flags = 0x20 if response else 0x08
    header = struct.pack(
        "!QQBBBBII",
        initiator_spi,
        responder_spi if response else 0,
        33,
        0x20,
        34,
        flags,
        0,
        28 + len(payload),
    )
    return header + payload


def _ethernet(payload: bytes, ethertype: int = 0x0800) -> bytes:
    return bytes.fromhex("020000000002020000000001") + struct.pack("!H", ethertype) + payload


def _ipv4(payload: bytes, source: str, destination: str, protocol: int, identification: int) -> bytes:
    return struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(payload),
        identification,
        0,
        64,
        protocol,
        0,
        ipaddress.IPv4Address(source).packed,
        ipaddress.IPv4Address(destination).packed,
    ) + payload


def _udp(payload: bytes, source_port: int, destination_port: int) -> bytes:
    return struct.pack("!HHHH", source_port, destination_port, 8 + len(payload), 0) + payload


def synthetic_packets(*, natt: bool = False) -> list[bytes]:
    request_payload = ike_sa_init(response=False)
    response_payload = ike_sa_init(response=True)
    if natt:
        request_payload = b"\x00\x00\x00\x00" + request_payload
        response_payload = b"\x00\x00\x00\x00" + response_payload
        port = 4500
    else:
        port = 500
    request = _ethernet(_ipv4(_udp(request_payload, port, port), "192.0.2.10", "192.0.2.20", 17, 1))
    response = _ethernet(_ipv4(_udp(response_payload, port, port), "192.0.2.20", "192.0.2.10", 17, 2))
    esp_one = struct.pack("!II", 0xAABBCCDD, 1) + bytes(48)
    esp_three = struct.pack("!II", 0xAABBCCDD, 3) + bytes(80)
    if natt:
        packet_three = _ethernet(_ipv4(_udp(esp_one, 4500, 4500), "192.0.2.10", "192.0.2.20", 17, 3))
        packet_four = _ethernet(_ipv4(_udp(esp_three, 4500, 4500), "192.0.2.10", "192.0.2.20", 17, 4))
    else:
        packet_three = _ethernet(_ipv4(esp_one, "192.0.2.10", "192.0.2.20", 50, 3))
        packet_four = _ethernet(_ipv4(esp_three, "192.0.2.10", "192.0.2.20", 50, 4))
    return [request, response, packet_three, packet_four]


def write_synthetic_pcap(path: str | Path, *, natt: bool = False) -> Path:
    selected = Path(path)
    packets = synthetic_packets(natt=natt)
    blob = bytearray(b"\xd4\xc3\xb2\xa1")
    blob.extend(struct.pack("<HHiIII", 2, 4, 0, 0, 65535, 1))
    for index, packet in enumerate(packets):
        blob.extend(struct.pack("<IIII", 1_700_000_000 + index, index * 1000, len(packet), len(packet)))
        blob.extend(packet)
    selected.write_bytes(bytes(blob))
    return selected
