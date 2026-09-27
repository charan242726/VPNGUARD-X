"""Dependency-free readers for classic libpcap and standard PCAPNG captures.

The PCAPNG implementation intentionally accepts only packet-bearing Enhanced
Packet Blocks and Simple Packet Blocks.  Unsupported blocks are skipped by
their declared length; malformed block lengths are rejected safely.
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Iterator

from .records import PcapPacket


class PcapFormatError(ValueError):
    pass


MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000.0),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000.0),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000.0),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000.0),
}

PCAPNG_SECTION_HEADER = b"\x0a\x0d\x0d\x0a"
PCAPNG_BYTE_ORDER_MAGIC = b"\x4d\x3c\x2b\x1a"
PCAPNG_IDB = 0x00000001
PCAPNG_SPB = 0x00000003
PCAPNG_EPB = 0x00000006


def _read_exact(handle, length: int, context: str) -> bytes:
    data = handle.read(length)
    if len(data) != length:
        raise PcapFormatError(f"truncated {context}")
    return data


def _read_pcapng(path: Path, *, max_packets: int | None = None) -> Iterator[PcapPacket]:
    """Yield packets from a standard PCAPNG file without external tooling."""
    with path.open("rb") as handle:
        interfaces: list[tuple[int, float]] = []  # (link type, timestamp units/sec)
        endian: str | None = None
        index = 0
        while max_packets is None or index < max_packets:
            type_bytes = handle.read(4)
            if not type_bytes:
                break
            if len(type_bytes) != 4:
                raise PcapFormatError("truncated PCAPNG block type")
            # A Section Header has endian-independent type bytes.  Its byte
            # order magic determines how the rest of that section is decoded.
            if type_bytes == PCAPNG_SECTION_HEADER:
                length_bytes = _read_exact(handle, 4, "PCAPNG section length")
                bom = _read_exact(handle, 4, "PCAPNG byte-order magic")
                if bom == PCAPNG_BYTE_ORDER_MAGIC:
                    endian = "<"
                elif bom == PCAPNG_BYTE_ORDER_MAGIC[::-1]:
                    endian = ">"
                else:
                    raise PcapFormatError("invalid PCAPNG byte-order magic")
                total_length = struct.unpack(endian + "I", length_bytes)[0]
                if total_length < 28 or total_length > 256 * 1024 * 1024:
                    raise PcapFormatError("invalid PCAPNG section length")
                remaining = total_length - 12
                body_tail = _read_exact(handle, remaining, "PCAPNG section body")
                if struct.unpack(endian + "I", body_tail[-4:])[0] != total_length:
                    raise PcapFormatError("PCAPNG section length mismatch")
                interfaces = []
                continue
            if endian is None:
                raise PcapFormatError("PCAPNG capture is missing a section header")
            block_type = struct.unpack(endian + "I", type_bytes)[0]
            total_length = struct.unpack(endian + "I", _read_exact(handle, 4, "PCAPNG block length"))[0]
            if total_length < 12 or total_length > 256 * 1024 * 1024 or total_length % 4:
                raise PcapFormatError("invalid PCAPNG block length")
            # Type and leading length have been consumed; retain both the
            # complete block body and trailing duplicated length for checking.
            payload = _read_exact(handle, total_length - 8, "PCAPNG block")
            if struct.unpack(endian + "I", payload[-4:])[0] != total_length:
                raise PcapFormatError("PCAPNG block length mismatch")
            body = payload[:-4]
            if block_type == PCAPNG_IDB:
                if len(body) < 8:
                    raise PcapFormatError("truncated PCAPNG interface description")
                link_type = struct.unpack(endian + "H", body[:2])[0]
                resolution = 1_000_000.0  # PCAPNG default: microseconds
                offset = 8
                while offset + 4 <= len(body):
                    option_type, option_length = struct.unpack(endian + "HH", body[offset:offset + 4])
                    offset += 4
                    padded = (option_length + 3) & ~3
                    if offset + padded > len(body):
                        raise PcapFormatError("truncated PCAPNG interface option")
                    value = body[offset:offset + option_length]
                    offset += padded
                    if option_type == 0:
                        break
                    if option_type == 9 and len(value) == 1:  # if_tsresol
                        raw = value[0]
                        resolution = (2 ** (raw & 0x7F)) if raw & 0x80 else (10 ** raw)
                interfaces.append((link_type, float(resolution)))
            elif block_type == PCAPNG_EPB:
                if len(body) < 20:
                    raise PcapFormatError("truncated PCAPNG enhanced packet")
                interface_id, ts_high, ts_low, captured_length, original_length = struct.unpack(endian + "IIIII", body[:20])
                if interface_id >= len(interfaces):
                    raise PcapFormatError("PCAPNG packet references unknown interface")
                if captured_length > 256 * 1024 * 1024:
                    raise PcapFormatError(f"unreasonable packet length {captured_length} at index {index}")
                padded = (captured_length + 3) & ~3
                if len(body) < 20 + padded:
                    raise PcapFormatError(f"truncated PCAPNG packet bytes at index {index}")
                link_type, resolution = interfaces[interface_id]
                yield PcapPacket(index=index, timestamp=((ts_high << 32) | ts_low) / resolution, captured_length=captured_length, original_length=original_length, data=body[20:20 + captured_length], link_type=link_type)
                index += 1
            elif block_type == PCAPNG_SPB:
                if not interfaces or len(body) < 4:
                    raise PcapFormatError("PCAPNG simple packet has no interface description")
                original_length = struct.unpack(endian + "I", body[:4])[0]
                data = body[4:]
                captured_length = min(original_length, len(data))
                link_type, _resolution = interfaces[0]
                yield PcapPacket(index=index, timestamp=0.0, captured_length=captured_length, original_length=original_length, data=data[:captured_length], link_type=link_type)
                index += 1


def read_pcap(path: str | Path, *, max_packets: int | None = None) -> Iterator[PcapPacket]:
    path = Path(path)
    with path.open("rb") as handle:
        magic = handle.read(4)
        if magic == PCAPNG_SECTION_HEADER:
            yield from _read_pcapng(path, max_packets=max_packets)
            return
        if magic not in MAGIC:
            raise PcapFormatError(f"unsupported PCAP magic {magic.hex()}")
        endian, fraction_scale = MAGIC[magic]
        rest = handle.read(20)
        if len(rest) != 20:
            raise PcapFormatError("truncated PCAP global header")
        version_major, version_minor, _zone, _sigfigs, _snaplen, link_type = struct.unpack(
            endian + "HHiIII", rest
        )
        if (version_major, version_minor) != (2, 4):
            raise PcapFormatError(f"unsupported PCAP version {version_major}.{version_minor}")

        index = 0
        while max_packets is None or index < max_packets:
            header = handle.read(16)
            if not header:
                break
            if len(header) != 16:
                raise PcapFormatError(f"truncated packet header at index {index}")
            ts_sec, ts_fraction, captured_length, original_length = struct.unpack(endian + "IIII", header)
            if captured_length > 256 * 1024 * 1024:
                raise PcapFormatError(f"unreasonable packet length {captured_length} at index {index}")
            data = handle.read(captured_length)
            if len(data) != captured_length:
                raise PcapFormatError(f"truncated packet bytes at index {index}")
            yield PcapPacket(
                index=index,
                timestamp=ts_sec + ts_fraction / fraction_scale,
                captured_length=captured_length,
                original_length=original_length,
                data=data,
                link_type=link_type,
            )
            index += 1
