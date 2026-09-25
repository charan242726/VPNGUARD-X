"""Dependency-free reader for classic libpcap files.

PCAPNG is intentionally rejected with a clear error.  The documented external
conversion route uses a version-recorded TShark invocation.
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


def read_pcap(path: str | Path, *, max_packets: int | None = None) -> Iterator[PcapPacket]:
    path = Path(path)
    with path.open("rb") as handle:
        magic = handle.read(4)
        if magic == b"\x0a\x0d\x0d\x0a":
            raise PcapFormatError("PCAPNG is not supported by the core reader; convert with pinned TShark")
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

