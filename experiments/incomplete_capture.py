"""Deterministic offline packet dropping for incomplete-PCAP experiments."""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from common.provenance import sha256_file
from parser.protocols import decode_packet
from parser.records import PcapPacket


MAGIC_ENDIAN = {
    b"\xd4\xc3\xb2\xa1": "<",
    b"\xa1\xb2\xc3\xd4": ">",
    b"\x4d\x3c\xb2\xa1": "<",
    b"\xa1\xb2\x3c\x4d": ">",
}


def _records(data: bytes) -> tuple[str, int, list[tuple[bytes, PcapPacket]]]:
    if len(data) < 24 or data[:4] not in MAGIC_ENDIAN:
        raise ValueError("source must be a classic PCAP")
    endian = MAGIC_ENDIAN[data[:4]]
    link_type = struct.unpack(f"{endian}I", data[20:24])[0]
    nanosecond = data[:4] in {b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"}
    scale = 1_000_000_000.0 if nanosecond else 1_000_000.0
    cursor = 24
    output: list[tuple[bytes, PcapPacket]] = []
    index = 0
    while cursor < len(data):
        if cursor + 16 > len(data):
            raise ValueError("truncated PCAP record header")
        ts_sec, ts_fraction, captured_length, original_length = struct.unpack(f"{endian}IIII", data[cursor : cursor + 16])
        end = cursor + 16 + captured_length
        if end > len(data):
            raise ValueError("truncated PCAP record data")
        raw = data[cursor:end]
        output.append(
            (
                raw,
                PcapPacket(
                    index,
                    ts_sec + ts_fraction / scale,
                    captured_length,
                    original_length,
                    data[cursor + 16 : end],
                    link_type,
                ),
            )
        )
        cursor = end
        index += 1
    return endian, link_type, output


def thin_pcap(source: str | Path, destination: str | Path, *, loss_fraction: float, seed: int) -> dict:
    if not 0.0 <= loss_fraction < 1.0:
        raise ValueError("loss_fraction must be in [0, 1)")
    source_path = Path(source).resolve()
    destination_path = Path(destination).resolve()
    data = source_path.read_bytes()
    _, _, parsed_records = _records(data)
    records = [record for record, _ in parsed_records]
    rng = random.Random(seed)
    keep = [rng.random() >= loss_fraction for _ in records]
    if records and not any(keep):
        keep[rng.randrange(len(records))] = True
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    destination_path.write_bytes(data[:24] + b"".join(record for record, selected in zip(records, keep, strict=True) if selected))
    manifest = {
        "source_pcap": str(source_path),
        "source_sha256": sha256_file(source_path),
        "output_pcap": str(destination_path),
        "output_sha256": sha256_file(destination_path),
        "seed": seed,
        "requested_loss_fraction": loss_fraction,
        "input_packet_count": len(records),
        "output_packet_count": sum(keep),
        "realized_loss_fraction": 1.0 - sum(keep) / len(records) if records else 0.0,
        "method": "independent Bernoulli packet removal preserving order and record bytes",
    }
    manifest_path = destination_path.with_suffix(destination_path.suffix + ".loss.json")
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def filter_pcap(source: str | Path, destination: str | Path, *, variant: str) -> dict:
    """Apply a declared structural missing-capture transformation."""
    if variant not in {"REMOVE_IKE_SA_INIT", "MIDSTREAM_ESP_ONLY"}:
        raise ValueError("unsupported structural capture variant")
    source_path = Path(source).resolve()
    destination_path = Path(destination).resolve()
    data = source_path.read_bytes()
    _, _, parsed_records = _records(data)
    keep: list[bool] = []
    for _, packet in parsed_records:
        decoded = decode_packet(packet)
        if variant == "REMOVE_IKE_SA_INIT":
            keep.append(not (decoded.ike is not None and decoded.ike.exchange_type == 34))
        else:
            keep.append(decoded.esp is not None)
    if not any(keep):
        raise ValueError(f"capture transformation {variant} removed every packet")
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    destination_path.write_bytes(
        data[:24]
        + b"".join(raw for (raw, _), selected in zip(parsed_records, keep, strict=True) if selected)
    )
    manifest = {
        "source_pcap": str(source_path),
        "source_sha256": sha256_file(source_path),
        "output_pcap": str(destination_path),
        "output_sha256": sha256_file(destination_path),
        "variant": variant,
        "input_packet_count": len(parsed_records),
        "output_packet_count": sum(keep),
        "removed_packet_count": len(parsed_records) - sum(keep),
        "method": (
            "remove decoded IKE_SA_INIT request/response records"
            if variant == "REMOVE_IKE_SA_INIT"
            else "retain only records structurally decoded as ESP"
        ),
    }
    manifest_path = destination_path.with_suffix(destination_path.suffix + ".transform.json")
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--loss", required=True, type=float, choices=[0.1, 0.3, 0.5])
    parser.add_argument("--seed", required=True, type=int)
    args = parser.parse_args()
    print(json.dumps(thin_pcap(args.source, args.destination, loss_fraction=args.loss, seed=args.seed), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
