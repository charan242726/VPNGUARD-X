"""PCAP and IPsec protocol parsing.

The analyzer import is lazy because the observability engine consumes parser
record types while the analyzer itself consumes the observability engine.
"""

from pathlib import Path
from typing import Any

from .pcap import PcapFormatError, read_pcap
from .live_capture import capture_live


def analyze_pcap(path: str | Path, *, max_packets: int | None = None) -> Any:
    from .analyzer import analyze_pcap as _analyze_pcap

    return _analyze_pcap(path, max_packets=max_packets)


__all__ = ["analyze_pcap", "capture_live", "read_pcap", "PcapFormatError"]
