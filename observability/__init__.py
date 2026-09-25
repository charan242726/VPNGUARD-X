"""Executable observability and cooperative-validation engine."""

from .cooperative import (
    cooperative_evidence_from_json,
    cooperative_evidence_from_swanctl,
    cooperative_evidence_from_xfrm,
    parse_swanctl_raw,
    parse_xfrm_state,
)
from .engine import build_passive_evidence
from .local_gateway import collect_local_gateway_telemetry
from .matrix import ObservabilityRule, load_observability_matrix

__all__ = [
    "ObservabilityRule",
    "build_passive_evidence",
    "cooperative_evidence_from_json",
    "cooperative_evidence_from_swanctl",
    "cooperative_evidence_from_xfrm",
    "collect_local_gateway_telemetry",
    "load_observability_matrix",
    "parse_swanctl_raw",
    "parse_xfrm_state",
]
