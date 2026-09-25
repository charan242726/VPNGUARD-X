#!/usr/bin/env python3
"""Validate repository-wide assurance and reproducibility invariants."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cgii import load_catalogue
from cyber_range.range import _canonical_properties, load_scenarios
from experiments.build_dataset import _match_candidates
from observability import load_observability_matrix
from policy import PolicyEngine


REQUIRED_FILES = [
    "docs/VPNGUARD_X_Technical_Specification.md",
    "docs/Novelty_and_Literature_Gap.md",
    "docs/CGII_Algorithm_Specification.md",
    "docs/Experiment_and_Evaluation_Plan.md",
    "data/IPsec_Observability_Matrix.csv",
    "data/CyberRange_Scenario_Matrix.csv",
    "docs/Standards_Rulebook.md",
]
REQUIRED_DIRECTORIES = [
    "cyber_range", "parser", "features", "models", "cgii", "calibration", "policy",
    "risk", "remediation", "api", "dashboard", "experiments", "tests", "configs", "docs",
]
VALID_STATUSES = {"OBSERVED", "DETERMINISTICALLY_DERIVED", "AI_INFERRED", "UNKNOWN/UNOBSERVABLE"}


def validate() -> dict:
    problems: list[str] = []
    for relative in REQUIRED_FILES:
        if not (ROOT / relative).is_file():
            problems.append(f"missing required file: {relative}")
    for relative in REQUIRED_DIRECTORIES:
        if not (ROOT / relative).is_dir():
            problems.append(f"missing required directory: {relative}")

    try:
        observability = load_observability_matrix()
        statuses = {rule.passive_status for rule in observability.values()}
        if not statuses <= VALID_STATUSES:
            problems.append(f"invalid observability statuses: {sorted(statuses - VALID_STATUSES)}")
    except Exception as exc:
        observability = {}
        problems.append(f"observability matrix invalid: {exc}")

    try:
        catalogue = load_catalogue(ROOT / "configs/candidate_catalogue.yaml")
    except Exception as exc:
        catalogue = None
        problems.append(f"candidate catalogue invalid: {exc}")

    try:
        policy = PolicyEngine.from_yaml(ROOT / "configs/policy_rules.yaml")
        for rule in policy.rules:
            if not all((rule.source_id, rule.source_section, rule.rationale, rule.remediation, rule.last_reviewed)):
                problems.append(f"policy rule lacks provenance: {rule.rule_id}")
    except Exception as exc:
        policy = None
        problems.append(f"policy configuration invalid: {exc}")

    enabled_scenarios = 0
    if catalogue is not None:
        for scenario_id, row in load_scenarios().items():
            if row["enabled"].lower() != "true":
                continue
            enabled_scenarios += 1
            matches = _match_candidates(_canonical_properties(row), catalogue)
            if len(matches) != 1:
                problems.append(f"enabled scenario {scenario_id} maps to {len(matches)} candidates: {matches}")

    application_config = ROOT / "configs/application_classes.yaml"
    if "UNKNOWN" not in application_config.read_text(encoding="utf-8"):
        problems.append("application class configuration lacks UNKNOWN")

    return {
        "valid": not problems,
        "problems": problems,
        "counts": {
            "observability_properties": len(observability),
            "candidate_configurations": len(catalogue.candidates) if catalogue else 0,
            "policy_rules": len(policy.rules) if policy else 0,
            "enabled_scenarios": enabled_scenarios,
        },
        "empirical_results": "TBD — requires experiment",
    }


def main() -> int:
    result = validate()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
