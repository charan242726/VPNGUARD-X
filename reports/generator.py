"""Lossless JSON plus evidence-conscious Markdown reports."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _fmt(value: Any) -> str:
    if value is None:
        return "UNKNOWN/UNOBSERVABLE"
    if isinstance(value, float):
        return f"{value:.4f}"
    if isinstance(value, (dict, list)):
        return "`" + json.dumps(value, sort_keys=True) + "`"
    return str(value)


def _technical_markdown(data: dict[str, Any]) -> str:
    capture = data["capture"]
    cgii = data["cgii"]
    risk = data["risk"]
    lines = [
        "# VPNGUARD-X Technical Assessment",
        "",
        f"**Run ID:** `{data['run']['run_id']}`  ",
        f"**Mode:** `{data['mode']}`  ",
        f"**Capture SHA-256:** `{capture['sha256']}`  ",
        "**Empirical benchmark metrics:** TBD — requires experiment",
        "",
        "## Assurance summary",
        "",
        f"- CGII status: `{cgii['status']}`",
        f"- Inference status: `{cgii['inference_status']}`",
        f"- Feasible candidates: {cgii['feasible_candidate_count']} of {cgii['total_candidates']}",
        f"- Returned set: {len(cgii['prediction_set'])}; method `{cgii['prediction_set_method']}`; mass {_fmt(cgii['prediction_set_mass'])}",
        f"- Evidence completeness: {_fmt(cgii['evidence_completeness'])}",
        f"- Policy/candidate basis status: `{data['policy']['basis_status']}`",
        f"- Risk interval: [{_fmt(risk['minimum'])}, {_fmt(risk['maximum'])}] with basis `{risk['evidence_status']}` (policy loss, not compromise probability)",
        "",
        "## Evidence ledger",
        "",
        "| Property | Value | Status | Source | Rationale |",
        "|---|---|---|---|---|",
    ]
    for record in capture["evidence"]:
        rationale = str(record["rationale"]).replace("|", "\\|")
        lines.append(
            f"| `{record['property_name']}` | {_fmt(record['value'])} | `{record['status']}` | "
            f"`{record['source']}` | {rationale} |"
        )
    lines.extend([
        "",
        "## CGII candidate set",
        "",
        "| Candidate | Constrained probability |",
        "|---|---:|",
    ])
    for candidate_id in cgii["prediction_set"]:
        lines.append(f"| `{candidate_id}` | {cgii['posterior'].get(candidate_id, 0.0):.6f} |")
    lines.extend(["", "## Policy findings", "", "| Rule | Status | Severity | Source |", "|---|---|---|---|"])
    for finding in data["policy"]["findings"]:
        source = finding["source"]
        lines.append(
            f"| `{finding['rule_id']}` | `{finding['status']}` | {finding['severity']} | "
            f"{source['source_id']} {source['section']} |"
        )
    lines.extend([
        "",
        "## Threat matrix",
        "",
        "| Threat context | Severity | Evidence status | Assessment |",
        "|---|---|---|---|",
    ])
    for threat in data.get("threat_matrix", []):
        lines.append(
            f"| {threat['threat_context']} | {threat['severity']} | `{threat['status']}` | "
            f"`{threat['finding']}` |"
        )
    lines.extend([
        "",
        "Threat entries describe policy exposure only; they do not establish an exploit or compromise.",
    ])
    lines.extend([
        "",
        "## Counterfactual remediation",
        "",
        f"Status: `{data['remediation']['status']}` with basis `{data['remediation']['evidence_status']}`. Cost interval: "
        f"[{_fmt(data['remediation']['minimum_cost'])}, {_fmt(data['remediation']['maximum_cost'])}].",
        "",
        "Robust common changes are those shared by every minimum-cost alternative:",
        "",
    ])
    if data["remediation"]["robust_common_changes"]:
        for field_name, change in data["remediation"]["robust_common_changes"].items():
            lines.append(f"- `{field_name}` → `{change['to']}`")
    else:
        lines.append("- None established across all supported candidates; use the candidate-contingent JSON details.")
    lines.extend([
        "",
        "## Limitations",
        "",
        "Protected IKEv2/ESP contents were not decrypted. Hidden configuration fields remain inferred or unknown unless authorized cooperative telemetry supplied them. Possible violations are not detected vulnerabilities. Results are bounded by the versioned candidate catalogue and policy profile.",
        "",
    ])
    return "\n".join(lines)


def _executive_markdown(data: dict[str, Any]) -> str:
    cgii = data["cgii"]
    risk = data["risk"]
    summary = data["policy"]["summary"]
    return "\n".join(
        [
            "# VPNGUARD-X Executive Summary",
            "",
            f"Capture `{data['capture']['sha256'][:12]}…` was assessed in **{data['mode']}** mode.",
            "",
            f"The evidence supports **{len(cgii['prediction_set'])} candidate configuration(s)**. "
            f"The bounded policy-risk interval is **[{_fmt(risk['minimum'])}, {_fmt(risk['maximum'])}]**; "
            "this is a normalized policy-loss range, not a probability of compromise.",
            "",
            f"Policy findings: {summary['CERTAIN_VIOLATION']} certain, "
            f"{summary['POSSIBLE_VIOLATION']} possible, and {summary['NOT_EVALUABLE']} not evaluable.",
            "",
            "No protected VPN parameter was reported as observed without packet or authorized endpoint evidence. "
            "Configuration-specific recommendations are retained in the technical/JSON report when ambiguity remains.",
            "",
            "Empirical accuracy and benchmark results: **TBD — requires experiment**.",
            "",
        ]
    )


def write_reports(bundle: Any, output_directory: str | Path) -> dict[str, str]:
    selected = Path(output_directory)
    selected.mkdir(parents=True, exist_ok=True)
    data = bundle.to_dict() if hasattr(bundle, "to_dict") else dict(bundle)
    paths = {
        "json": selected / "assessment.json",
        "technical_markdown": selected / "technical_report.md",
        "executive_markdown": selected / "executive_report.md",
    }
    paths["json"].write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    paths["technical_markdown"].write_text(_technical_markdown(data), encoding="utf-8")
    paths["executive_markdown"].write_text(_executive_markdown(data), encoding="utf-8")
    return {name: str(path.resolve()) for name, path in paths.items()}
