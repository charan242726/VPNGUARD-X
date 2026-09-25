"""Evidence-conscious JSON, Markdown, and human-readable PDF reports."""

from __future__ import annotations

import json
from html import escape
from pathlib import Path
from typing import Any


def _fmt(value: Any) -> str:
    if value is None:
        return "UNKNOWN / UNOBSERVABLE"
    if isinstance(value, float):
        return f"{value:.4f}"
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True)
    return str(value)


def _safe(value: Any) -> str:
    return escape(_fmt(value)).replace("\n", "<br/>")


def _short_hash(value: Any, length: int = 16) -> str:
    text = str(value or "—")
    return text if len(text) <= length else f"{text[:length]}…"


def _pdf_value(value: Any, limit: int = 220) -> str:
    """Keep PDF evidence readable; the JSON export retains lossless values."""
    if isinstance(value, list):
        return f"[{len(value)} item(s)] " + _short_hash(value[:8], limit)
    text = _fmt(value)
    return text if len(text) <= limit else f"{text[:limit]}… [full value in Evidence JSON]"


def _evidence_by_property(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {item["property_name"]: item for item in data["capture"].get("evidence", []) if item.get("property_name")}


def _evidence_value(evidence: dict[str, dict[str, Any]], property_name: str) -> tuple[Any, str, str]:
    item = evidence.get(property_name)
    if not item:
        return None, "UNKNOWN / UNOBSERVABLE", "No packet or authorized endpoint evidence"
    return item.get("value"), item.get("status", "UNKNOWN / UNOBSERVABLE"), item.get("source", "—")


def _risk_score(data: dict[str, Any]) -> int:
    risk = data.get("risk", {})
    minimum = float(risk.get("minimum") or 0)
    maximum = float(risk.get("maximum") or minimum)
    return max(0, min(100, round((1 - ((minimum + maximum) / 2)) * 100)))


def _risk_label(data: dict[str, Any]) -> str:
    maximum = float(data.get("risk", {}).get("maximum") or 0)
    if maximum >= 0.65:
        return "HIGH"
    if maximum >= 0.30:
        return "MODERATE"
    return "LOW"


def _recommendations(data: dict[str, Any]) -> list[dict[str, str]]:
    """Return only evidence-supported actions, never a generic crypto checklist."""
    items: list[dict[str, str]] = []
    seen: set[str] = set()
    for finding in data.get("policy", {}).get("findings", []):
        status = finding.get("status")
        remediation = finding.get("remediation")
        if status not in {"CERTAIN_VIOLATION", "POSSIBLE_VIOLATION"} or not remediation or remediation in seen:
            continue
        seen.add(remediation)
        certainty = "Required" if status == "CERTAIN_VIOLATION" else "Validate first"
        items.append({
            "priority": finding.get("severity", "MEDIUM"),
            "title": finding.get("rule_id", "Policy finding"),
            "action": remediation,
            "basis": f"{certainty}: {status.replace('_', ' ').lower()} based on {finding.get('basis_status', 'available')} evidence.",
        })
    robust = data.get("remediation", {}).get("robust_common_changes", {})
    for field, change in robust.items():
        action = f"Set {field.replace('_', ' ')} to {_fmt(change.get('to'))}."
        if action not in seen:
            seen.add(action)
            items.append({"priority": "HIGH", "title": "Robust configuration change", "action": action,
                          "basis": "This change is shared by every minimum-cost compliant alternative."})
    missing = ["child.pfs_group", "child.anti_replay_enabled", "child.replay_window_size", "sa.remaining_lifetime_seconds"]
    observed = _evidence_by_property(data)
    unavailable = [name for name in missing if not observed.get(name) or observed[name].get("value") is None]
    if unavailable:
        items.append({"priority": "MEDIUM", "title": "Complete endpoint assurance",
                      "action": "Connect approved read-only gateway telemetry before changing policy for hidden SA controls.",
                      "basis": "The capture cannot prove " + ", ".join(x.replace("_", " ") for x in unavailable) + "."})
    return items or [{"priority": "INFO", "title": "No corrective change established",
                      "action": "Retain the current policy and continue periodic evidence-backed review.",
                      "basis": "No certain or possible policy violation was established for the supported candidate set."}]


def _technical_markdown(data: dict[str, Any]) -> str:
    capture, cgii, risk = data["capture"], data["cgii"], data["risk"]
    lines = ["# VPNGUARD-X Technical Assessment", "", f"**Run ID:** `{data['run']['run_id']}`  ", f"**Mode:** `{data['mode']}`  ", f"**Capture SHA-256:** `{capture['sha256']}`  ", "**Empirical benchmark metrics:** TBD — requires experiment", "", "## Assurance summary", "", f"- Security posture: {_risk_score(data)}/100 ({_risk_label(data)})", f"- CGII status: `{cgii['status']}`; feasible candidates: {cgii['feasible_candidate_count']} of {cgii['total_candidates']}", f"- Evidence completeness: {_fmt(cgii['evidence_completeness'])}", f"- Risk interval: [{_fmt(risk['minimum'])}, {_fmt(risk['maximum'])}] (policy loss, not compromise probability)", "", "## Evidence ledger", "", "| Property | Value | Status | Source | Rationale |", "|---|---|---|---|---|"]
    for record in capture["evidence"]:
        lines.append(f"| `{record['property_name']}` | {_fmt(record['value'])} | `{record['status']}` | `{record['source']}` | {str(record['rationale']).replace('|', '\\|')} |")
    lines.extend(["", "## Policy findings", "", "| Rule | Status | Severity | Recommended action |", "|---|---|---|---|"])
    for finding in data["policy"]["findings"]:
        lines.append(f"| `{finding['rule_id']}` | `{finding['status']}` | {finding['severity']} | {_fmt(finding.get('remediation'))} |")
    lines.extend(["", "## Recommendations", ""])
    for item in _recommendations(data):
        lines.append(f"- **{item['priority']} — {item['title']}:** {item['action']} _{item['basis']}_")
    lines.extend(["", "## Limitations", "", "Protected IKEv2/ESP contents were not decrypted. Hidden configuration fields remain inferred or unknown unless authorized cooperative telemetry supplied them. Possible violations are not confirmed vulnerabilities. Results are bounded by the versioned candidate catalogue and policy profile.", ""])
    return "\n".join(lines)


def _executive_markdown(data: dict[str, Any]) -> str:
    cgii, risk, summary = data["cgii"], data["risk"], data["policy"]["summary"]
    return "\n".join(["# VPNGUARD-X Executive Summary", "", f"**Security posture:** {_risk_score(data)}/100 ({_risk_label(data)} policy exposure)", "", f"Capture `{data['capture']['sha256'][:12]}…` was assessed in **{data['mode']}** mode.", f"Evidence supports **{len(cgii['prediction_set'])} candidate configuration(s)**. The bounded policy-risk interval is **[{_fmt(risk['minimum'])}, {_fmt(risk['maximum'])}]**; this is normalized policy loss, not compromise probability.", "", f"Policy findings: {summary['CERTAIN_VIOLATION']} certain, {summary['POSSIBLE_VIOLATION']} possible, and {summary['NOT_EVALUABLE']} not evaluable.", "", "## Recommended next actions", "", *[f"- **{item['priority']}:** {item['action']}" for item in _recommendations(data)], "", "No protected VPN parameter is reported as observed without packet or authorized endpoint evidence. Empirical accuracy and benchmark results: **TBD — requires experiment**.", ""])


def _pdf_dependencies() -> dict[str, Any]:
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle, PageBreak
    except ImportError as error:  # pragma: no cover - guarded by declared dependency
        raise RuntimeError("PDF report support is unavailable. Re-run install.sh to install reportlab.") from error
    return locals()


def _pdf_theme() -> tuple[dict[str, Any], dict[str, Any]]:
    lib = _pdf_dependencies()
    colors, ParagraphStyle, getSampleStyleSheet = lib["colors"], lib["ParagraphStyle"], lib["getSampleStyleSheet"]
    styles = getSampleStyleSheet()
    palette = {"navy": colors.HexColor("#101D36"), "blue": colors.HexColor("#1769E0"), "ink": colors.HexColor("#1D2939"), "muted": colors.HexColor("#667085"), "line": colors.HexColor("#D0D5DD"), "soft": colors.HexColor("#F5F8FC")}
    styles.add(ParagraphStyle(name="VgxTitle", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=25, leading=30, textColor=palette["navy"], spaceAfter=8))
    styles.add(ParagraphStyle(name="VgxSubtitle", parent=styles["Normal"], fontName="Helvetica", fontSize=10, leading=15, textColor=palette["muted"], spaceAfter=12))
    styles.add(ParagraphStyle(name="VgxH1", parent=styles["Heading1"], fontName="Helvetica-Bold", fontSize=16, leading=21, textColor=palette["navy"], spaceBefore=12, spaceAfter=7))
    styles.add(ParagraphStyle(name="VgxH2", parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=11, leading=15, textColor=palette["blue"], spaceBefore=8, spaceAfter=5))
    styles.add(ParagraphStyle(name="VgxBody", parent=styles["BodyText"], fontName="Helvetica", fontSize=8.6, leading=12.5, textColor=palette["ink"], spaceAfter=5))
    styles.add(ParagraphStyle(name="VgxSmall", parent=styles["BodyText"], fontName="Helvetica", fontSize=7.1, leading=9.2, textColor=palette["muted"]))
    styles.add(ParagraphStyle(name="VgxCardValue", parent=styles["BodyText"], fontName="Helvetica-Bold", fontSize=17, leading=20, textColor=palette["navy"], alignment=1))
    styles.add(ParagraphStyle(name="VgxTable", parent=styles["BodyText"], fontName="Helvetica", fontSize=6.8, leading=8.5, textColor=palette["ink"]))
    styles.add(ParagraphStyle(name="VgxTableHead", parent=styles["BodyText"], fontName="Helvetica-Bold", fontSize=6.7, leading=8.2, textColor=colors.white))
    return lib, {"styles": styles, "palette": palette}


def _header_footer(canvas: Any, document: Any) -> None:
    canvas.saveState()
    canvas.setFillColorRGB(0.063, 0.114, 0.212)
    canvas.rect(0, document.pagesize[1] - 8, document.pagesize[0], 3, fill=1, stroke=0)
    canvas.setFont("Helvetica-Bold", 7)
    canvas.setFillColorRGB(0.4, 0.45, 0.53)
    canvas.drawString(document.leftMargin, 16, "VPNGUARD-X  •  Evidence-bounded IPsec assurance")
    canvas.drawRightString(document.pagesize[0] - document.rightMargin, 16, f"Page {document.page}")
    canvas.restoreState()


def _paragraph(lib: dict[str, Any], styles: dict[str, Any], text: Any, style: str = "VgxBody") -> Any:
    # Card values are constructed locally from numeric posture facts. All
    # evidence and user-supplied text remains escaped before PDF rendering.
    content = str(text) if style == "VgxCardValue" else _safe(text)
    return lib["Paragraph"](content, styles[style])


def _table(lib: dict[str, Any], theme: dict[str, Any], rows: list[list[Any]], widths: list[float], *, header: bool = True) -> Any:
    palette, styles = theme["palette"], theme["styles"]
    data = []
    for index, row in enumerate(rows):
        style = "VgxTableHead" if header and index == 0 else "VgxTable"
        data.append([_paragraph(lib, styles, value, style) for value in row])
    table = lib["Table"](data, colWidths=widths, repeatRows=1 if header else 0, hAlign="LEFT")
    commands = [("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5), ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4), ("GRID", (0, 0), (-1, -1), 0.25, palette["line"])]
    if header:
        commands.extend([("BACKGROUND", (0, 0), (-1, 0), palette["navy"]), ("TEXTCOLOR", (0, 0), (-1, 0), palette["soft"])])
    for index in range(1 if header else 0, len(rows)):
        if index % 2:
            commands.append(("BACKGROUND", (0, index), (-1, index), palette["soft"]))
    table.setStyle(lib["TableStyle"](commands))
    return table


def _cover(lib: dict[str, Any], theme: dict[str, Any], data: dict[str, Any], title: str, subtitle: str) -> list[Any]:
    styles, palette = theme["styles"], theme["palette"]
    capture, run = data["capture"], data["run"]
    score, label = _risk_score(data), _risk_label(data)
    cards = [[_paragraph(lib, styles, f"<b>{score}/100</b><br/><font size='7' color='#667085'>SECURITY POSTURE</font>", "VgxCardValue"), _paragraph(lib, styles, f"<b>{label}</b><br/><font size='7' color='#667085'>POLICY EXPOSURE</font>", "VgxCardValue"), _paragraph(lib, styles, f"<b>{capture.get('packet_count', 0):,}</b><br/><font size='7' color='#667085'>PACKETS INSPECTED</font>", "VgxCardValue")]]
    card = lib["Table"](cards, colWidths=[56 * lib["mm"], 56 * lib["mm"], 56 * lib["mm"]])
    card.setStyle(lib["TableStyle"]([("BACKGROUND", (0, 0), (-1, -1), palette["soft"]), ("BOX", (0, 0), (-1, -1), 0.5, palette["line"]), ("INNERGRID", (0, 0), (-1, -1), 0.5, palette["line"]), ("TOPPADDING", (0, 0), (-1, -1), 12), ("BOTTOMPADDING", (0, 0), (-1, -1), 12), ("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
    return [lib["Spacer"](1, 22 * lib["mm"]), _paragraph(lib, styles, "VPNGUARD-X / IPSEC ASSURANCE", "VgxH2"), _paragraph(lib, styles, title, "VgxTitle"), _paragraph(lib, styles, subtitle, "VgxSubtitle"), card, lib["Spacer"](1, 12 * lib["mm"]), _paragraph(lib, styles, "Assessment identity", "VgxH1"), _table(lib, theme, [["Run ID", run.get("run_id"), "Completed", run.get("completed_at_utc", "—")], ["Assessment mode", data.get("mode"), "Policy profile", run.get("profile_id", "—")], ["Capture SHA-256", capture.get("sha256", "—"), "Product version", run.get("product_version", "—")]], [28 * lib["mm"], 60 * lib["mm"], 28 * lib["mm"], 58 * lib["mm"]], header=False), lib["Spacer"](1, 9 * lib["mm"]), _paragraph(lib, styles, "Important interpretation", "VgxH2"), _paragraph(lib, styles, "This report measures policy exposure over evidence-supported IPsec configuration candidates. It is not a compromise determination. Encrypted content, secret material, and hidden endpoint-only SA fields are never represented as packet-observed facts.")]


def _executive_pdf(data: dict[str, Any], destination: Path) -> None:
    lib, theme = _pdf_theme()
    doc = lib["SimpleDocTemplate"](str(destination), pagesize=lib["A4"], leftMargin=17 * lib["mm"], rightMargin=17 * lib["mm"], topMargin=18 * lib["mm"], bottomMargin=18 * lib["mm"], title="VPNGUARD-X Executive Security Assessment")
    styles = theme["styles"]
    story = _cover(lib, theme, data, "Executive security assessment", "Decision-ready IPsec posture, exposure, and next actions")
    story += [lib["PageBreak"](), _paragraph(lib, styles, "Executive overview", "VgxH1")]
    cgii, policy, risk = data["cgii"], data["policy"], data["risk"]
    story.append(_table(lib, theme, [["Assessment area", "Result"], ["Configuration resolution", f"{len(cgii.get('prediction_set', []))} supported candidate(s) of {cgii.get('total_candidates', 0)}"], ["Evidence completeness", f"{float(cgii.get('evidence_completeness') or 0) * 100:.0f}%"], ["Policy-risk range", f"{float(risk.get('minimum') or 0) * 100:.1f}% – {float(risk.get('maximum') or 0) * 100:.1f}%"], ["Policy findings", f"{policy.get('summary', {}).get('CERTAIN_VIOLATION', 0)} certain; {policy.get('summary', {}).get('POSSIBLE_VIOLATION', 0)} possible; {policy.get('summary', {}).get('NOT_EVALUABLE', 0)} not evaluable"], ["AI traffic inference", f"{data.get('application', {}).get('label', 'UNKNOWN')} ({float(data.get('application', {}).get('max_probability') or 0) * 100:.0f}% model confidence)"]], [55 * lib["mm"], 119 * lib["mm"]]))
    evidence, summary_rows = _evidence_by_property(data), [["Property", "Value", "Evidence"]]
    for prop, label in [("ike.version", "IKE version"), ("ike.selected_encryption", "IKE encryption"), ("ike.selected_prf", "IKE PRF"), ("ike.initial_ke_group", "DH group"), ("child.mode", "IPsec mode"), ("child.pfs_group", "PFS"), ("child.anti_replay_enabled", "Replay protection")]:
        value, status, source = _evidence_value(evidence, prop)
        summary_rows.append([label, _fmt(value), f"{status.replace('_', ' ')} / {source}"])
    story += [_paragraph(lib, styles, "Observed and assured IPsec posture", "VgxH1"), _table(lib, theme, summary_rows, [42 * lib["mm"], 58 * lib["mm"], 74 * lib["mm"]]), _paragraph(lib, styles, "Prioritized recommendations", "VgxH1")]
    for item in _recommendations(data):
        story.append(_table(lib, theme, [[f"{item['priority']}  •  {item['title']}", item["action"]], ["Why this is recommended", item["basis"]]], [47 * lib["mm"], 127 * lib["mm"]], header=False))
        story.append(lib["Spacer"](1, 3 * lib["mm"]))
    threats = [item for item in data.get("threat_matrix", []) if item.get("finding") != "NO_VIOLATION_OF_THIS_RULE"]
    story += [_paragraph(lib, styles, "Threat matrix", "VgxH1"), _paragraph(lib, styles, "Threat entries describe policy exposure context. They do not establish exploitation or compromise.")]
    threat_rows = [["Context", "Severity", "Assessment", "Evidence status"]]
    for item in (threats or data.get("threat_matrix", []))[:8]:
        threat_rows.append([item.get("threat_context", "—"), item.get("severity", "—"), item.get("finding", "—").replace("_", " "), item.get("status", "—").replace("_", " ")])
    story += [_table(lib, theme, threat_rows, [52 * lib["mm"], 22 * lib["mm"], 57 * lib["mm"], 43 * lib["mm"]]), _paragraph(lib, styles, "Assurance boundary", "VgxH1"), _paragraph(lib, styles, "The application classifier infers encrypted-flow traffic categories from safe aggregate flow features. Its confidence does not prove ground truth or in-domain coverage. Configuration and security conclusions are limited to the evidence ledger, the stated policy profile, and the supported candidate catalogue.")]
    doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)


def _technical_pdf(data: dict[str, Any], destination: Path) -> None:
    lib, theme = _pdf_theme()
    doc = lib["SimpleDocTemplate"](str(destination), pagesize=lib["A4"], leftMargin=14 * lib["mm"], rightMargin=14 * lib["mm"], topMargin=18 * lib["mm"], bottomMargin=18 * lib["mm"], title="VPNGUARD-X Technical IPsec Assessment")
    styles = theme["styles"]
    story = _cover(lib, theme, data, "Technical IPsec assessment", "Evidence ledger, configuration candidates, policy rationale, and remediation")
    story += [lib["PageBreak"](), _paragraph(lib, styles, "Capture and protocol inventory", "VgxH1")]
    capture = data["capture"]
    story.append(_table(lib, theme, [["Metric", "Value"], ["Packets inspected", f"{capture.get('packet_count', 0):,}"], ["IKE security associations", len(capture.get("ike_sessions", []))], ["ESP flows", len(capture.get("esp_flows", []))], ["Capture digest", capture.get("sha256", "—")], ["Assessment mode", data.get("mode", "—")]], [58 * lib["mm"], 132 * lib["mm"]]))
    collection = capture.get("collection")
    if collection:
        story += [_paragraph(lib, styles, "Live collection provenance", "VgxH2"), _table(lib, theme, [["Collection field", "Value"], ["Selected interface", collection.get("interface", "—")], ["Capture filter", collection.get("filter", "—")], ["Collection window", f"{collection.get('duration_seconds', '—')} seconds"], ["Started", collection.get("started_at_utc", "—")], ["Completed", collection.get("completed_at_utc", "—")], ["Probe performed", "No — passive collection only"]], [58 * lib["mm"], 132 * lib["mm"]])]
    session_rows = [["IKE SA", "Endpoints", "Exchange records", "Retransmissions"]]
    for session in capture.get("ike_sessions", []):
        endpoints = ", ".join(" ↔ ".join(pair) for pair in session.get("endpoints", [])[:1])
        session_rows.append([_short_hash(session.get("initiator_spi")), endpoints or "—", len(session.get("exchanges", [])), session.get("retransmissions", 0)])
    story += [_paragraph(lib, styles, "IKE session summary", "VgxH2"), _table(lib, theme, session_rows, [38 * lib["mm"], 82 * lib["mm"], 35 * lib["mm"], 35 * lib["mm"]]), _paragraph(lib, styles, "Evidence ledger", "VgxH1")]
    ledger = [["Property", "Value", "Status", "Source", "Rationale"]]
    for item in capture.get("evidence", []):
        ledger.append([item.get("property_name", "—"), _pdf_value(item.get("value")), item.get("status", "—").replace("_", " "), item.get("source", "—"), item.get("rationale", "—")])
    story.append(_table(lib, theme, ledger, [33 * lib["mm"], 40 * lib["mm"], 34 * lib["mm"], 34 * lib["mm"], 49 * lib["mm"]]))
    cgii = data["cgii"]
    story += [lib["PageBreak"](), _paragraph(lib, styles, "Configuration inference and AI", "VgxH1")]
    candidate_rows = [["Supported candidate", "Constrained probability"]]
    for candidate in cgii.get("prediction_set", []):
        candidate_rows.append([candidate, f"{float(cgii.get('posterior', {}).get(candidate, 0)) * 100:.2f}%"])
    if len(candidate_rows) == 1:
        candidate_rows.append(["No candidate set resolved", cgii.get("inference_status", "—")])
    story.append(_table(lib, theme, candidate_rows, [138 * lib["mm"], 52 * lib["mm"]]))
    app = data.get("application", {})
    story += [_paragraph(lib, styles, "Encrypted-flow traffic inference", "VgxH2"), _table(lib, theme, [["Classifier", "Result"], ["Predicted category", app.get("label", "UNKNOWN")], ["Confidence", f"{float(app.get('max_probability') or 0) * 100:.2f}%"], ["Inference status", app.get("status", "—")], ["Caveat", app.get("ood_caveat", "No model conclusion supplied.")]], [52 * lib["mm"], 138 * lib["mm"]]), _paragraph(lib, styles, "Policy findings", "VgxH1")]
    findings = [["Rule", "Status", "Severity", "Rationale / action"]]
    for item in data.get("policy", {}).get("findings", []):
        text = item.get("rationale", "—")
        if item.get("status") in {"CERTAIN_VIOLATION", "POSSIBLE_VIOLATION"}:
            text += f" Action: {item.get('remediation', 'Validate remediation.')}"
        findings.append([item.get("rule_id", "—"), item.get("status", "—").replace("_", " "), item.get("severity", "—"), text])
    story.append(_table(lib, theme, findings, [32 * lib["mm"], 36 * lib["mm"], 20 * lib["mm"], 102 * lib["mm"]]))
    story += [lib["PageBreak"](), _paragraph(lib, styles, "Threat matrix and remediation", "VgxH1")]
    threats = [["Threat context", "Rule", "Severity", "Finding", "Evidence state"]]
    for item in data.get("threat_matrix", []):
        threats.append([item.get("threat_context", "—"), item.get("rule_id", "—"), item.get("severity", "—"), item.get("finding", "—").replace("_", " "), item.get("status", "—").replace("_", " ")])
    story.append(_table(lib, theme, threats, [45 * lib["mm"], 33 * lib["mm"], 20 * lib["mm"], 50 * lib["mm"], 42 * lib["mm"]]))
    story += [_paragraph(lib, styles, "Recommended actions", "VgxH1")]
    for item in _recommendations(data):
        story += [_paragraph(lib, styles, f"<b>{_safe(item['priority'])} — {_safe(item['title'])}</b>: {_safe(item['action'])}"), _paragraph(lib, styles, f"Basis: {_safe(item['basis'])}", "VgxSmall")]
    deployment = data.get("run", {}).get("deployment", {})
    story += [_paragraph(lib, styles, "Reproducibility and limitations", "VgxH1"), _table(lib, theme, [["Item", "Value"], ["Policy profile", data.get("run", {}).get("profile_id", "—")], ["Policy hash", data.get("run", {}).get("policy_hash", "—")], ["Candidate catalogue hash", data.get("run", {}).get("catalogue_hash", "—")], ["Deployment bundle", deployment.get("bundle_id", "No model bundle loaded")], ["Model purpose", deployment.get("purpose", "—")]], [55 * lib["mm"], 135 * lib["mm"]]), _paragraph(lib, styles, "Protected IKEv2/ESP payloads were not decrypted. Fields marked unknown require visible negotiation evidence or approved endpoint telemetry. Possible findings are conditional policy exposure, not confirmed vulnerabilities. Verify interoperability and operational impact before applying any configuration change.")]
    doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)


def write_reports(bundle: Any, output_directory: str | Path) -> dict[str, str]:
    selected = Path(output_directory)
    selected.mkdir(parents=True, exist_ok=True)
    data = bundle.to_dict() if hasattr(bundle, "to_dict") else dict(bundle)
    paths = {"json": selected / "assessment.json", "technical_markdown": selected / "technical_report.md", "executive_markdown": selected / "executive_report.md", "technical_pdf": selected / "technical_report.pdf", "executive_pdf": selected / "executive_report.pdf"}
    paths["json"].write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    paths["technical_markdown"].write_text(_technical_markdown(data), encoding="utf-8")
    paths["executive_markdown"].write_text(_executive_markdown(data), encoding="utf-8")
    _executive_pdf(data, paths["executive_pdf"])
    _technical_pdf(data, paths["technical_pdf"])
    return {name: str(path.resolve()) for name, path in paths.items()}
