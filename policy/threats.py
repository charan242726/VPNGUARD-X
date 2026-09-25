"""Evidence-linked policy exposures, never claims of an observed attack."""
from common.evidence import EvidenceStatus
from policy.engine import _violates

# Runtime policy code must not depend on the offline experiment package.
PROPERTY_TO_FIELD = {
    "ike.version": "ike_version", "outer.ip_version": "outer_ip_version", "encapsulation": "encapsulation",
    "ike.selected_encryption": "ike_encryption", "ike.selected_integrity": "ike_integrity",
    "ike.selected_prf": "ike_prf", "ike.initial_ke_group": "ike_ke_group", "child.mode": "child_mode",
    "child.encryption": "child_encryption", "child.integrity": "child_integrity", "child.pfs_group": "child_pfs_group",
    "child.esn": "esn", "child.anti_replay_enabled": "anti_replay",
    "sa.configured_lifetime": "child_lifetime_seconds", "ike.authentication_family": "authentication_family",
}

CONTEXT = {"ike_version": "Legacy protocol exposure", "ike_encryption": "IKE confidentiality weakness", "ike_integrity": "IKE integrity weakness",
           "ike_prf": "IKE key derivation weakness", "ike_ke_group": "Key exchange strength mismatch", "child_encryption": "Traffic confidentiality weakness",
           "child_integrity": "Traffic integrity weakness", "child_pfs_group": "Reduced isolation between key compromises",
           "anti_replay": "Replay protection assurance gap", "child_lifetime_seconds": "Extended exposure under one SA"}

def build_threat_matrix(evaluation, evidence, engine=None):
    inverse = {field: prop for prop, field in PROPERTY_TO_FIELD.items()}
    result = []
    for finding in evaluation.findings:
        rule = finding.rule
        prop = inverse.get(rule.field)
        records = evidence.by_property(prop) if prop else []
        hard = [r for r in records if r.is_hard]
        distinct = {repr(r.value) for r in hard}
        if len(distinct) == 1:
            status = "DETERMINISTICALLY_DERIVED"
            verdict = "EVIDENCE_SUPPORTED_VIOLATION" if _violates(hard[0].value, rule.operator, rule.value) else "NO_VIOLATION_OF_THIS_RULE"
            scope = "SUPPLIED_PACKET_OR_ENDPOINT_EVIDENCE"
        elif len(distinct) > 1:
            status, verdict, scope = "UNKNOWN/UNOBSERVABLE", "CONFLICTING_EVIDENCE", "UNRESOLVED"
        elif evaluation.basis_status is EvidenceStatus.AI_INFERRED and evaluation.candidate_ids:
            status, verdict, scope = "AI_INFERRED", finding.status.value, "CALIBRATED_CANDIDATE_SET_CONDITIONAL"
        else:
            status, verdict, scope = "UNKNOWN/UNOBSERVABLE", "NOT_OBSERVED", "CATALOGUE_CONDITIONAL_ONLY"
        result.append({"threat_id": "THREAT:" + rule.rule_id, "rule_id": rule.rule_id, "threat_context": CONTEXT.get(rule.field, "Policy assurance gap"),
                       "severity": rule.severity, "status": status, "finding": verdict, "catalogue_finding": finding.status.value, "scope": scope,
                       "property": prop, "evidence": [r.to_dict() for r in records], "violating_candidate_ids": list(finding.violating_candidate_ids),
                       "source": finding.to_dict()["source"], "rationale": rule.rationale, "remediation": rule.remediation,
                       "attack_observed": False, "interpretation": "Policy exposure context; no exploit or compromise established."})
    return result
