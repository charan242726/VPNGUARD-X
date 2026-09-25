from __future__ import annotations

import unittest
from pathlib import Path

from cgii import CGIIEngine, PriorDistribution, load_catalogue
from common.evidence import EvidenceLedger, EvidenceRecord, EvidenceStatus
from policy import FindingStatus, PolicyEngine
from remediation import find_minimum_changes
from risk import compute_risk_interval


ROOT = Path(__file__).resolve().parents[1]


def observed(name: str, value: object) -> EvidenceRecord:
    return EvidenceRecord(name, value, EvidenceStatus.OBSERVED, "TEST_FIXTURE", "Synthetic unit-test evidence")


class CGIIAndPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalogue = load_catalogue(ROOT / "configs/candidate_catalogue.yaml")
        cls.engine = CGIIEngine(cls.catalogue)
        cls.policy = PolicyEngine.from_yaml(ROOT / "configs/policy_rules.yaml")

    def test_hard_evidence_is_monotone(self) -> None:
        empty = self.engine.infer(EvidenceLedger())
        ledger = EvidenceLedger([observed("ike.version", "IKEV2")])
        constrained = self.engine.infer(ledger)
        self.assertTrue(set(constrained.feasible_candidate_ids) <= set(empty.feasible_candidate_ids))
        self.assertTrue(all(self.catalogue.by_id[candidate_id].ike_version == "IKEV2" for candidate_id in constrained.feasible_candidate_ids))

    def test_ai_evidence_never_eliminates(self) -> None:
        baseline = self.engine.infer(EvidenceLedger())
        ledger = EvidenceLedger([
            EvidenceRecord(
                "ike.version",
                "IKEV1",
                EvidenceStatus.AI_INFERRED,
                "TEST_MODEL",
                "Synthetic soft prediction",
                confidence=0.99,
                model_id="test",
                model_hash="0" * 64,
            )
        ])
        inferred = self.engine.infer(ledger)
        self.assertEqual(set(inferred.feasible_candidate_ids), set(baseline.feasible_candidate_ids))

    def test_conflicting_observations_abstain(self) -> None:
        ledger = EvidenceLedger([observed("ike.version", "IKEV1"), observed("ike.version", "IKEV2")])
        result = self.engine.infer(ledger)
        self.assertEqual(result.status, "EVIDENCE_CONFLICT")
        self.assertFalse(result.posterior)
        self.assertFalse(result.prediction_set)

    def test_posterior_projection_zeroes_eliminated_candidates(self) -> None:
        ids = {candidate.candidate_id for candidate in self.catalogue.candidates}
        prior = PriorDistribution({candidate_id: index + 1 for index, candidate_id in enumerate(sorted(ids))}, "TEST_PRIOR", "1" * 64, is_learned=True)
        result = self.engine.infer(EvidenceLedger([observed("ike.version", "IKEV1")]), prior)
        self.assertAlmostEqual(sum(result.posterior.values()), 1.0)
        self.assertTrue(all(self.catalogue.by_id[candidate_id].ike_version == "IKEV1" for candidate_id in result.posterior))
        self.assertEqual(result.inference_status.value, "AI_INFERRED")

    def test_set_policy_and_risk_semantics(self) -> None:
        candidates = [
            self.catalogue.by_id["MODERN_V4_NATIVE_TUNNEL_CBC14"],
            self.catalogue.by_id["MODERN_V4_NATIVE_TUNNEL_CBC14_NOPFS"],
        ]
        evaluation = self.policy.evaluate(candidates, "nist_800_77r1")
        pfs = next(finding for finding in evaluation.findings if finding.rule.rule_id == "NIST-PFS-001")
        self.assertEqual(pfs.status, FindingStatus.POSSIBLE_VIOLATION)
        interval = compute_risk_interval(evaluation)
        self.assertEqual(interval.status, "BOUNDED")
        self.assertLess(interval.minimum, interval.maximum)

    def test_counterfactual_remediation_is_catalogue_bounded(self) -> None:
        legacy = self.catalogue.by_id["LEGACY_IKEV1_V4_DES_GROUP1"]
        result = find_minimum_changes([legacy], self.catalogue, self.policy, "nist_800_77r1")
        self.assertEqual(result.status, "OK")
        self.assertGreater(result.minimum_cost or 0.0, 0.0)
        self.assertTrue(result.compliant_catalogue_candidate_ids)


if __name__ == "__main__":
    unittest.main()
