from __future__ import annotations

import tempfile
import unittest
import json
from pathlib import Path

from calibration import SplitConformalCalibrator, TemperatureScaler
from experiments.bootstrap_results import bootstrap
from experiments.metrics import evaluate_prediction_records
from features import FLOW_FEATURE_NAMES, extract_capture_features, extract_sequence_features
from models.open_world import OpenWorldGate
from parser import analyze_pcap

from tests.fixtures import write_synthetic_pcap


class CalibrationFeatureTests(unittest.TestCase):
    def test_configuration_ties_abstain_and_survive_json_key_sorting(self) -> None:
        record = {
            "true_candidate_id": "candidate-b",
            "candidate_posterior": {"candidate-b": 0.5, "candidate-a": 0.5},
            "prediction_set": ["candidate-a", "candidate-b"],
        }
        before = evaluate_prediction_records([record])["configuration"]
        serialized = json.loads(json.dumps(record, sort_keys=True))
        after = evaluate_prediction_records([serialized])["configuration"]
        self.assertEqual(before, after)
        self.assertEqual(before["decision_rule"], "SINGLETON_PREDICTION_SET_ELSE_ABSTAIN")
        self.assertEqual(before["exact_match"], 0.0)
        self.assertEqual(before["point_prediction_rate"], 0.0)
        self.assertEqual(before["point_abstention_rate"], 1.0)
        self.assertIsNone(before["point_exact_match_conditional"])
        self.assertEqual(before["prediction_set_coverage"], 1.0)

    def test_configuration_singleton_emits_point_decision(self) -> None:
        metrics = evaluate_prediction_records(
            [{
                "true_candidate_id": "candidate-b",
                "candidate_posterior": {"candidate-b": 0.5, "candidate-a": 0.5},
                "prediction_set": ["candidate-b"],
            }]
        )["configuration"]
        self.assertEqual(metrics["exact_match"], 1.0)
        self.assertEqual(metrics["point_prediction_rate"], 1.0)
        self.assertEqual(metrics["point_exact_match_conditional"], 1.0)

    def test_explicit_point_value_cannot_bypass_non_singleton_abstention(self) -> None:
        metrics = evaluate_prediction_records(
            [{
                "true_candidate_id": "candidate-b",
                "candidate_posterior": {"candidate-b": 0.6, "candidate-a": 0.4},
                "prediction_set": ["candidate-a", "candidate-b"],
                "predicted_candidate_id": "candidate-b",
            }]
        )["configuration"]
        self.assertEqual(metrics["exact_match"], 0.0)
        self.assertEqual(metrics["point_prediction_rate"], 0.0)

    def test_bootstrap_uses_equal_seed_metrics_instead_of_pooling_scores(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for seed, known_score, unknown_score in ((11, 0.1, 0.2), (22, 0.3, 0.4)):
                target = root / f"seed-{seed}" / "split" / "method" / "predictions.jsonl"
                target.parent.mkdir(parents=True)
                records = [
                    {
                        "artifact_id": f"known-{seed}", "replicate_group": f"known-{seed}",
                        "split_id": "OOD", "method": "METHOD", "seed": seed,
                        "true_application": "WEB", "reported_application": "WEB", "is_ood": False,
                        "ood_score": known_score, "application_probabilities": {"WEB": 1.0 - known_score, "VIDEO": known_score},
                    },
                    {
                        "artifact_id": f"unknown-{seed}", "replicate_group": f"unknown-{seed}",
                        "split_id": "OOD", "method": "METHOD", "seed": seed,
                        "true_application": "UNKNOWN", "reported_application": "UNKNOWN", "is_ood": True,
                        "ood_score": unknown_score, "application_probabilities": {"WEB": 1.0 - unknown_score, "VIDEO": unknown_score},
                    },
                ]
                target.write_text("".join(json.dumps(row) + "\n" for row in records), encoding="utf-8")
            result = bootstrap(root, iterations=200, seed=26160)
            interval = result["intervals"][0]
            self.assertEqual(result["bootstrap_unit"], "evaluation_seed_then_replicate_group")
            self.assertEqual(interval["seed_count"], 2)
            # Each seed ranks UNKNOWN above known traffic (AUROC 1.0). Pooling
            # the differently scaled scores would incorrectly produce 0.75.
            self.assertEqual(interval["metrics"]["ood.auroc"]["estimate"], 1.0)

    def test_split_conformal(self) -> None:
        probabilities = [{"a": 0.9, "b": 0.1}, {"a": 0.3, "b": 0.7}, {"a": 0.8, "b": 0.2}]
        calibrator = SplitConformalCalibrator.fit(probabilities, ["a", "b", "a"], alpha=0.25)
        selected = calibrator.prediction_set({"a": 0.75, "b": 0.25}, 0.25)
        self.assertIn("a", selected)
        self.assertEqual(len(calibrator.calibrator_hash), 64)

    def test_temperature_scaling(self) -> None:
        scaler = TemperatureScaler.fit([[5.0, 0.0], [0.0, 5.0]], [0, 1], grid_points=20)
        transformed = scaler.transform([[2.0, 1.0]])[0]
        self.assertAlmostEqual(sum(transformed), 1.0)
        self.assertGreater(transformed[0], transformed[1])

    def test_open_world_gate(self) -> None:
        gate = OpenWorldGate.fit([0.72, 0.8, 0.9, 0.95], target_id_rejection_rate=0.25)
        self.assertEqual(gate.decide({"WEB": 0.4, "VIDEO": 0.35, "VOIP": 0.25}).label, "UNKNOWN")
        self.assertEqual(gate.decide({"WEB": 0.9, "VIDEO": 0.1}).label, "WEB")

    def test_feature_shapes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            analysis = analyze_pcap(write_synthetic_pcap(Path(directory) / "capture.pcap"))
        vector = extract_capture_features(analysis.packets)
        sequence = extract_sequence_features(analysis.packets, sequence_length=8)
        self.assertEqual(len(vector), len(FLOW_FEATURE_NAMES))
        self.assertEqual(len(sequence.values), 8)
        self.assertEqual(sum(sequence.mask), 4)
        self.assertEqual(len(sequence.values[0]), 5)


if __name__ == "__main__":
    unittest.main()
