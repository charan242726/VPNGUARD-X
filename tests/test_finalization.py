from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from experiments.recompute_metrics_from_predictions import recompute
from experiments.sanitize_dataset import sanitize_dataset
from scripts.finalize_vpnguard_x import _audit_scenario_manifests
from scripts.prepare_analysis_review import _validate_export, prepare_analysis_review


class FinalizationTests(unittest.TestCase):
    def test_privacy_scan_does_not_mistake_https_url_for_windows_drive(self) -> None:
        _validate_export(Path("standards.md"), b"https://www.rfc-editor.org/rfc/rfc7296")

    def test_dataset_sanitization_changes_only_path_fields(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.jsonl"
            destination = root / "portable.jsonl"
            source.write_text(
                json.dumps(
                    {
                        "artifact_id": "a",
                        "features": [1.0, 2.0],
                        "ground_truth_path": "/home/student/VPNGUARD-X/artifacts/range/a/ground_truth.json",
                        "pcap_path": r"D:\\SIH\\VPNGUARD-X\\artifacts\\range\\a\\capture.pcap",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            manifest = sanitize_dataset(source, destination)
            row = json.loads(destination.read_text(encoding="utf-8"))
            self.assertTrue(manifest["scientific_fields_unchanged"])
            self.assertEqual(manifest["modified_path_field_count"], 2)
            self.assertEqual(row["features"], [1.0, 2.0])
            self.assertTrue(row["ground_truth_path"].startswith("artifacts/"))
            self.assertTrue(row["pcap_path"].startswith("artifacts/"))

    def test_recompute_uses_singleton_or_abstain_and_preserves_predictions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "results"
            run = source / "seed-11/SPLIT/METHOD"
            run.mkdir(parents=True)
            prediction_path = run / "predictions.jsonl"
            records = [
                {
                    "artifact_id": "a",
                    "replicate_group": "a",
                    "split_id": "SPLIT",
                    "method": "METHOD",
                    "seed": 11,
                    "true_candidate_id": "b",
                    "candidate_posterior": {"b": 0.5, "a": 0.5},
                    "prediction_set": ["a", "b"],
                    "packet_loss_fraction": 0.0,
                },
                {
                    "artifact_id": "b",
                    "replicate_group": "b",
                    "split_id": "SPLIT",
                    "method": "METHOD",
                    "seed": 11,
                    "true_candidate_id": "b",
                    "candidate_posterior": {"a": 0.1, "b": 0.9},
                    "prediction_set": ["b"],
                    "packet_loss_fraction": 0.1,
                },
            ]
            prediction_path.write_text(
                "".join(json.dumps(row, sort_keys=True) + "\n" for row in records), encoding="utf-8"
            )
            before = prediction_path.read_bytes()
            digest = hashlib.sha256(before).hexdigest()
            (run / "metrics.json").write_text(
                json.dumps(
                    {
                        "schema_version": "0.2.0",
                        "dataset_sha256": "old-dataset",
                        "split_id": "SPLIT",
                        "seed": 11,
                        "method": "METHOD",
                        "prediction_sha256": digest,
                    }
                ),
                encoding="utf-8",
            )
            (source / "aggregate-results.json").write_text(
                json.dumps({"dataset_sha256": "old-dataset"}), encoding="utf-8"
            )
            destination = root / "final"
            audit = recompute(
                source,
                destination,
                iterations=200,
                dataset_file="portable.jsonl",
                dataset_sha256="portable-dataset",
            )
            corrected = json.loads((destination / "seed-11/SPLIT/METHOD/metrics.json").read_text(encoding="utf-8"))
            configuration = corrected["metrics"]["configuration"]
            self.assertEqual(configuration["exact_match"], 0.5)
            self.assertEqual(configuration["point_prediction_rate"], 0.5)
            self.assertEqual(configuration["point_exact_match_conditional"], 1.0)
            self.assertEqual(corrected["dataset_sha256"], "portable-dataset")
            self.assertEqual(corrected["source_dataset_sha256"], "old-dataset")
            self.assertFalse(audit["model_retraining_performed"])
            self.assertEqual(prediction_path.read_bytes(), before)

    def test_scenario_audit_keeps_historical_hash_mismatch_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            run = project / "artifacts/range/RUN/seed-11"
            run.mkdir(parents=True)
            configured = {"child.mode": "TUNNEL"}
            (run / "ground_truth.json").write_text(
                json.dumps(
                    {
                        "scenario_id": "RUN",
                        "source_scenario_id": "SOURCE",
                        "seed": 11,
                        "stack": "strongSwan",
                        "configured_properties": configured,
                        "scenario_manifest_hash": "executed-hash",
                        "capture": {"capture_variant": "FULL"},
                    }
                ),
                encoding="utf-8",
            )
            (run / "scenario_manifest.json").write_text(
                json.dumps(
                    {
                        "scenario_id": "RUN",
                        "source_scenario_id": "SOURCE",
                        "seed": 11,
                        "stack": "strongSwan",
                        "configured_properties": configured,
                        "manifest_hash": "regenerated-hash",
                        "status": "COMPILED_NOT_EXECUTED",
                    }
                ),
                encoding="utf-8",
            )
            audit = _audit_scenario_manifests(project)
            self.assertEqual(audit["manifest_hash_mismatch_count"], 1)
            self.assertEqual(audit["semantic_match_count"], 1)
            self.assertIsNotNone(audit["known_limitation"])

    def test_analysis_archives_sanitize_dataset_paths_and_split_predictions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory) / "project"
            output = Path(directory) / "output"
            dataset = project / "artifacts/finalization/run/data/dataset.jsonl"
            dataset.parent.mkdir(parents=True)
            dataset.write_text(
                json.dumps(
                    {
                        "artifact_id": "a",
                        "ground_truth_path": "/home/student/VPNGUARD-X/artifacts/range/a/ground_truth.json",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            source_run = project / "artifacts/results_corrected/seed-11/SPLIT/METHOD"
            final_run = project / "artifacts/finalization/run/results/seed-11/SPLIT/METHOD"
            source_run.mkdir(parents=True)
            final_run.mkdir(parents=True)
            (source_run / "predictions.jsonl").write_text(
                json.dumps({"artifact_id": "a", "seed": 11}) + "\n", encoding="utf-8"
            )
            (final_run / "metrics.json").write_text(json.dumps({"metrics": {}}), encoding="utf-8")
            result = prepare_analysis_review(
                project,
                output,
                source_results="artifacts/results_corrected",
                final_results="artifacts/finalization/run/results",
                portable_dataset="artifacts/finalization/run/data/dataset.jsonl",
            )
            self.assertEqual(result["prediction_file_count"], 1)
            common = output / "VPNGUARD-X_Publication_Evidence_Common.zip"
            with zipfile.ZipFile(common) as archive:
                content = archive.read("data/publication/vpnguard_x_combined.jsonl").decode("utf-8")
                self.assertNotIn("/home/student", content)
                self.assertIn("artifacts/range/a/ground_truth.json", content)
            self.assertTrue((output / "VPNGUARD-X_Publication_Predictions_seed-11.zip").is_file())


if __name__ == "__main__":
    unittest.main()
