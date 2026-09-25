"""The review bundle must preserve provenance without exporting credentials."""

import hashlib
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from scripts.prepare_safe_review import make_bundle


class SafeReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.project = self.base / "project"
        self.run = self.project / "artifacts/range/SCENARIO/seed-11"
        self.run.mkdir(parents=True)
        packet = b"test capture fixture"
        (self.run / "capture.pcap").write_bytes(packet)
        (self.run / "ground_truth.json").write_text(
            json.dumps({
                "capture": {"pcap_file": "capture.pcap", "sha256": hashlib.sha256(packet).hexdigest(), "capture_variant": "FULL"},
                "outcome": "COMPLETED", "seed": 11, "stack": "test-stack",
                "secrets_or_session_keys_in_record": False,
            }), encoding="utf-8",
        )
        (self.run / "left").mkdir()
        (self.run / "left/swanctl.conf").write_text("secret" + " = fixture-only", encoding="utf-8")

    def test_bundle_excludes_credentials_and_captures(self):
        corrected = self.project / "artifacts/results_corrected/seed-11/UNSEEN_APPLICATION_OOD/METHOD"
        corrected.mkdir(parents=True)
        (corrected / "metrics.json").write_text(json.dumps({
            "split_id": "UNSEEN_APPLICATION_OOD",
            "metrics": {
                "incomplete_capture": {"0.0": {}, "0.1": {}, "0.3": {}, "0.5": {}},
                "ood": {"auroc": 0.75, "fpr95": 0.25},
            },
        }), encoding="utf-8")
        split = self.project / "artifacts/splits/seed-11"
        split.mkdir(parents=True)
        (split / "test.json").write_text(json.dumps({"train_ids": [], "calibration_ids": [], "test_ids": []}), encoding="utf-8")
        dest = self.base / "review.zip"
        report = make_bundle(self.project, dest)
        self.assertEqual(report["ground_truth_count"], 1)
        self.assertEqual(report["integrity_issues"], [])
        self.assertEqual(report["result_roots"]["results_corrected"]["metric_file_count"], 1)
        self.assertEqual(report["result_roots"]["results_corrected"]["dedicated_ood_null_metric_count"], 0)
        with zipfile.ZipFile(dest) as archive:
            names = archive.namelist()
            self.assertTrue(any(name.endswith("ground_truth.json") for name in names))
            self.assertFalse(any(name.endswith((".pcap", "swanctl.conf")) for name in names))
            self.assertIn("REVIEW_INVENTORY.json", names)
            self.assertTrue(any(name.startswith("artifacts/results_corrected/") for name in names))
            self.assertTrue(any(name.startswith("artifacts/splits/") for name in names))

    def test_allowlisted_file_with_credential_is_rejected(self):
        audit = self.project / "artifacts/audits"
        audit.mkdir(parents=True)
        (audit / "test.json").write_text(json.dumps({"psk": "fixture-only"}), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "potential credential"):
            make_bundle(self.project, self.base / "unsafe.zip")
        self.assertFalse((self.base / "unsafe.zip").exists())


if __name__ == "__main__":
    unittest.main()
