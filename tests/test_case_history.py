from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from common.case_history import list_cases, record_case


class CaseHistoryTests(unittest.TestCase):
    def test_metadata_only_case_index(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            assessment = root / "assessment.json"
            assessment.write_text(json.dumps({
                "run": {"run_id": "vgx-test-case"},
                "capture": {"sha256": "capture-digest", "packet_count": 8, "packets": [{"payload": "never-indexed"}]},
                "risk": {"minimum": 0.1, "maximum": 0.4},
                "application": {"label": "WEB"},
            }), encoding="utf-8")
            result = record_case(root / "cases.sqlite3", assessment, source_kind="PCAP_ANALYSIS")
            self.assertEqual(result["run_id"], "vgx-test-case")
            entries = list_cases(root / "cases.sqlite3")
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["run_id"], "vgx-test-case")
        self.assertEqual(entries[0]["packet_count"], 8)
        self.assertNotIn("packets", entries[0])
        self.assertNotIn("payload", str(entries[0]))


if __name__ == "__main__":
    unittest.main()
