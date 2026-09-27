from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from parser import analyze_pcap
from pipeline import VPNGuardXPipeline
from reports import write_reports

from tests.fixtures import write_synthetic_pcap, write_synthetic_pcapng


class ParserPipelineTests(unittest.TestCase):
    def test_ike_and_esp_reconstruction(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = write_synthetic_pcap(Path(directory) / "synthetic.pcap")
            analysis = analyze_pcap(path)
        self.assertEqual(analysis.packet_count, 4)
        self.assertEqual([packet.packet_kind for packet in analysis.packets], ["IKE", "IKE", "ESP_NATIVE", "ESP_NATIVE"])
        self.assertEqual(len(analysis.ike_sessions), 1)
        self.assertEqual(len(analysis.esp_flows), 1)
        self.assertEqual(analysis.esp_flows[0].observed_gap_count, 1)
        self.assertEqual(analysis.evidence.best("ike.selected_encryption").value, "ENCR_AES_CBC_256")
        self.assertEqual(analysis.evidence.best("ike.selected_integrity").value, "AUTH_HMAC_SHA2_256_128")
        self.assertEqual(analysis.evidence.best("ike.initial_ke_group").value, 14)
        self.assertEqual(analysis.evidence.best("child.mode").status.value, "UNKNOWN/UNOBSERVABLE")

    def test_nat_t_demultiplexing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = write_synthetic_pcap(Path(directory) / "natt.pcap", natt=True)
            analysis = analyze_pcap(path)
        self.assertEqual([packet.packet_kind for packet in analysis.packets], ["IKE_NATT", "IKE_NATT", "ESP_UDP", "ESP_UDP"])
        self.assertEqual(analysis.evidence.best("encapsulation").value, "UDP_ENCAPSULATED_ESP")
        self.assertTrue(analysis.evidence.best("natt.non_esp_marker").value)

    def test_pcapng_input_matches_classic_pcap(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = write_synthetic_pcapng(Path(directory) / "synthetic.pcapng")
            analysis = analyze_pcap(path)
        self.assertEqual(analysis.packet_count, 4)
        self.assertEqual([packet.packet_kind for packet in analysis.packets], ["IKE", "IKE", "ESP_NATIVE", "ESP_NATIVE"])
        self.assertEqual(len(analysis.ike_sessions), 1)
        self.assertEqual(len(analysis.esp_flows), 1)

    def test_full_pipeline_and_reports(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pcap = write_synthetic_pcap(root / "synthetic.pcap")
            bundle = VPNGuardXPipeline().analyze(pcap)
            data = bundle.to_dict()
            self.assertEqual(data["mode"], "PASSIVE_BLACK_BOX")
            self.assertEqual(data["cgii"]["status"], "OK")
            self.assertEqual(set(data["cgii"]["prediction_set"]), {
                "MODERN_V4_NATIVE_TUNNEL_CBC14",
                "MODERN_V4_NATIVE_TUNNEL_CBC14_NOPFS",
                "MODERN_V4_NATIVE_TRANSPORT_CBC14",
            })
            self.assertEqual(data["application"]["status"], "UNKNOWN/UNOBSERVABLE")
            self.assertLessEqual(data["risk"]["minimum"], data["risk"]["maximum"])
            paths = write_reports(bundle, root / "reports")
            for path in paths.values():
                self.assertTrue(Path(path).exists())
            report = json.loads(Path(paths["json"]).read_text(encoding="utf-8"))
            self.assertEqual(report["run"]["run_id"], data["run"]["run_id"])

    def test_cooperative_evidence_can_resolve_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pcap = write_synthetic_pcap(Path(directory) / "synthetic.pcap")
            cooperative = {
                "child.mode": "TUNNEL",
                "child.encryption": "ENCR_AES_CBC_256",
                "child.integrity": "AUTH_HMAC_SHA2_256_128",
                "child.pfs_group": 14,
                "child.esn": False,
                "child.anti_replay_enabled": True,
                "sa.configured_lifetime": 3600,
                "ike.authentication_family": "PSK",
            }
            data = VPNGuardXPipeline().analyze(pcap, cooperative_properties=cooperative).to_dict()
        self.assertEqual(data["mode"], "COOPERATIVE_VALIDATION")
        self.assertEqual(data["cgii"]["prediction_set"], ["MODERN_V4_NATIVE_TUNNEL_CBC14"])

    def test_live_capture_metadata_is_provenance_not_configuration_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pcap = write_synthetic_pcap(Path(directory) / "synthetic.pcap")
            data = VPNGuardXPipeline().analyze(
                pcap,
                capture_metadata={
                    "interface": "eth0",
                    "filter": "udp port 500 or udp port 4500 or ip proto 50 or ip6 proto 50",
                    "duration_seconds": 20,
                    "authorization_acknowledged": True,
                    "active_probe_performed": False,
                    "psk": "must-not-be-retained",
                },
            ).to_dict()
        self.assertEqual(data["capture"]["collection"]["interface"], "eth0")
        self.assertNotIn("psk", data["capture"]["collection"])
        self.assertNotIn("collection", {item["property_name"] for item in data["capture"]["evidence"]})


if __name__ == "__main__":
    unittest.main()
