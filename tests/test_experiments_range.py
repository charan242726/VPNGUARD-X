from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cgii import load_catalogue
from cyber_range.range import STACK_INTEROP, compile_planned_run, compile_scenario, load_scenarios
from cyber_range.batch import execute_plan
from experiments.plan_benchmark import generate_plan
from experiments.build_dataset import _match_candidates
from experiments.incomplete_capture import filter_pcap, thin_pcap
from experiments.splits import ExperimentRecord, build_generalization_splits
from experiments.run_evaluation import _linked_test_rows, dry_run
from observability import cooperative_evidence_from_json, cooperative_evidence_from_swanctl, cooperative_evidence_from_xfrm
from parser import analyze_pcap

from tests.fixtures import write_synthetic_pcap


class ExperimentRangeTests(unittest.TestCase):
    def test_compile_resume_does_not_overwrite_completed_run_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "range"
            completed = output / "already-done/seed-11"
            completed.mkdir(parents=True)
            (completed / "capture.pcap").write_bytes(b"preserved")
            (completed / "ground_truth.json").write_text("{}", encoding="utf-8")
            sentinel = completed / "scenario_manifest.json"
            sentinel.write_text("preserve executed manifest", encoding="utf-8")
            plan = root / "plan.csv"
            plan.write_text("placeholder\n", encoding="utf-8")
            with patch("cyber_range.batch._load_plan", return_value=[{"run_id": "already-done", "seed": "11"}]), patch(
                "cyber_range.batch.compile_planned_run"
            ) as compile_mock:
                result = execute_plan(plan, output, mode="compile", resume=True)
            compile_mock.assert_not_called()
            self.assertEqual(result["skipped_count"], 1)
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "preserve executed manifest")

    def test_range_compile_is_reproducible_and_secret_not_in_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            compiled = compile_scenario("VGX-I2-V4-TUN-GCM19-NATIVE-WEB", 11, directory)
            run = Path(compiled.run_directory)
            manifest = (run / "scenario_manifest.json").read_text(encoding="utf-8")
            config = run / "left/swanctl.conf"
            self.assertNotIn("secret =", manifest)
            self.assertEqual(config.stat().st_mode & 0o777, 0o600)
            self.assertIn("aes256gcm16-prfsha384-ecp256", config.read_text(encoding="utf-8"))

    def test_every_enabled_scenario_has_one_catalogue_ground_truth(self) -> None:
        catalogue = load_catalogue(Path(__file__).resolve().parents[1] / "configs/candidate_catalogue.yaml")
        with tempfile.TemporaryDirectory() as directory:
            for scenario_id, row in load_scenarios().items():
                if row["enabled"].lower() != "true":
                    continue
                seed = int(row["replicate_seeds"].split("|")[0])
                compiled = compile_scenario(scenario_id, seed, directory)
                self.assertEqual(len(_match_candidates(compiled.configured_properties, catalogue)), 1, scenario_id)

    def test_balanced_benchmark_plan_and_planned_compile(self) -> None:
        design = Path(__file__).resolve().parents[1] / "configs/benchmark_design.yaml"
        rows, manifest = generate_plan(design, profile="pilot", stack="strongSwan-6.1.0")
        self.assertTrue(manifest["balanced_configuration_by_traffic"])
        self.assertEqual(manifest["row_count"], 18)
        with tempfile.TemporaryDirectory() as directory:
            compiled = compile_planned_run({key: str(value) for key, value in rows[0].items()}, directory)
            self.assertEqual(compiled.source_scenario_id, rows[0]["base_scenario_id"])
            self.assertEqual(compiled.scenario["application_profile"], rows[0]["application_profile"])

    def test_libreswan_interop_compile_is_bounded_and_secret_excluded(self) -> None:
        design = Path(__file__).resolve().parents[1] / "configs/benchmark_design.yaml"
        rows, _ = generate_plan(design, profile="pilot", stack=STACK_INTEROP)
        with tempfile.TemporaryDirectory() as directory:
            compiled = compile_planned_run({key: str(value) for key, value in rows[0].items()}, directory)
            run = Path(compiled.run_directory)
            self.assertIn("keyexchange=ikev2", (run / "right/ipsec.conf").read_text(encoding="utf-8"))
            manifest = json.loads((run / "scenario_manifest.json").read_text(encoding="utf-8"))
            self.assertFalse(manifest["secret_material_in_manifest"])
            secret_line = (run / "right/ipsec.secrets").read_text(encoding="utf-8").strip()
            secret_value = secret_line.rsplit(" ", 1)[-1].strip('"')
            self.assertNotIn(secret_value, json.dumps(manifest))

    def test_incomplete_capture_is_parseable_and_manifested(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = write_synthetic_pcap(root / "source.pcap")
            destination = root / "loss30.pcap"
            manifest = thin_pcap(source, destination, loss_fraction=0.3, seed=26160)
            self.assertTrue(destination.exists())
            self.assertTrue(destination.with_suffix(".pcap.loss.json").exists())
            self.assertEqual(manifest["input_packet_count"], 4)
            self.assertGreaterEqual(manifest["output_packet_count"], 1)

    def test_structural_capture_variants_remove_declared_packets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = write_synthetic_pcap(root / "source.pcap")
            no_init = root / "no-init.pcap"
            midstream = root / "midstream.pcap"
            no_init_manifest = filter_pcap(source, no_init, variant="REMOVE_IKE_SA_INIT")
            midstream_manifest = filter_pcap(source, midstream, variant="MIDSTREAM_ESP_ONLY")
            self.assertEqual(no_init_manifest["output_packet_count"], 2)
            self.assertEqual(midstream_manifest["output_packet_count"], 2)
            self.assertFalse(analyze_pcap(no_init).ike_sessions)
            self.assertFalse(analyze_pcap(midstream).ike_sessions)

    def test_splits_do_not_overlap(self) -> None:
        records = [
            ExperimentRecord("a1", "a", "GCM", "TUNNEL", 4, "NATIVE_ESP", "strongSwan", "WEB", "a"),
            ExperimentRecord("a2", "a", "GCM", "TUNNEL", 4, "NATIVE_ESP", "strongSwan", "WEB", "a"),
            ExperimentRecord("b1", "b", "CBC", "TRANSPORT", 6, "UDP_ENCAPSULATED_ESP", "other", "UNKNOWN", "b"),
            ExperimentRecord("c1", "c", "CBC", "TUNNEL", 6, "NATIVE_ESP", "strongSwan", "VIDEO", "c"),
        ]
        splits = build_generalization_splits(records)
        self.assertTrue(splits)
        for split in splits:
            self.assertFalse(set(split.train_ids) & set(split.calibration_ids))
            self.assertFalse(set(split.train_ids) & set(split.test_ids))
            self.assertFalse(set(split.calibration_ids) & set(split.test_ids))

    def test_packet_loss_lineage_joins_full_capture_and_dry_run_counts_variants(self) -> None:
        rows = [
            {"artifact_id": "full-with-null-seed", "capture_variant": "FULL", "replicate_group": "root", "packet_loss_fraction": 0.0},
            *(
                {"artifact_id": f"loss-{level}", "capture_variant": f"LOSS_{level}", "source_artifact_id": "root", "replicate_group": "root", "packet_loss_fraction": level / 100}
                for level in (10, 30, 50)
            ),
            {"artifact_id": "other-loss", "capture_variant": "LOSS_10", "source_artifact_id": "other", "replicate_group": "other", "packet_loss_fraction": 0.1},
        ]
        selected = _linked_test_rows(rows, {"full-with-null-seed"}, True)
        self.assertEqual({row["artifact_id"] for row in selected}, {"full-with-null-seed", "loss-10", "loss-30", "loss-50"})
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dataset = root / "data.jsonl"
            dataset.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
            split = root / "split.json"
            split.write_text(json.dumps({"seed": 11, "train_ids": [], "calibration_ids": [], "test_ids": ["full-with-null-seed"]}), encoding="utf-8")
            summary = dry_run(dataset, [split], True)
            self.assertTrue(summary["valid"])
            self.assertEqual(summary["splits"][0]["test_variant_counts"], {"FULL": 1, "LOSS_10": 1, "LOSS_30": 1, "LOSS_50": 1})

    def test_unseen_application_ood_has_held_out_known_controls(self) -> None:
        rows = [
            ExperimentRecord(f"{label}-{i}", "config", "GCM", "TUNNEL", 4, "NATIVE_ESP", "strongSwan", label, f"{label}-{i}")
            for label in ("WEB", "VIDEO", "UNKNOWN") for i in range(10)
        ]
        split = next(item for item in build_generalization_splits(rows, seed=11) if item.split_id == "UNSEEN_APPLICATION_OOD")
        labels = {row.artifact_id: row.application_class for row in rows}
        self.assertEqual({labels[item] for item in split.test_ids}, {"WEB", "VIDEO", "UNKNOWN"})
        self.assertNotIn("UNKNOWN", {labels[item] for item in split.train_ids + split.calibration_ids})
        self.assertEqual(len(split.test_ids), 14)

    def test_cooperative_parsing_and_secret_rejection(self) -> None:
        text = "version=2 encr-alg=AES_GCM_16 encr-keysize=256 prf-alg=PRF_HMAC_SHA2_384 dh-group=ECP_256 mode=tunnel"
        ledger = cooperative_evidence_from_swanctl(text)
        self.assertEqual(ledger.best("ike.selected_encryption").value, "ENCR_AES_GCM_16_256")
        self.assertEqual(ledger.best("ike.initial_ke_group").value, 19)
        with self.assertRaises(ValueError):
            cooperative_evidence_from_json({"nested": {"session_key": "not-allowed"}})

    def test_nested_vici_distinguishes_ike_and_child_sa_fields(self) -> None:
        text = (
            "list-sa event {vgx {version=2 encr-alg=AES_CBC encr-keysize=256 "
            "integ-alg=HMAC_SHA2_256_128 prf-alg=PRF_HMAC_SHA2_256 dh-group=ECP_256 "
            "child-sas {protected-1 {mode=TUNNEL protocol=ESP encr-alg=AES_GCM_16 "
            "encr-keysize=256 dh-group=ECP_384 esn=1 life-time=3588}}}}"
        )
        ledger = cooperative_evidence_from_swanctl(text)
        self.assertEqual(ledger.best("ike.selected_encryption").value, "ENCR_AES_CBC_256")
        self.assertEqual(ledger.best("child.encryption").value, "ENCR_AES_GCM_16_256")
        self.assertEqual(ledger.best("child.pfs_group").value, 20)
        self.assertTrue(ledger.best("child.esn").value)
        self.assertEqual(ledger.best("sa.remaining_lifetime_seconds").value, 3588)
        self.assertIsNone(ledger.best("sa.configured_lifetime"))

    def test_xfrm_extended_replay_window_takes_precedence(self) -> None:
        text = """src 10.0.0.1 dst 10.0.0.2
        proto esp spi 0x00000001 reqid 1 mode tunnel
        replay-window 0 flag af-unspec
        anti-replay esn context:
        replay_window 32 seq 4 oseq 0
        """
        ledger = cooperative_evidence_from_xfrm(text)
        self.assertEqual(ledger.best("child.replay_window_size").value, 32)
        self.assertTrue(ledger.best("child.anti_replay_enabled").value)

    def test_xfrm_statistics_counter_does_not_override_sa_replay_window(self) -> None:
        text = """src 10.0.0.2 dst 10.0.0.1
        proto esp spi 0x00000001 reqid 1 mode tunnel
        replay-window 32 seq 0x00000000 flag af-unspec
        stats:
          replay-window 0 replay 0 failed 0
        """
        ledger = cooperative_evidence_from_xfrm(text)
        self.assertEqual(ledger.best("child.replay_window_size").value, 32)
        self.assertTrue(ledger.best("child.anti_replay_enabled").value)


if __name__ == "__main__":
    unittest.main()
