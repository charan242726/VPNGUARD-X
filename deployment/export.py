"""Export saved models with held-out calibration; source and test data remain unchanged."""
from __future__ import annotations
import hashlib
import json
import math
import shutil
from dataclasses import asdict
from importlib.metadata import version
from pathlib import Path
from calibration import SplitConformalCalibrator, TemperatureScaler
from calibration.wrapper import TemperatureCalibratedModel
from cgii import CGIIEngine, PriorDistribution, load_catalogue
from common.provenance import sha256_file, stable_hash
from deployment.bundle import REQUIRED_FILES, load_deployment, read_json
from experiments.run_evaluation import _ledger
from features import FLOW_FEATURE_NAMES
from models.open_world import OpenWorldGate
from models.xgboost_baseline import XGBoostBaseline

def dump(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")

def export_bundle(*, dataset, split, model_root, catalogue_path, output, purpose="LAB_DEPLOYMENT", alpha=0.1):
    dataset, split, model_root, catalogue_path, output = map(Path, (dataset, split, model_root, catalogue_path, output))
    if output.exists():
        raise ValueError("output exists; use a new versioned directory")
    manifest = read_json(split)
    payload = {k: manifest[k] for k in ("split_id", "train_ids", "calibration_ids", "test_ids", "held_out_value", "seed")}
    if hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest() != manifest["manifest_hash"]:
        raise ValueError("split manifest hash mismatch")
    rows = [json.loads(line) for line in dataset.read_text(encoding="utf-8").splitlines() if line.strip()]
    by_id = {r["artifact_id"]: r for r in rows}
    if len(by_id) != len(rows):
        raise ValueError("duplicate artifact IDs")
    parts = {p: [by_id[x] for x in manifest[p + "_ids"]] for p in ("train", "calibration", "test")}
    for i, a in enumerate(parts):
        if not parts[a]:
            raise ValueError("empty partition: " + a)
        for b in list(parts)[i + 1:]:
            for key in ("artifact_id", "replicate_group", "pcap_sha256"):
                if {r[key] for r in parts[a]} & {r[key] for r in parts[b]}:
                    raise ValueError(key + " leakage across " + a + "/" + b)
    catalogue = load_catalogue(catalogue_path)
    for row in parts["train"] + parts["calibration"]:
        if row.get("capture_variant") != "FULL" or row.get("flow_feature_names") != list(FLOW_FEATURE_NAMES):
            raise ValueError("FULL captures and exact feature order required")
        if len(row["flow_features"]) != len(FLOW_FEATURE_NAMES) or not all(math.isfinite(float(x)) for x in row["flow_features"]):
            raise ValueError("invalid feature vector")
        if row.get("configuration_id") not in catalogue.by_id:
            raise ValueError("unknown candidate label")
    models = {}
    for task, label in (("application", "application_class"), ("configuration", "configuration_id")):
        path = model_root / ("xgb-" + task)
        model = XGBoostBaseline.load(path)
        selected = [r for r in parts["train"] if r.get(label) and (task != "application" or r[label] != "UNKNOWN")]
        expected = stable_hash({"artifact_ids": sorted(r["artifact_id"] for r in selected), "label_key": label, "seed": int(manifest["seed"])})
        metadata = read_json(path / "metadata.json")
        if metadata.get("training_manifest_hash") != expected or metadata.get("feature_names") != list(FLOW_FEATURE_NAMES):
            raise ValueError(task + " training provenance/feature schema mismatch")
        if set(model.classes) != {r[label] for r in selected}:
            raise ValueError(task + " class labels mismatch")
        models[task] = model
    known = [r for r in parts["calibration"] if r["application_class"] != "UNKNOWN"]
    groups = sorted({r["replicate_group"] for r in known}, key=lambda g: stable_hash([manifest["seed"], g]))
    if len(groups) < 4:
        raise ValueError("at least four independent calibration groups required")
    temp_groups = set(groups[::2])
    temp_rows = [r for r in known if r["replicate_group"] in temp_groups]
    gate_rows = [r for r in known if r["replicate_group"] not in temp_groups]
    app = models["application"]
    if any(r["application_class"] not in app.classes for r in known):
        raise ValueError("unseen calibration class")
    probabilities = app.predict_proba([r["flow_features"] for r in temp_rows])
    scaler = TemperatureScaler.fit([[math.log(max(1e-15, d[c])) for c in app.classes] for d in probabilities], [app.classes.index(r["application_class"]) for r in temp_rows])
    gate = OpenWorldGate.fit([max(d.values()) for d in TemperatureCalibratedModel(app, scaler).predict_proba([r["flow_features"] for r in gate_rows])])
    config = models["configuration"]
    constrained = []
    for row, dist in zip(parts["calibration"], config.predict_proba([r["flow_features"] for r in parts["calibration"]]), strict=True):
        if row["configuration_id"] not in config.classes:
            raise ValueError("unseen calibration configuration; use the deployment OOD split")
        result = CGIIEngine(catalogue).infer(_ledger(row), PriorDistribution(dist, config.model_id, config.model_hash, manifest["split_id"], True))
        if result.status != "OK" or row["configuration_id"] not in result.posterior:
            raise ValueError("calibration evidence excludes ground truth")
        constrained.append(result.posterior)
    conformal = SplitConformalCalibrator.fit(constrained, [r["configuration_id"] for r in parts["calibration"]], alpha=alpha)
    output.mkdir(parents=True)
    try:
        for task in models:
            (output / task).mkdir()
            for name in ("model.ubj", "metadata.json"):
                shutil.copyfile(model_root / ("xgb-" + task) / name, output / task / name)
        shutil.copyfile(catalogue_path, output / "catalogue.yaml")
        dump(output / "calibration.json", {"temperature": asdict(scaler), "open_world_gate": asdict(gate), "conformal": conformal.to_dict()})
        dump(output / "partitions.json", {"train_ids": manifest["train_ids"], "temperature_ids": [r["artifact_id"] for r in temp_rows],
             "gate_ids": [r["artifact_id"] for r in gate_rows], "conformal_ids": manifest["calibration_ids"], "test_ids": manifest["test_ids"],
             "replicate_group_disjoint": True, "test_ids_untouched": True,
             "note": "Application temperature/gate groups are disjoint. Configuration conformal uses all held-out calibration rows for a separate model."})
        result = {"schema_version": "1.0.0", "purpose": purpose, "domain_id": f"{purpose}:{manifest['split_id']}:seed-{manifest['seed']}",
                  "dataset_sha256": sha256_file(dataset), "split_sha256": sha256_file(split), "split_id": manifest["split_id"], "seed": manifest["seed"],
                  "feature_names": list(FLOW_FEATURE_NAMES), "feature_scope": "CAPTURE_AGGREGATE_SINGLE_VPN", "catalogue_hash": catalogue.catalogue_hash,
                  "xgboost_version": version("xgboost"), "files": {name: sha256_file(output / name) for name in sorted(REQUIRED_FILES)},
                  "test_used_for_fitting": False, "benchmark_claim": "TBD — requires experiment"}
        result["bundle_id"] = stable_hash(result)
        dump(output / "deployment.json", result)
        load_deployment(output, allow_demo=purpose == "SYNTHETIC_SOFTWARE_DEMO")
    except Exception:
        shutil.rmtree(output)
        raise
    return result
