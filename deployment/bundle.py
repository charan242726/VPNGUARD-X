"""Verified native UBJSON loading; no pickle. Hashes are integrity checks, not signatures."""
from __future__ import annotations
import json
import math
from dataclasses import dataclass
from importlib.metadata import version
from pathlib import Path
from calibration import SplitConformalCalibrator, TemperatureScaler
from calibration.wrapper import TemperatureCalibratedModel
from cgii import load_catalogue
from common.provenance import sha256_file, stable_hash
from features import FLOW_FEATURE_NAMES
from models.open_world import OpenWorldGate
from models.xgboost_baseline import XGBoostBaseline

REQUIRED_FILES = {"catalogue.yaml", "application/model.ubj", "application/metadata.json", "configuration/model.ubj", "configuration/metadata.json", "calibration.json", "partitions.json"}

def read_json(path):
    def reject(value):
        raise ValueError("non-finite JSON: " + value)
    result = json.loads(Path(path).read_text(encoding="utf-8"), parse_constant=reject)
    if not isinstance(result, dict):
        raise ValueError("expected JSON object")
    return result

@dataclass(frozen=True)
class DeploymentBundle:
    directory: Path
    manifest: dict
    application: TemperatureCalibratedModel
    configuration: XGBoostBaseline
    conformal: SplitConformalCalibrator
    gate: OpenWorldGate

    @property
    def catalogue_path(self):
        return self.directory / "catalogue.yaml"

    def to_dict(self):
        return {"state": "LOADED", "bundle_id": self.manifest["bundle_id"], "purpose": self.manifest["purpose"],
                "domain_id": self.manifest["domain_id"], "dataset_sha256": self.manifest["dataset_sha256"],
                "application_model_hash": self.application.model_hash, "configuration_model_hash": self.configuration.model_hash,
                "temperature_hash": self.application.scaler.calibrator_hash, "gate_hash": self.gate.gate_hash,
                "conformal_hash": self.conformal.calibrator_hash, "feature_scope": "CAPTURE_AGGREGATE_SINGLE_VPN",
                "trained_application_classes": list(self.application.base_model.classes), "trained_configuration_classes": list(self.configuration.classes),
                "coverage_caveat": "Marginal conformal coverage needs exchangeability; no OOD coverage guarantee.",
                "empirical_performance": "TBD — requires experiment"}

def load_deployment(directory, *, allow_demo=False):
    root = Path(directory).resolve()
    manifest = read_json(root / "deployment.json")
    if manifest.get("schema_version") != "1.0.0":
        raise ValueError("unsupported deployment schema")
    if manifest.get("bundle_id") != stable_hash({k: v for k, v in manifest.items() if k != "bundle_id"}):
        raise ValueError("deployment manifest hash mismatch")
    if manifest.get("purpose") not in {"LAB_DEPLOYMENT", "SYNTHETIC_SOFTWARE_DEMO"}:
        raise ValueError("unknown deployment purpose")
    if manifest["purpose"] == "SYNTHETIC_SOFTWARE_DEMO" and not allow_demo:
        raise ValueError("synthetic demo requires explicit --allow-demo or VPNGUARDX_ALLOW_DEMO=1")
    if manifest.get("feature_names") != list(FLOW_FEATURE_NAMES):
        raise ValueError("deployment feature order differs from runtime")
    if manifest.get("feature_scope") != "CAPTURE_AGGREGATE_SINGLE_VPN":
        raise ValueError("unsupported inference scope")
    if manifest.get("xgboost_version") != version("xgboost"):
        raise ValueError("XGBoost version differs from deployment; install the supplied lock")
    if set(manifest.get("files", {})) != REQUIRED_FILES:
        raise ValueError("incomplete or unexpected deployment inventory")
    for name, digest in manifest["files"].items():
        path = (root / name).resolve()
        if not path.is_relative_to(root) or not path.is_file() or sha256_file(path) != digest:
            raise ValueError("deployment artifact missing, outside bundle, or changed: " + name)
    catalogue = load_catalogue(root / "catalogue.yaml")
    if catalogue.catalogue_hash != manifest.get("catalogue_hash"):
        raise ValueError("catalogue hash mismatch")
    models = {}
    for task in ("application", "configuration"):
        metadata = read_json(root / task / "metadata.json")
        if metadata.get("feature_names") != list(FLOW_FEATURE_NAMES):
            raise ValueError(task + " model feature order mismatch")
        model = XGBoostBaseline.load(root / task)
        if model.booster.num_features() != len(FLOW_FEATURE_NAMES):
            raise ValueError("model feature width mismatch")
        allowed = set(catalogue.by_id) if task == "configuration" else {"WEB", "VIDEO", "VOIP", "BULK_FILE", "INTERACTIVE_MESSAGING", "ICMP_CONTROL"}
        if not set(model.classes) <= allowed:
            raise ValueError("unknown model classes")
        models[task] = model
    cal = read_json(root / "calibration.json")
    scaler = TemperatureScaler(**cal["temperature"])
    gate = OpenWorldGate(**cal["open_world_gate"])
    conformal = SplitConformalCalibrator(**cal["conformal"])
    if not all(math.isfinite(float(x)) for x in (scaler.temperature, gate.threshold, conformal.threshold, conformal.alpha)):
        raise ValueError("invalid calibration numbers")
    if not (scaler.temperature > 0 and 0 <= gate.threshold <= 1 and 0 <= conformal.threshold <= 1 and 0 < conformal.alpha < 1
            and scaler.calibration_count > 0 and gate.calibration_count > 0 and conformal.sample_count > 0):
        raise ValueError("invalid calibration parameters")
    parts = read_json(root / "partitions.json")
    for a, b in (("train_ids", "temperature_ids"), ("train_ids", "gate_ids"), ("temperature_ids", "gate_ids"), ("train_ids", "conformal_ids")):
        if set(parts[a]) & set(parts[b]):
            raise ValueError("training/calibration overlap")
    if not parts.get("replicate_group_disjoint") or not parts.get("test_ids_untouched"):
        raise ValueError("missing leakage checks")
    return DeploymentBundle(root, manifest, TemperatureCalibratedModel(models["application"], scaler), models["configuration"], conformal, gate)
