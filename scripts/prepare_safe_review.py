#!/usr/bin/env python3
"""Audit a local range and package review evidence without captures or keys.

Run this on the student's full lab copy. The report inventories all completed
run directories; the ZIP contains only allowlisted evidence files. This is a
private-review bundle, not a public dataset release or a Git-history audit.
"""

from __future__ import annotations

import argparse
import ast
import csv
import hashlib
import json
import re
import subprocess
import sys
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


PATTERNS = (
    "artifacts/environment/preflight.json",
    "artifacts/audits/*.json",
    "artifacts/plans/*.csv",
    "artifacts/plans/*.manifest.json",
    "artifacts/range/batch-*-manifest.json",
    "artifacts/range/incomplete-capture-manifest.json",
    "artifacts/range/**/ground_truth.json",
    "artifacts/range/**/scenario_manifest.json",
    "artifacts/range/**/*.pcap.loss.json",
    "artifacts/splits/**/*.json",
    "artifacts/results*/aggregate-results.json",
    "artifacts/results*/bootstrap-confidence-intervals.json",
    "artifacts/results*/bootstrap*.json",
    "artifacts/results*/system-latency.json",
    "artifacts/results*/latency*.json",
    "artifacts/results*/manuscript-results.csv",
    "artifacts/results*/manuscript-results.md",
    "artifacts/results*/dry-run.json",
    "artifacts/results*/**/metrics.json",
    "data/generated/*.manifest.json",
)
MAX_FILE_BYTES = 25 * 1024 * 1024
MAX_BUNDLE_BYTES = 100 * 1024 * 1024
SECRET_ASSIGNMENT = re.compile(
    rb"(?im)^\s*[\"']?(?:secret|psk|password|passphrase|private_key|api_key|access_token|client_secret|session_key)"
    rb"[\"']?\s*[:=]\s*[\"']?([^\s\"']+)"
)
PRIVATE_KEY = re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----")
SENSITIVE_KEYS = {"secret", "psk", "password", "passphrase", "private_key", "api_key", "access_token", "client_secret", "session_key"}
FORBIDDEN_NAMES = {"swanctl.conf", "ipsec.secrets"}
FORBIDDEN_SUFFIXES = {".pcap", ".pcapng", ".raw", ".key", ".pem", ".p12", ".pfx", ".secrets"}
GENERATED_DIRS = {"artifacts", "build", "dist", "manuscript", ".venv", "venv", "__pycache__"}


def digest(path: Path) -> str:
    sha = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            sha.update(chunk)
    return sha.hexdigest()


def has_secret(path: Path, content: bytes) -> bool:
    if PRIVATE_KEY.search(content):
        return True
    if path.suffix == ".json":
        try:
            document = json.loads(content)
        except (UnicodeDecodeError, ValueError):
            return True
        pending = [document]
        while pending:
            node = pending.pop()
            if isinstance(node, dict):
                for key, value in node.items():
                    if str(key).lower() in SENSITIVE_KEYS and value not in (None, False, "", "<REDACTED>"):
                        return True
                    if isinstance(value, (dict, list)):
                        pending.append(value)
            elif isinstance(node, list):
                pending.extend(item for item in node if isinstance(item, (dict, list)))
        return False
    if path.suffix == ".py":
        try:
            syntax = ast.parse(content.decode("utf-8"))
        except (SyntaxError, UnicodeDecodeError):
            return True
        for node in ast.walk(syntax):
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                if any(isinstance(target, ast.Name) and target.id.lower() in SENSITIVE_KEYS for target in targets):
                    value = node.value
                    if isinstance(value, ast.Constant) and isinstance(value.value, str) and value.value:
                        return True
            if isinstance(node, ast.keyword) and node.arg and node.arg.lower() in SENSITIVE_KEYS:
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str) and node.value.value:
                    return True
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if SECRET_ASSIGNMENT.search(node.value.encode("utf-8")):
                    return True
        return False
    for found in SECRET_ASSIGNMENT.finditer(content):
        value = found.group(1).lstrip(b"\\")
        if not (value.startswith((b"{", b"$", b"<")) or value.lower() in {b"null", b"none", b"false"}):
            return True
    return False


def git_index_audit(project: Path) -> dict:
    """Check staged/tracked paths, without claiming to scan Git history."""
    try:
        root = subprocess.run(
            ["git", "-C", str(project), "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, check=False,
        )
    except FileNotFoundError:
        return {"repository_detected": False, "git_available": False,
                "tracked_count": 0, "issues": [], "history_scanned": False}
    if root.returncode != 0 or Path(root.stdout.strip()).resolve() != project:
        return {"repository_detected": False, "tracked_count": 0, "issues": [], "history_scanned": False}
    listed = subprocess.run(
        ["git", "-C", str(project), "ls-files", "--cached", "-z"],
        capture_output=True, check=True,
    )
    names = [x.decode("utf-8", errors="replace") for x in listed.stdout.split(b"\0") if x]
    issues: list[str] = []
    for name in names:
        path = project / name
        parts = Path(name).parts
        if not parts or not path.is_file():
            continue
        if any(part in GENERATED_DIRS for part in parts) or (
            len(parts) > 1 and (parts[:2] == ("data", "generated") or parts[:2] == ("models", "artifacts")
                                or parts[:2] == ("manuscript", "qa") or parts[:2] == ("manuscript", "work"))
        ):
            issues.append(f"tracked generated file: {name}")
        if path.is_symlink() or not path.resolve().is_relative_to(project):
            issues.append(f"tracked symlink: {name}")
            continue
        if path.name in FORBIDDEN_NAMES or path.suffix.lower() in FORBIDDEN_SUFFIXES:
            if name != "examples/synthetic_demo/synthetic_ikev2_esp.pcap":
                issues.append(f"tracked confidential/binary type: {name}")
            continue
        if path.stat().st_size > 100 * 1024 * 1024:
            issues.append(f"tracked file exceeds 100 MiB: {name}")
        elif path.stat().st_size <= MAX_FILE_BYTES and path.suffix.lower() in {".txt", ".json", ".yaml", ".yml", ".conf", ".py", ".md", ".env"}:
            data = path.read_bytes()
            if has_secret(path, data):
                issues.append(f"possible credential in tracked text: {name}")
    return {"repository_detected": True, "tracked_count": len(names), "issues": issues, "history_scanned": False}


def inventory(project: Path, *, verify_pcaps: bool = True) -> dict:
    range_root = project / "artifacts/range"
    outcomes: Counter[str] = Counter()
    stacks: Counter[str] = Counter()
    seeds: Counter[str] = Counter()
    variants: Counter[str] = Counter()
    issues: list[str] = []
    total_truth = 0
    full_manifest_checked = 0
    full_manifest_mismatches = 0
    for truth_path in sorted(range_root.rglob("ground_truth.json")) if range_root.exists() else []:
        total_truth += 1
        rel = truth_path.relative_to(project).as_posix()
        try:
            truth = json.loads(truth_path.read_text(encoding="utf-8"))
            capture = truth["capture"]
            name = capture["pcap_file"]
            if name != "capture.pcap":
                issues.append(f"{rel}: unexpected capture filename")
                continue
            pcap = truth_path.parent / name
            if not pcap.is_file() or pcap.is_symlink():
                issues.append(f"{rel}: capture missing or symlinked")
            elif verify_pcaps and digest(pcap) != capture["sha256"]:
                issues.append(f"{rel}: capture SHA-256 mismatch")
            if truth.get("secrets_or_session_keys_in_record") is not False:
                issues.append(f"{rel}: secret exclusion not asserted")
            outcomes[str(truth.get("outcome"))] += 1
            stacks[str(truth.get("stack"))] += 1
            seeds[str(truth.get("seed"))] += 1
            variants[str(capture.get("capture_variant"))] += 1
            if capture.get("capture_variant") == "FULL" and truth.get("scenario_manifest_hash"):
                manifest_path = truth_path.parent / "scenario_manifest.json"
                if not manifest_path.is_file():
                    issues.append(f"{rel}: scenario manifest missing")
                else:
                    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                    full_manifest_checked += 1
                    if manifest.get("manifest_hash") != truth.get("scenario_manifest_hash"):
                        full_manifest_mismatches += 1
        except (OSError, ValueError, TypeError, KeyError) as exc:
            issues.append(f"{rel}: invalid ground truth ({type(exc).__name__})")
    if full_manifest_mismatches:
        issues.append(
            f"{full_manifest_mismatches}/{full_manifest_checked} FULL scenario manifests do not match executed ground truth"
        )
    plans = {}
    for plan in sorted((project / "artifacts/plans").glob("*.csv")) if (project / "artifacts/plans").exists() else []:
        with plan.open(newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        existing = sum((range_root / row["run_id"] / f"seed-{row['seed']}" / "ground_truth.json").is_file() for row in rows)
        plans[plan.name] = {"planned": len(rows), "ground_truth_present": existing}
    result_roots = {}
    artifacts_root = project / "artifacts"
    for result_root in sorted(artifacts_root.glob("results*")) if artifacts_root.exists() else []:
        if not result_root.is_dir():
            continue
        metric_paths = list(result_root.rglob("metrics.json"))
        loss_keys: Counter[str] = Counter()
        dedicated_ood_null = 0
        for metric_path in metric_paths:
            try:
                metric = json.loads(metric_path.read_text(encoding="utf-8"))
                values = metric.get("metrics", metric)
                incomplete = values.get("incomplete_capture", {})
                if isinstance(incomplete, dict):
                    loss_keys.update(str(key) for key in incomplete)
                if metric.get("split_id") == "UNSEEN_APPLICATION_OOD":
                    ood = values.get("ood", {})
                    if not isinstance(ood, dict) or ood.get("auroc") is None or ood.get("fpr95") is None:
                        dedicated_ood_null += 1
            except (OSError, ValueError, TypeError):
                issues.append(f"{metric_path.relative_to(project).as_posix()}: invalid metrics JSON")
        result_roots[result_root.name] = {
            "metric_file_count": len(metric_paths),
            "aggregate_results_present": (result_root / "aggregate-results.json").is_file(),
            "loss_metric_key_counts": dict(sorted(loss_keys.items())),
            "dedicated_ood_null_metric_count": dedicated_ood_null,
        }
    return {
        "ground_truth_count": total_truth,
        "verified_pcap_hashes": verify_pcaps,
        "outcomes": dict(sorted(outcomes.items())),
        "stacks": dict(sorted(stacks.items())),
        "seeds": dict(sorted(seeds.items())),
        "capture_variants": dict(sorted(variants.items())),
        "plan_coverage": plans,
        "scenario_manifest_provenance": {
            "full_manifests_checked": full_manifest_checked,
            "hash_mismatch_count": full_manifest_mismatches,
        },
        "result_roots": result_roots,
        "integrity_issues": issues,
    }


def make_bundle(project: Path, destination: Path, *, verify_pcaps: bool = True) -> dict:
    project = project.resolve()
    destination = destination.resolve()
    if destination.is_relative_to(project):
        raise ValueError("put the review ZIP outside the project to prevent accidental Git inclusion")
    report = inventory(project, verify_pcaps=verify_pcaps)
    report["git_index_audit"] = git_index_audit(project)
    selected: set[Path] = set()
    for pattern in PATTERNS:
        selected.update(project.glob(pattern))
    paths = sorted((p for p in selected if p.is_file()), key=lambda p: p.relative_to(project).as_posix())
    omitted: list[str] = []
    included: list[tuple[Path, bytes]] = []
    total_bytes = 0
    for path in paths:
        relative = path.relative_to(project).as_posix()
        if path.is_symlink() or not path.resolve().is_relative_to(project):
            raise ValueError(f"refusing link outside project: {relative}")
        if path.name in FORBIDDEN_NAMES or path.suffix.lower() in FORBIDDEN_SUFFIXES:
            raise ValueError(f"refusing confidential or binary file: {relative}")
        size = path.stat().st_size
        if size > MAX_FILE_BYTES or total_bytes + size > MAX_BUNDLE_BYTES:
            omitted.append(relative)
            continue
        content = path.read_bytes()
        if has_secret(path, content):
            raise ValueError(f"potential credential in allowlisted file: {relative}")
        included.append((path, content))
        total_bytes += len(content)
    report.update({
        "schema": "safe-review-1",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "included_file_count": len(included),
        "omitted_due_to_size": omitted,
        "contains_raw_pcaps": False,
        "contains_endpoint_configs_or_raw_telemetry": False,
        "scope": "private review; Git history and non-allowlisted files have not been secret-scanned",
    })
    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as bundle:
        for path, content in included:
            bundle.writestr(path.relative_to(project).as_posix(), content)
        bundle.writestr("REVIEW_INVENTORY.json", json.dumps(report, indent=2, sort_keys=True) + "\n")
    report["bundle_bytes"] = destination.stat().st_size
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path, required=True, help="ZIP outside the project directory")
    parser.add_argument("--skip-pcap-hashes", action="store_true", help="only for a fast preliminary inventory")
    args = parser.parse_args()
    report = make_bundle(args.project, args.output, verify_pcaps=not args.skip_pcap_hashes)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 1 if report["integrity_issues"] or report["omitted_due_to_size"] or report["git_index_audit"]["issues"] else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError) as exc:
        sys.exit(f"Review bundle stopped: {exc}")
