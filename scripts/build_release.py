#!/usr/bin/env python3
"""Build a deterministic source/reproducibility archive with a hash manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from common.provenance import stable_hash
from scripts.prepare_safe_review import FORBIDDEN_NAMES, FORBIDDEN_SUFFIXES, has_secret
from scripts.validate_repository import validate


EXCLUDED_PARTS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "artifacts",
    "build",
    "dist",
    "manuscript",
    "prebuilt",
    "qa",
    "qa_student_runbook",
    "work",
}


def _included_files() -> list[Path]:
    files = []
    for path in ROOT.rglob("*"):
        relative = path.relative_to(ROOT)
        if not path.is_file() or path.is_symlink() or any(part in EXCLUDED_PARTS or part.endswith(".egg-info") for part in relative.parts):
            continue
        if relative.parts[:2] == ("data", "generated") or path.name in FORBIDDEN_NAMES:
            continue
        if path.suffix.lower() in FORBIDDEN_SUFFIXES and relative.as_posix() != "examples/synthetic_demo/synthetic_ikev2_esp.pcap":
            continue
        if path.name.startswith(".env") or path.suffix.lower() in {".zip", ".7z"}:
            continue
        if path.suffix in {".pyc", ".pyo"} or path.name == ".DS_Store":
            continue
        files.append(path)
    return sorted(files, key=lambda path: path.relative_to(ROOT).as_posix())


def build_archive(destination: str | Path, *, run_tests: bool = True, version: str = "0.2.5") -> dict:
    repository_validation = validate()
    if not repository_validation["valid"]:
        raise RuntimeError(f"repository validation failed: {repository_validation['problems']}")
    if run_tests:
        subprocess.run(
            [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
            cwd=ROOT,
            check=True,
            timeout=300,
        )
    files = _included_files()
    entries = []
    for path in files:
        content = path.read_bytes()
        if path.suffix.lower() in {".py", ".json", ".yaml", ".yml", ".conf", ".txt", ".md"} and has_secret(path, content):
            raise RuntimeError(f"potential credential in source file: {path.relative_to(ROOT)}")
        entries.append({
            "path": path.relative_to(ROOT).as_posix(),
            "size_bytes": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
        })
    embedded_manifest = {
        "release_schema": "0.1.0",
        "project": "VPNGUARD-X",
        "version": version,
        "file_count": len(entries),
        "files": entries,
        "repository_validation": repository_validation,
        "verification_command": "python -m unittest discover -s tests -v",
        "empirical_results": "TBD — requires experiment",
    }
    embedded_manifest["release_id"] = stable_hash(embedded_manifest)
    manifest_bytes = (json.dumps(embedded_manifest, indent=2, sort_keys=True) + "\n").encode()
    selected = Path(destination).resolve()
    selected.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(selected, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in files:
            relative = Path("VPNGUARD-X") / path.relative_to(ROOT)
            info = zipfile.ZipInfo(relative.as_posix(), date_time=(2026, 9, 14, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (0o755 if path.stat().st_mode & 0o111 else 0o644) << 16
            archive.writestr(info, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
        info = zipfile.ZipInfo("VPNGUARD-X/RELEASE_MANIFEST.json", date_time=(2026, 9, 14, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = 0o644 << 16
        archive.writestr(info, manifest_bytes, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    result = {
        "archive": str(selected),
        "archive_size_bytes": selected.stat().st_size,
        "archive_sha256": hashlib.sha256(selected.read_bytes()).hexdigest(),
        "release_id": embedded_manifest["release_id"],
        "version": version,
        "source_file_count": len(entries),
        "tests_executed": run_tests,
        "empirical_results": "TBD — requires experiment",
    }
    selected.with_suffix(selected.suffix + ".manifest.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--version", default="0.2.5")
    parser.add_argument("--skip-tests", action="store_true")
    args = parser.parse_args()
    print(json.dumps(build_archive(args.output, run_tests=not args.skip_tests, version=args.version), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
