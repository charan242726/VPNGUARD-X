#!/usr/bin/env python3
"""Compile and run authorized strongSwan/Libreswan scenarios in an isolated range.

No command accepts an arbitrary network target.  Scenario endpoints are fixed
private/ULA addresses in ``compose.yaml`` and traffic.py enforces the same set.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from common.provenance import sha256_file, stable_hash
from observability import cooperative_evidence_from_swanctl, cooperative_evidence_from_xfrm
from parser import analyze_pcap
from experiments.incomplete_capture import filter_pcap, thin_pcap


DEFAULT_MATRIX = ROOT / "data/CyberRange_Scenario_Matrix.csv"
COMPOSE_FILE = ROOT / "cyber_range/compose.yaml"
LIBRESWAN_COMPOSE_FILE = ROOT / "cyber_range/compose.libreswan.yaml"
SAFE_SCENARIO_ID = re.compile(r"^[A-Z0-9_-]+$")
STACK_STRONGSWAN = "strongSwan-6.1.0"
STACK_INTEROP = "strongSwan-6.1.0-to-Libreswan-5.4"
LIBRESWAN_COMMIT = "5eb03b7772b312e705feab9ad5868678a3c007e6"


def _is_interop_stack(stack: str) -> bool:
    return stack == STACK_INTEROP


@dataclass(frozen=True)
class CompiledScenario:
    scenario_id: str
    seed: int
    run_directory: str
    scenario: dict[str, str]
    configured_properties: dict[str, Any]
    manifest_hash: str
    source_scenario_id: str | None = None
    stack: str = STACK_STRONGSWAN


def load_scenarios(matrix_path: str | Path = DEFAULT_MATRIX) -> dict[str, dict[str, str]]:
    selected = Path(matrix_path)
    with selected.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    result = {row["scenario_id"]: row for row in rows}
    if len(result) != len(rows):
        raise ValueError("scenario IDs must be unique")
    return result


def _addresses(row: dict[str, str]) -> dict[str, str]:
    ipv6 = row["ip_version"] == "6"
    natt = row["path_mode"] == "NAT_T"
    if ipv6:
        left_outer, right_outer = "fd00:80::10", "fd00:80::20"
        left_ts, right_ts = "fd00:11::/64", "fd00:22::/64"
        client, server = "fd00:11::20", "fd00:22::20"
    else:
        left_outer = "10.81.0.10" if natt else "10.80.0.10"
        right_outer = "10.80.0.20"
        left_ts, right_ts = "10.11.0.0/24", "10.22.0.0/24"
        client, server = "10.11.0.20", "10.22.0.20"
    if row["mode"] == "TRANSPORT":
        left_ts, right_ts = left_outer, right_outer
    return {
        "left_outer": left_outer,
        "right_outer": right_outer,
        "left_ts": left_ts,
        "right_ts": right_ts,
        "client": client,
        "server": server,
    }


def _canonical_properties(row: dict[str, str]) -> dict[str, Any]:
    ike_parts = row["ike_proposal"].split("-")
    child_parts = row["child_proposal"].split("-")
    encryption_names = {
        "aes128gcm16": "ENCR_AES_GCM_16_128",
        "aes128": "ENCR_AES_CBC_128",
        "aes256gcm16": "ENCR_AES_GCM_16_256",
        "aes256": "ENCR_AES_CBC_256",
        "chacha20poly1305": "ENCR_CHACHA20_POLY1305",
        "3des": "ENCR_3DES",
    }
    group_names = {
        "modp1024": 2,
        "modp1536": 5,
        "modp2048": 14,
        "ecp256": 19,
        "ecp384": 20,
        "curve25519": 31,
    }
    ike_encryption = encryption_names.get(ike_parts[0], ike_parts[0].upper())
    child_encryption = encryption_names.get(child_parts[0], child_parts[0].upper())
    ike_integrity = "AUTH_NONE" if any(token in ike_parts[0] for token in ("gcm", "poly1305", "ccm")) else (
        "AUTH_HMAC_SHA2_256_128" if "sha256" in ike_parts else "AUTH_HMAC_SHA1_96" if "sha1" in ike_parts else "UNKNOWN"
    )
    child_integrity = "AUTH_NONE" if any(token in child_parts[0] for token in ("gcm", "poly1305", "ccm")) else (
        "AUTH_HMAC_SHA2_256_128" if "sha256" in child_parts else "AUTH_HMAC_SHA1_96" if "sha1" in child_parts else "UNKNOWN"
    )
    default_prf = "prfsha256" if row["ike_version"] == "IKEV1" and "sha256" in ike_parts else "sha1" if row["ike_version"] == "IKEV1" else ""
    prf = next((token for token in ike_parts if token.startswith("prf")), default_prf)
    prf_names = {"prfsha256": "PRF_HMAC_SHA2_256", "prfsha384": "PRF_HMAC_SHA2_384", "sha1": "PRF_HMAC_SHA1"}
    group_token = next((token for token in ike_parts if token in group_names), "")
    return {
        "ike.version": row["ike_version"],
        "outer.ip_version": int(row["ip_version"]),
        "encapsulation": "UDP_ENCAPSULATED_ESP" if row["path_mode"] in {"NAT_T", "FORCED_UDP_4500"} else "NATIVE_ESP",
        "child.mode": row["mode"],
        "ike.selected_encryption": ike_encryption,
        "ike.selected_integrity": ike_integrity,
        "ike.selected_prf": prf_names.get(prf, prf.upper() or "UNKNOWN"),
        "ike.initial_ke_group": group_names.get(group_token, "UNKNOWN"),
        "child.encryption": child_encryption,
        "child.integrity": child_integrity,
        "child.pfs_group": int(row["child_pfs_group"]) if row["child_pfs_group"].isdigit() else "NONE",
        "child.esn": False,
        "child.anti_replay_enabled": True,
        "sa.configured_lifetime": 3600,
        "ike.authentication_family": "PSK",
        "inner.application_class": row["application_class"],
    }


def _swanctl_config(row: dict[str, str], side: str, psk: str, *, use_address_ids: bool = False) -> str:
    address = _addresses(row)
    local_outer = address[f"{side}_outer"]
    remote_side = "right" if side == "left" else "left"
    remote_outer = address[f"{remote_side}_outer"]
    local_ts = address[f"{side}_ts"]
    remote_ts = address[f"{remote_side}_ts"]
    local_id = local_outer if use_address_ids else f"{side}@vpnguard-x.invalid"
    remote_id = remote_outer if use_address_ids else f"{remote_side}@vpnguard-x.invalid"
    version = "2" if row["ike_version"] == "IKEV2" else "1"
    forced_encap = row["path_mode"] == "FORCED_UDP_4500"
    # A NATed responder accepts a roaming source address; the authenticated ID remains fixed.
    configured_remote = "%any" if side == "right" and row["path_mode"] == "NAT_T" else remote_outer
    encap_line = "        encap = yes\n" if forced_encap else ""
    return f"""connections {{
    vgx {{
        version = {version}
        local_addrs = {local_outer}
        remote_addrs = {configured_remote}
        proposals = {row['ike_proposal']}
        mobike = no
        reauth_time = 0s
{encap_line}        local {{
            auth = psk
            id = {local_id}
        }}
        remote {{
            auth = psk
            id = {remote_id}
        }}
        children {{
            protected {{
                local_ts = {local_ts}
                remote_ts = {remote_ts}
                mode = {row['mode'].lower()}
                esp_proposals = {row['child_proposal']}
                replay_window = 32
                life_time = 3600s
                rekey_time = 3300s
                start_action = none
            }}
        }}
    }}
}}
secrets {{
    ike-vgx {{
        id-left = {address['left_outer'] if use_address_ids else 'left@vpnguard-x.invalid'}
        id-right = {address['right_outer'] if use_address_ids else 'right@vpnguard-x.invalid'}
        secret = \"{psk}\"
    }}
}}
"""


def _libreswan_algorithms(row: dict[str, str]) -> tuple[str, str]:
    """Translate the deliberately small validated interop proposal subset."""
    mappings = {
        (
            "aes256gcm16-prfsha384-ecp256",
            "aes256gcm16-ecp256",
        ): ("aes_gcm256-sha2_384;dh19", "aes_gcm256;dh19"),
        (
            "aes256-sha256-prfsha256-modp2048",
            "aes256-sha256-modp2048",
        ): ("aes256-sha2_256;dh14", "aes256-sha2_256;dh14"),
    }
    key = (row["ike_proposal"], row["child_proposal"])
    if key not in mappings:
        raise ValueError("configuration is outside the declared strongSwan-to-Libreswan interoperability subset")
    return mappings[key]


def _libreswan_config(row: dict[str, str]) -> str:
    if row["ike_version"] != "IKEV2" or row["ip_version"] != "4" or row["path_mode"] != "NATIVE_ESP":
        raise ValueError("initial Libreswan interop runner supports IKEv2/IPv4/native ESP only")
    address = _addresses(row)
    ike, esp = _libreswan_algorithms(row)
    pfs = "no" if row["child_pfs_group"] == "NONE" else "yes"
    return f"""config setup
    plutodebug=none

conn vgx
    type={row['mode'].lower()}
    keyexchange=ikev2
    authby=secret
    left={address['left_outer']}
    leftid={address['left_outer']}
    leftsubnet={address['left_ts']}
    right={address['right_outer']}
    rightid={address['right_outer']}
    rightsubnet={address['right_ts']}
    ike={ike}
    esp={esp}
    pfs={pfs}
    encapsulation=no
    ikelifetime=8h
    salifetime=1h
    rekey=no
    auto=add
"""


def _compile_row(
    run_id: str,
    source_scenario_id: str,
    row: dict[str, str],
    seed: int,
    output_root: str | Path,
    *,
    matrix_path: str | Path,
) -> CompiledScenario:
    if not SAFE_SCENARIO_ID.fullmatch(run_id):
        raise ValueError("run ID contains unsafe characters")
    if row["enabled"].lower() != "true":
        raise ValueError("scenario is disabled; enable only after documenting the required stack/plugin validation")
    declared_seeds = {int(value) for value in row["replicate_seeds"].split("|")}
    if seed not in declared_seeds:
        raise ValueError(f"seed {seed} is not declared for reproducible scenario {source_scenario_id}")
    stack = row.get("stack", STACK_STRONGSWAN)
    if not (stack.startswith("strongSwan-6.1.0") or _is_interop_stack(stack)):
        raise ValueError(f"unsupported cyber-range stack: {stack}")
    compose_file = LIBRESWAN_COMPOSE_FILE if _is_interop_stack(stack) else COMPOSE_FILE
    if not compose_file.is_file():
        raise ValueError(f"compose definition is missing for stack {stack}: {compose_file}")
    run_directory = Path(output_root).resolve() / run_id / f"seed-{seed}"
    (run_directory / "left").mkdir(parents=True, exist_ok=True)
    (run_directory / "right").mkdir(parents=True, exist_ok=True)
    psk = hashlib.sha256(f"VPNGUARD-X-RANGE:{run_id}:{seed}".encode()).hexdigest()
    left_path = run_directory / "left/swanctl.conf"
    left_path.write_text(_swanctl_config(row, "left", psk, use_address_ids=_is_interop_stack(stack)), encoding="utf-8")
    left_path.chmod(0o600)
    if _is_interop_stack(stack):
        right_config = run_directory / "right/ipsec.conf"
        right_secrets = run_directory / "right/ipsec.secrets"
        right_config.write_text(_libreswan_config(row), encoding="utf-8")
        addresses = _addresses(row)
        right_secrets.write_text(
            f"{addresses['left_outer']} {addresses['right_outer']} : PSK \"{psk}\"\n",
            encoding="utf-8",
        )
        right_config.chmod(0o600)
        right_secrets.chmod(0o600)
    else:
        right_path = run_directory / "right/swanctl.conf"
        right_path.write_text(_swanctl_config(row, "right", psk), encoding="utf-8")
        right_path.chmod(0o600)
    manifest = {
        "schema_version": "0.2.0",
        "status": "COMPILED_NOT_EXECUTED",
        "scenario_id": run_id,
        "source_scenario_id": source_scenario_id,
        "seed": seed,
        "stack": stack,
        "scenario": row,
        "configured_properties": _canonical_properties(row),
        "addresses": _addresses(row),
        "matrix_sha256": sha256_file(matrix_path),
        "compose_sha256": sha256_file(compose_file),
        "strongswan_version": "6.1.0",
        "strongswan_source_sha256": "fe6c97481298767213cfc2e9a1da29fdd8018d481ff4cb9cf0283099654f20d4",
        "libreswan_version": "5.4" if _is_interop_stack(stack) else None,
        "libreswan_source_commit": LIBRESWAN_COMMIT if _is_interop_stack(stack) else None,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "secret_material_in_manifest": False,
    }
    manifest_hash = stable_hash(manifest)
    manifest["manifest_hash"] = manifest_hash
    (run_directory / "scenario_manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return CompiledScenario(
        run_id,
        seed,
        str(run_directory),
        row,
        manifest["configured_properties"],
        manifest_hash,
        source_scenario_id,
        stack,
    )


def compile_scenario(
    scenario_id: str,
    seed: int,
    output_root: str | Path,
    *,
    matrix_path: str | Path = DEFAULT_MATRIX,
) -> CompiledScenario:
    scenarios = load_scenarios(matrix_path)
    if scenario_id not in scenarios:
        raise KeyError(f"unknown scenario ID: {scenario_id}")
    return _compile_row(scenario_id, scenario_id, dict(scenarios[scenario_id]), seed, output_root, matrix_path=matrix_path)


def compile_planned_run(
    plan_row: dict[str, str],
    output_root: str | Path,
    *,
    matrix_path: str | Path = DEFAULT_MATRIX,
) -> CompiledScenario:
    required = {
        "run_id", "base_scenario_id", "seed", "application_class",
        "application_profile", "capture_variant", "stack",
    }
    missing = sorted(required - set(plan_row))
    if missing:
        raise ValueError(f"plan row is missing fields: {missing}")
    scenarios = load_scenarios(matrix_path)
    source_id = plan_row["base_scenario_id"]
    if source_id not in scenarios:
        raise KeyError(f"unknown base scenario ID: {source_id}")
    row = dict(scenarios[source_id])
    for field in ("application_class", "application_profile", "capture_variant", "stack"):
        row[field] = plan_row[field]
    row["scenario_id"] = plan_row["run_id"]
    return _compile_row(
        plan_row["run_id"],
        source_id,
        row,
        int(plan_row["seed"]),
        output_root,
        matrix_path=matrix_path,
    )


def _compose_command(
    project: str,
    compose_file: Path,
    *arguments: str,
    env_file: Path | None = None,
) -> list[str]:
    command = ["docker", "compose"]
    if env_file is not None:
        # Compose interpolation must receive this explicitly.  Some elevated
        # Docker launchers intentionally discard the child process environment.
        command.extend(["--env-file", str(env_file)])
    return [*command, "-f", str(compose_file), "-p", project, *arguments]


def _run(command: list[str], *, env: dict[str, str], check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=ROOT, env=env, check=check, text=True, capture_output=True, timeout=1800)


def _redact_xfrm(text: str) -> str:
    pattern = re.compile(r"\b(aead|auth-trunc|auth|enc)(\s+\S+\s+)0x[0-9a-fA-F]+", re.IGNORECASE)
    return pattern.sub(r"\1\2<REDACTED>", text)


def _ledger_values(ledger: Any) -> dict[str, Any]:
    return {record.property_name: record.value for record in ledger.records if record.value is not None}


def run_scenario(compiled: CompiledScenario, *, keep_range: bool = False) -> Path:
    if shutil.which("docker") is None:
        raise RuntimeError("Docker with the Compose plugin is required to execute the cyber-range")
    run_directory = Path(compiled.run_directory)
    project = "vgx" + hashlib.sha256(f"{compiled.scenario_id}:{compiled.seed}".encode()).hexdigest()[:10]
    env = dict(os.environ)
    env["VGX_RUN_DIR"] = str(run_directory)
    compose_env = run_directory / "compose.env"
    compose_env.write_text(f"VGX_RUN_DIR={run_directory}\n", encoding="utf-8")
    row = compiled.scenario
    compose_file = LIBRESWAN_COMPOSE_FILE if _is_interop_stack(compiled.stack) else COMPOSE_FILE
    addresses = _addresses(row)
    outcome = "FAILED"
    failure_reason: str | None = None
    command_log: list[dict[str, Any]] = []

    def compose(*arguments: str) -> list[str]:
        return _compose_command(project, compose_file, *arguments, env_file=compose_env)

    def invoke(service: str, *arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        command = compose("exec", "-T", service, *arguments)
        result = _run(command, env=env, check=check)
        command_log.append({"service": service, "arguments": list(arguments), "returncode": result.returncode})
        return result

    try:
        _run(compose("up", "--detach", "--build"), env=env)
        if row["path_mode"] == "NAT_T":
            invoke("left", "ip", "route", "replace", "10.80.0.20/32", "via", "10.81.0.1", "src", "10.81.0.10")
        # Background inside the service instead of Compose's detached-exec
        # flag: this is compatible with Compose implementations that do not
        # support `exec -d`.
        invoke(
            "right",
            "sh",
            "-c",
            "tcpdump -i any -U -s 0 -w /scenario/capture.full.tmp "
            "'udp port 500 or udp port 4500 or ip proto 50 or ip6 proto 50' "
            ">/scenario/tcpdump.log 2>&1 &",
        )
        time.sleep(1)
        if not _is_interop_stack(compiled.stack):
            invoke("right", "swanctl", "--load-all")
        else:
            invoke("right", "ipsec", "status")
        invoke("left", "swanctl", "--load-all")
        invoke("left", "swanctl", "--initiate", "--child", "protected", "--timeout", "20")
        time.sleep(2)
        traffic_service = "left_client"
        traffic_target = addresses["server"]
        if row["mode"] == "TRANSPORT":
            invoke("right", "sh", "-c", "python3 /opt/vgx/traffic_server.py >/scenario/transport-server.log 2>&1 &")
            traffic_service = "left"
            traffic_target = addresses["right_outer"]
        invoke(
            traffic_service,
            "python3",
            "/opt/vgx/traffic.py",
            "--class",
            row["application_class"],
            "--target",
            traffic_target,
            "--seed",
            str(compiled.seed),
            "--profile",
            row["application_profile"],
        )
        invoke("right", "sh", "-c", "pkill -INT tcpdump || true; sleep 2")
        left_sas = invoke("left", "swanctl", "--list-sas", "--raw").stdout
        right_sas = (
            invoke("right", "swanctl", "--list-sas", "--raw").stdout
            if not _is_interop_stack(compiled.stack)
            else invoke("right", "ipsec", "showstates").stdout + "\n" + invoke("right", "ipsec", "trafficstatus").stdout
        )
        left_xfrm = _redact_xfrm(invoke("left", "ip", "-s", "xfrm", "state").stdout)
        right_xfrm = _redact_xfrm(invoke("right", "ip", "-s", "xfrm", "state").stdout)
        (run_directory / "left_sas.raw").write_text(left_sas, encoding="utf-8")
        (run_directory / "right_sas.raw").write_text(right_sas, encoding="utf-8")
        (run_directory / "left_xfrm.redacted.txt").write_text(left_xfrm, encoding="utf-8")
        (run_directory / "right_xfrm.redacted.txt").write_text(right_xfrm, encoding="utf-8")
        if "protected" not in left_sas:
            raise RuntimeError("CHILD-SA was not present in strongSwan endpoint state")
        if not _is_interop_stack(compiled.stack) and "protected" not in right_sas:
            raise RuntimeError("CHILD-SA was not present in strongSwan responder state")
        if _is_interop_stack(compiled.stack) and "ESP" not in right_sas.upper():
            raise RuntimeError("CHILD-SA was not present in Libreswan responder state")
        if "proto esp" not in left_xfrm.lower() or "proto esp" not in right_xfrm.lower():
            raise RuntimeError("ESP XFRM state was not established at both endpoints")
        full_capture = run_directory / "capture.full.tmp"
        if not full_capture.exists() or full_capture.stat().st_size < 24:
            raise RuntimeError("outer capture was not created")
        full_analysis = analyze_pcap(full_capture)
        if not full_analysis.ike_sessions or not full_analysis.esp_flows:
            raise RuntimeError("outer capture lacks a reconstructed IKE session or ESP flow")
        final_capture = run_directory / "capture.pcap"
        loss_map = {
            "LOSS_10": 0.10, "LOSS_30": 0.30, "LOSS_50": 0.50,
            "DROP_10": 0.10, "DROP_30": 0.30, "DROP_50": 0.50,
        }
        if row["capture_variant"] in loss_map:
            thin_pcap(full_capture, final_capture, loss_fraction=loss_map[row["capture_variant"]], seed=compiled.seed)
            full_capture.unlink()
        elif row["capture_variant"] in {"REMOVE_IKE_SA_INIT", "MIDSTREAM_ESP_ONLY"}:
            filter_pcap(full_capture, final_capture, variant=row["capture_variant"])
            full_capture.unlink()
        else:
            full_capture.replace(final_capture)
        outcome = "COMPLETED"
    except Exception as exc:
        failure_reason = f"{type(exc).__name__}: {exc}"
        try:
            invoke("right", "sh", "-c", "pkill -INT tcpdump || true", check=False)
        except Exception:
            pass
    finally:
        try:
            image_state = _run(compose("images", "--format", "json"), env=env, check=False).stdout
            (run_directory / "container_images.jsonl").write_text(image_state, encoding="utf-8")
            logs = _run(compose("logs", "--no-color"), env=env, check=False).stdout
            (run_directory / "range.log").write_text(logs, encoding="utf-8")
        finally:
            if not keep_range:
                _run(compose("down", "--volumes", "--remove-orphans"), env=env, check=False)

    pcap_path = run_directory / "capture.pcap"
    if not pcap_path.exists() or pcap_path.stat().st_size < 24:
        raise RuntimeError(f"range failed to produce a valid PCAP: {failure_reason or 'unknown failure'}")
    swanctl_values: dict[str, Any] = {}
    xfrm_values: dict[str, Any] = {}
    swanctl_paths = [run_directory / "left_sas.raw"]
    if not _is_interop_stack(compiled.stack):
        swanctl_paths.append(run_directory / "right_sas.raw")
    for path in swanctl_paths:
        if path.exists():
            swanctl_values.update(_ledger_values(cooperative_evidence_from_swanctl(path.read_text(encoding="utf-8"))))
    for path in (run_directory / "left_xfrm.redacted.txt", run_directory / "right_xfrm.redacted.txt"):
        if path.exists():
            xfrm_values.update(_ledger_values(cooperative_evidence_from_xfrm(path.read_text(encoding="utf-8"))))
    ground_truth = {
        "schema_version": "0.2.0",
        "scenario_id": compiled.scenario_id,
        "source_scenario_id": compiled.source_scenario_id,
        "scenario_manifest_hash": compiled.manifest_hash,
        "seed": compiled.seed,
        "stack": compiled.stack,
        "outcome": outcome,
        "failure_reason": failure_reason,
        "application": {
            "label": row["application_class"],
            "profile": row["application_profile"],
            "generator": "cyber_range/traffic.py",
        },
        "configured_properties": compiled.configured_properties,
        "observed_properties": {**swanctl_values, **xfrm_values},
        "telemetry": {
            "left_sas_sha256": sha256_file(run_directory / "left_sas.raw") if (run_directory / "left_sas.raw").exists() else None,
            "right_sas_sha256": sha256_file(run_directory / "right_sas.raw") if (run_directory / "right_sas.raw").exists() else None,
            "xfrm_key_material_redacted": True,
            "libreswan_state_parser": "NOT_IMPLEMENTED_CONFIGURED_AND_XFRM_GROUND_TRUTH_ONLY" if _is_interop_stack(compiled.stack) else None,
        },
        "capture": {
            "pcap_file": "capture.pcap",
            "sha256": sha256_file(pcap_path),
            "size_bytes": pcap_path.stat().st_size,
            "capture_filter": "udp port 500 or udp port 4500 or IP protocol 50",
            "capture_point": "right gateway, all interfaces with outer-protocol filter",
            "capture_variant": row["capture_variant"],
            "loss_manifest": (
                json.loads((pcap_path.with_suffix(pcap_path.suffix + ".loss.json")).read_text(encoding="utf-8"))
                if pcap_path.with_suffix(pcap_path.suffix + ".loss.json").exists()
                else None
            ),
            "transformation_manifest": (
                json.loads((pcap_path.with_suffix(pcap_path.suffix + ".transform.json")).read_text(encoding="utf-8"))
                if pcap_path.with_suffix(pcap_path.suffix + ".transform.json").exists()
                else None
            ),
        },
        "command_log": command_log,
        "completed_at_utc": datetime.now(timezone.utc).isoformat(),
        "secrets_or_session_keys_in_record": False,
    }
    (run_directory / "ground_truth.json").write_text(json.dumps(ground_truth, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if outcome != "COMPLETED":
        raise RuntimeError(f"scenario failed; artifacts retained with ground truth: {failure_reason}")
    return pcap_path


def validate_artifacts(root: str | Path) -> list[str]:
    problems: list[str] = []
    pcaps = sorted(Path(root).resolve().rglob("*.pcap"))
    for pcap in pcaps:
        ground_truth_path = pcap.parent / "ground_truth.json"
        if not ground_truth_path.exists():
            problems.append(f"{pcap}: missing ground_truth.json")
            continue
        try:
            ground_truth = json.loads(ground_truth_path.read_text(encoding="utf-8"))
            capture = ground_truth["capture"]
            if capture["pcap_file"] != pcap.name:
                problems.append(f"{pcap}: ground-truth filename mismatch")
            if capture["sha256"] != sha256_file(pcap):
                problems.append(f"{pcap}: ground-truth SHA-256 mismatch")
            if ground_truth.get("secrets_or_session_keys_in_record") is not False:
                problems.append(f"{pcap}: ground truth does not assert secret exclusion")
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            problems.append(f"{ground_truth_path}: invalid ground truth ({exc})")
    if not pcaps:
        problems.append("no PCAP artifacts found")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="VPNGUARD-X isolated strongSwan range")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("compile", "run"):
        command = subparsers.add_parser(name)
        command.add_argument("--scenario", required=True)
        command.add_argument("--seed", type=int, required=True)
        command.add_argument("--output", type=Path, default=ROOT / "artifacts/range")
        command.add_argument("--matrix", type=Path, default=DEFAULT_MATRIX)
        if name == "run":
            command.add_argument("--keep-range", action="store_true")
    validate = subparsers.add_parser("validate")
    validate.add_argument("root", type=Path)
    args = parser.parse_args(argv)
    if args.command in {"compile", "run"}:
        compiled = compile_scenario(args.scenario, args.seed, args.output, matrix_path=args.matrix)
        print(json.dumps(asdict(compiled), indent=2, sort_keys=True))
        if args.command == "run":
            pcap = run_scenario(compiled, keep_range=args.keep_range)
            print(json.dumps({"pcap": str(pcap), "ground_truth": str(pcap.parent / "ground_truth.json")}, indent=2))
        return 0
    problems = validate_artifacts(args.root)
    if problems:
        print(json.dumps({"valid": False, "problems": problems}, indent=2))
        return 1
    print(json.dumps({"valid": True}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
