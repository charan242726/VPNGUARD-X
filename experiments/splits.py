"""Leakage-resistant generalization split manifests."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Iterable


@dataclass(frozen=True)
class ExperimentRecord:
    artifact_id: str
    configuration_id: str
    cipher: str
    mode: str
    ip_version: int
    encapsulation: str
    stack: str
    application_class: str
    replicate_group: str


@dataclass(frozen=True)
class SplitManifest:
    split_id: str
    train_ids: tuple[str, ...]
    calibration_ids: tuple[str, ...]
    test_ids: tuple[str, ...]
    held_out_value: str
    seed: int
    manifest_hash: str

    def to_dict(self) -> dict:
        return asdict(self)


def _hash_score(seed: int, group: str) -> int:
    return int(hashlib.sha256(f"{seed}:{group}".encode()).hexdigest()[:16], 16)


def _partition_train_calibration(records: list[ExperimentRecord], seed: int) -> tuple[list[str], list[str]]:
    groups: dict[str, list[str]] = {}
    for record in records:
        groups.setdefault(record.replicate_group, []).append(record.artifact_id)
    ordered_groups = sorted(groups, key=lambda group: (_hash_score(seed, group), group))
    calibration_count = max(1, round(len(ordered_groups) * 0.2)) if len(ordered_groups) > 1 else 0
    calibration_groups = set(ordered_groups[:calibration_count])
    training = sorted(artifact_id for group, ids in groups.items() if group not in calibration_groups for artifact_id in ids)
    calibration = sorted(artifact_id for group, ids in groups.items() if group in calibration_groups for artifact_id in ids)
    return training, calibration


def _manifest(
    split_id: str,
    training_pool: list[ExperimentRecord],
    test: list[ExperimentRecord],
    held_out: str,
    seed: int,
) -> SplitManifest:
    train_ids, calibration_ids = _partition_train_calibration(training_pool, seed)
    test_ids = sorted(record.artifact_id for record in test)
    if set(train_ids) & set(calibration_ids) or set(train_ids) & set(test_ids) or set(calibration_ids) & set(test_ids):
        raise AssertionError("split partitions overlap")
    payload = {
        "split_id": split_id,
        "train_ids": train_ids,
        "calibration_ids": calibration_ids,
        "test_ids": test_ids,
        "held_out_value": held_out,
        "seed": seed,
    }
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
    return SplitManifest(split_id, tuple(train_ids), tuple(calibration_ids), tuple(test_ids), held_out, seed, digest)


def build_generalization_splits(records: Iterable[ExperimentRecord], *, seed: int = 26160) -> list[SplitManifest]:
    values = list(records)
    if len({record.artifact_id for record in values}) != len(values):
        raise ValueError("artifact IDs must be unique")
    manifests: list[SplitManifest] = []

    def leave_one(field: str, prefix: str) -> None:
        unique = sorted({getattr(record, field) for record in values}, key=str)
        for held_out in unique:
            test = [record for record in values if getattr(record, field) == held_out]
            train = [record for record in values if getattr(record, field) != held_out]
            if test and train:
                manifests.append(_manifest(f"{prefix}::{held_out}", train, test, str(held_out), seed))

    leave_one("configuration_id", "LOCO")
    leave_one("cipher", "LOCIPHER")
    leave_one("mode", "LOMODE")

    directed = [
        ("IPV4_TO_IPV6", lambda r: r.ip_version == 4, lambda r: r.ip_version == 6, "4->6"),
        ("NATIVE_TO_NATT", lambda r: r.encapsulation == "NATIVE_ESP", lambda r: r.encapsulation == "UDP_ENCAPSULATED_ESP", "native->NAT-T"),
        ("NATT_TO_NATIVE", lambda r: r.encapsulation == "UDP_ENCAPSULATED_ESP", lambda r: r.encapsulation == "NATIVE_ESP", "NAT-T->native"),
    ]
    for split_id, train_predicate, test_predicate, label in directed:
        train = [record for record in values if train_predicate(record)]
        test = [record for record in values if test_predicate(record)]
        if train and test:
            manifests.append(_manifest(split_id, train, test, label, seed))

    stacks = sorted({record.stack for record in values})
    if len(stacks) > 1:
        source = stacks[0]
        for target in stacks[1:]:
            train = [record for record in values if record.stack == source]
            test = [record for record in values if record.stack == target]
            manifests.append(_manifest(f"CROSS_STACK::{source}->{target}", train, test, target, seed))

    known = [record for record in values if record.application_class != "UNKNOWN"]
    unknown = [record for record in values if record.application_class == "UNKNOWN"]
    if known and unknown:
        # Reserve known controls independently for every class, by replicate
        # group.  OOD AUROC/FPR95 need both known and UNKNOWN test examples.
        groups_by_class: dict[str, set[str]] = {}
        for record in known:
            groups_by_class.setdefault(record.application_class, set()).add(record.replicate_group)
        reserved_groups: set[str] = set()
        for application_class, groups in sorted(groups_by_class.items()):
            if len(groups) >= 3:
                ordered = sorted(groups, key=lambda group: (_hash_score(seed, group), group))
                reserved_groups.update(ordered[:max(1, round(len(groups) * 0.2))])
        training_pool = [record for record in known if record.replicate_group not in reserved_groups]
        controls = [record for record in known if record.replicate_group in reserved_groups]
        if training_pool and controls:
            manifests.append(_manifest("UNSEEN_APPLICATION_OOD", training_pool, controls + unknown, "UNKNOWN", seed))
    return manifests
