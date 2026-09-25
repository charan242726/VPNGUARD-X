"""Deterministic uncertainty-sampling experiment harness."""

from __future__ import annotations

from dataclasses import dataclass
from math import log
from typing import Any, Callable, Iterable, Mapping


@dataclass(frozen=True)
class ActiveLearningPoint:
    round_index: int
    labels_used: int
    evaluation_metric: float
    newly_selected_ids: tuple[str, ...]


def _entropy(distribution: Mapping[str, float]) -> float:
    return -sum(float(value) * log(float(value)) for value in distribution.values() if value > 0)


def run_uncertainty_sampling(
    pool_ids: Iterable[str],
    initial_labeled_ids: Iterable[str],
    *,
    rounds: int,
    batch_size: int,
    train_and_score_pool: Callable[[set[str], list[str]], Mapping[str, Mapping[str, float]]],
    evaluate: Callable[[set[str]], float],
) -> list[ActiveLearningPoint]:
    """Run an experiment through callbacks; returned numbers come only from callbacks."""
    pool = sorted(set(pool_ids))
    labeled = set(initial_labeled_ids)
    if not labeled <= set(pool):
        raise ValueError("initial labels must belong to the pool")
    if rounds < 0 or batch_size <= 0:
        raise ValueError("invalid active-learning schedule")
    curve = [ActiveLearningPoint(0, len(labeled), float(evaluate(labeled)), ())]
    for round_index in range(1, rounds + 1):
        unlabeled = [artifact_id for artifact_id in pool if artifact_id not in labeled]
        if not unlabeled:
            break
        distributions = train_and_score_pool(labeled, unlabeled)
        if set(distributions) != set(unlabeled):
            raise ValueError("scorer must return one distribution for every unlabeled artifact")
        ranked = sorted(unlabeled, key=lambda artifact_id: (-_entropy(distributions[artifact_id]), artifact_id))
        selected = tuple(ranked[:batch_size])
        labeled.update(selected)
        curve.append(ActiveLearningPoint(round_index, len(labeled), float(evaluate(labeled)), selected))
    return curve
