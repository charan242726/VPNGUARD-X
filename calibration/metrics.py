"""Dependency-free calibration metrics used by experiments."""

from __future__ import annotations

from math import log
from typing import Sequence


def _validate(y_true: Sequence[int], probabilities: Sequence[Sequence[float]]) -> None:
    if len(y_true) != len(probabilities) or not y_true:
        raise ValueError("non-empty labels and probabilities must have equal length")
    width = len(probabilities[0])
    if width < 2 or any(len(row) != width for row in probabilities):
        raise ValueError("probability rows must have a common width >= 2")
    for label, row in zip(y_true, probabilities, strict=True):
        if label < 0 or label >= width:
            raise ValueError("label outside probability width")
        if any(value < 0 or value > 1 for value in row) or abs(sum(row) - 1.0) > 1e-6:
            raise ValueError("each probability row must sum to one")


def negative_log_likelihood(y_true: Sequence[int], probabilities: Sequence[Sequence[float]]) -> float:
    _validate(y_true, probabilities)
    epsilon = 1e-15
    return -sum(log(max(epsilon, probabilities[index][label])) for index, label in enumerate(y_true)) / len(y_true)


def brier_multiclass(y_true: Sequence[int], probabilities: Sequence[Sequence[float]]) -> float:
    _validate(y_true, probabilities)
    total = 0.0
    for label, row in zip(y_true, probabilities, strict=True):
        total += sum((probability - (1.0 if index == label else 0.0)) ** 2 for index, probability in enumerate(row))
    return total / len(y_true)


def expected_calibration_error(
    y_true: Sequence[int],
    probabilities: Sequence[Sequence[float]],
    *,
    bins: int = 15,
) -> float:
    _validate(y_true, probabilities)
    if bins <= 0:
        raise ValueError("bins must be positive")
    buckets: list[list[tuple[float, bool]]] = [[] for _ in range(bins)]
    for label, row in zip(y_true, probabilities, strict=True):
        predicted = max(range(len(row)), key=lambda index: row[index])
        confidence = row[predicted]
        bucket = min(bins - 1, int(confidence * bins))
        buckets[bucket].append((confidence, predicted == label))
    count = len(y_true)
    ece = 0.0
    for bucket in buckets:
        if not bucket:
            continue
        mean_confidence = sum(item[0] for item in bucket) / len(bucket)
        accuracy = sum(item[1] for item in bucket) / len(bucket)
        ece += (len(bucket) / count) * abs(accuracy - mean_confidence)
    return ece
