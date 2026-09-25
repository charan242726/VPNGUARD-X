"""Evaluation metrics without fabricated defaults."""

from __future__ import annotations

from statistics import mean
from typing import Any, Iterable, Sequence

from calibration.metrics import brier_multiclass, expected_calibration_error, negative_log_likelihood


def _macro_f1(
    true: Sequence[str],
    predicted: Sequence[str],
    *,
    labels: Sequence[str] | None = None,
) -> float:
    classes = list(labels) if labels is not None else sorted(set(true) | set(predicted))
    values = []
    for label in classes:
        tp = sum(a == label and b == label for a, b in zip(true, predicted, strict=True))
        fp = sum(a != label and b == label for a, b in zip(true, predicted, strict=True))
        fn = sum(a == label and b != label for a, b in zip(true, predicted, strict=True))
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        values.append(2 * precision * recall / (precision + recall) if precision + recall else 0.0)
    return mean(values) if values else 0.0


def _stable_argmax(scores: dict[str, Any]) -> str:
    """Return an order-independent argmax for ordinary point classifiers."""
    if not scores:
        raise ValueError("scores are required")
    return max(sorted(scores), key=lambda label: float(scores[label]))


def _configuration_decision(row: dict[str, Any]) -> str | None:
    """Return only an explicitly supported configuration point decision.

    Configuration inference is set-valued.  A point decision is therefore
    emitted only when the prediction set is a singleton.  This also provides a
    backward-compatible, serialization-invariant interpretation of prediction
    records created before ``predicted_candidate_id`` was stored explicitly.
    Equal posterior probabilities must never be resolved by dictionary order.
    """
    prediction_set = row.get("prediction_set")
    if isinstance(prediction_set, (list, tuple)) and len(prediction_set) == 1:
        singleton = str(prediction_set[0])
        explicit = row.get("predicted_candidate_id")
        # An explicit value is redundant provenance, not permission to bypass
        # set-valued semantics.  Inconsistent records abstain conservatively.
        if explicit not in (None, "", singleton):
            return None
        return singleton
    return None


def _balanced_accuracy(true: Sequence[str], predicted: Sequence[str]) -> float:
    recalls = []
    for label in sorted(set(true)):
        indices = [index for index, value in enumerate(true) if value == label]
        recalls.append(sum(predicted[index] == label for index in indices) / len(indices))
    return mean(recalls) if recalls else 0.0


def _binary_auroc(labels: Sequence[int], scores: Sequence[float]) -> float | None:
    positives = [score for label, score in zip(labels, scores, strict=True) if label == 1]
    negatives = [score for label, score in zip(labels, scores, strict=True) if label == 0]
    if not positives or not negatives:
        return None
    wins = 0.0
    for positive in positives:
        for negative in negatives:
            wins += 1.0 if positive > negative else 0.5 if positive == negative else 0.0
    return wins / (len(positives) * len(negatives))


def _fpr95(labels: Sequence[int], scores: Sequence[float]) -> float | None:
    positive_scores = sorted(score for label, score in zip(labels, scores, strict=True) if label == 1)
    negative_scores = [score for label, score in zip(labels, scores, strict=True) if label == 0]
    if not positive_scores or not negative_scores:
        return None
    threshold_index = max(0, int(0.05 * (len(positive_scores) - 1)))
    threshold = positive_scores[threshold_index]
    return sum(score >= threshold for score in negative_scores) / len(negative_scores)


def _latency_summary(values: Sequence[float]) -> dict[str, float] | None:
    if not values:
        return None
    ordered = sorted(values)
    return {
        "mean_ms": mean(ordered),
        "p50_ms": ordered[int(0.50 * (len(ordered) - 1))],
        "p95_ms": ordered[int(0.95 * (len(ordered) - 1))],
        "p99_ms": ordered[int(0.99 * (len(ordered) - 1))],
    }


def evaluate_prediction_records(records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    rows = list(records)
    if not rows:
        raise ValueError("evaluation records are required")
    output: dict[str, Any] = {"sample_count": len(rows)}

    config_rows = [row for row in rows if row.get("true_candidate_id") and row.get("candidate_posterior")]
    if config_rows:
        true = [row["true_candidate_id"] for row in config_rows]
        decisions = [_configuration_decision(row) for row in config_rows]
        predicted = [decision if decision is not None else "<ABSTAIN>" for decision in decisions]
        prediction_sets = [row.get("prediction_set", []) for row in config_rows]
        decision_count = sum(decision is not None for decision in decisions)
        correct_count = sum(a == b for a, b in zip(true, predicted, strict=True))
        output["configuration"] = {
            "decision_rule": "SINGLETON_PREDICTION_SET_ELSE_ABSTAIN",
            # Abstentions count as incorrect in the unconditional exact-match
            # metric; the accompanying decision rate makes the trade-off
            # explicit.  Conditional accuracy is never substituted for it.
            "exact_match": correct_count / len(true),
            "macro_f1": _macro_f1(true, predicted, labels=sorted(set(true))),
            "point_prediction_rate": decision_count / len(true),
            "point_abstention_rate": 1.0 - decision_count / len(true),
            "point_exact_match_conditional": correct_count / decision_count if decision_count else None,
            "prediction_set_coverage": sum(label in values for label, values in zip(true, prediction_sets, strict=True)) / len(true),
            "prediction_set_mean_size": mean(len(values) for values in prediction_sets),
            "constraint_violation_rate": sum(bool(row.get("predicted_constraint_violations")) for row in config_rows) / len(config_rows),
        }
    else:
        output["configuration"] = "TBD — requires experiment records"

    traffic_rows = [
        row
        for row in rows
        if row.get("true_application")
        and row.get("application_probabilities")
        and not bool(row.get("is_ood"))
    ]
    if traffic_rows:
        classes = sorted({label for row in traffic_rows for label in row["application_probabilities"]})
        index = {label: position for position, label in enumerate(classes)}
        true_labels = [row["true_application"] for row in traffic_rows]
        predicted_labels = [_stable_argmax(row["application_probabilities"]) for row in traffic_rows]
        probabilities = [[float(row["application_probabilities"].get(label, 0.0)) for label in classes] for row in traffic_rows]
        true_indices = [index[label] for label in true_labels]
        class_aurocs = []
        for label in classes:
            labels = [int(value == label) for value in true_labels]
            scores = [float(row["application_probabilities"].get(label, 0.0)) for row in traffic_rows]
            auroc = _binary_auroc(labels, scores)
            if auroc is not None:
                class_aurocs.append(auroc)
        output["traffic"] = {
            "balanced_accuracy": _balanced_accuracy(true_labels, predicted_labels),
            "macro_f1": _macro_f1(true_labels, predicted_labels),
            "nll": negative_log_likelihood(true_indices, probabilities),
            "brier": brier_multiclass(true_indices, probabilities),
            "ece_15_bin": expected_calibration_error(true_indices, probabilities, bins=15),
            "macro_one_vs_rest_auroc": mean(class_aurocs) if class_aurocs else None,
        }
    else:
        output["traffic"] = "TBD — requires experiment records"

    open_world_rows = [
        row
        for row in rows
        if row.get("true_application") and row.get("reported_application")
    ]
    if open_world_rows:
        open_true = [row["true_application"] for row in open_world_rows]
        open_predicted = [row["reported_application"] for row in open_world_rows]
        output["open_world_traffic"] = {
            "balanced_accuracy_including_unknown": _balanced_accuracy(open_true, open_predicted),
            "macro_f1_including_unknown": _macro_f1(open_true, open_predicted),
            "unknown_recall": (
                sum(predicted == "UNKNOWN" for truth, predicted in zip(open_true, open_predicted, strict=True) if truth == "UNKNOWN")
                / sum(truth == "UNKNOWN" for truth in open_true)
                if any(truth == "UNKNOWN" for truth in open_true)
                else None
            ),
        }
    else:
        output["open_world_traffic"] = "TBD — requires open-world decisions"

    ood_rows = [row for row in rows if row.get("is_ood") is not None and row.get("ood_score") is not None]
    if ood_rows:
        labels = [int(bool(row["is_ood"])) for row in ood_rows]
        scores = [float(row["ood_score"]) for row in ood_rows]
        output["ood"] = {"auroc": _binary_auroc(labels, scores), "fpr95": _fpr95(labels, scores)}
    else:
        output["ood"] = "TBD — requires OOD experiment records"

    latency = [float(row["latency_ms"]) for row in rows if row.get("latency_ms") is not None]
    output["latency"] = _latency_summary(latency) or "TBD — requires latency measurements"
    loss_groups: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        if row.get("packet_loss_fraction") is not None:
            loss_groups.setdefault(str(row["packet_loss_fraction"]), []).append(row)
    robustness: dict[str, Any] = {}
    for loss, group in sorted(loss_groups.items()):
        summary: dict[str, Any] = {"sample_count": len(group)}
        group_config = [row for row in group if row.get("true_candidate_id") and row.get("candidate_posterior")]
        if group_config:
            decisions = [_configuration_decision(row) for row in group_config]
            decision_count = sum(decision is not None for decision in decisions)
            correct_count = sum(
                row["true_candidate_id"] == decision
                for row, decision in zip(group_config, decisions, strict=True)
            )
            summary["configuration_exact_match"] = correct_count / len(group_config)
            summary["configuration_point_prediction_rate"] = decision_count / len(group_config)
            summary["configuration_point_abstention_rate"] = 1.0 - decision_count / len(group_config)
            summary["configuration_point_exact_match_conditional"] = (
                correct_count / decision_count if decision_count else None
            )
            summary["prediction_set_coverage"] = sum(
                row["true_candidate_id"] in row.get("prediction_set", []) for row in group_config
            ) / len(group_config)
        group_traffic = [row for row in group if row.get("true_application") and row.get("application_probabilities")]
        if group_traffic:
            true_group = [row["true_application"] for row in group_traffic]
            predicted_group = [_stable_argmax(row["application_probabilities"]) for row in group_traffic]
            summary["traffic_balanced_accuracy"] = _balanced_accuracy(true_group, predicted_group)
        robustness[loss] = summary
    output["incomplete_capture"] = (
        robustness
        if loss_groups
        else "TBD — requires 0.1/0.3/0.5 packet-loss experiments"
    )
    protocol_pairs: list[tuple[str, str]] = []
    missing_protocol_values = 0
    for row in rows:
        truth = row.get("protocol_truth")
        predicted = row.get("protocol_predicted")
        if not isinstance(truth, dict) or not isinstance(predicted, dict):
            continue
        for property_name, expected in truth.items():
            if property_name not in predicted:
                missing_protocol_values += 1
                protocol_pairs.append((repr(expected), "<MISSING>"))
            else:
                protocol_pairs.append((repr(expected), repr(predicted[property_name])))
    output["protocol_extraction"] = (
        {
            "field_count": len(protocol_pairs),
            "field_accuracy": sum(expected == predicted for expected, predicted in protocol_pairs) / len(protocol_pairs),
            "macro_f1": _macro_f1([value[0] for value in protocol_pairs], [value[1] for value in protocol_pairs]),
            "missing_field_count": missing_protocol_values,
        }
        if protocol_pairs
        else "TBD — requires field-level parser ground-truth records"
    )
    active_rows = sorted(
        [row for row in rows if row.get("active_learning_round") is not None and row.get("labels_used") is not None and row.get("validation_metric") is not None],
        key=lambda row: (int(row["labels_used"]), int(row["active_learning_round"])),
    )
    if active_rows:
        area = 0.0
        for left, right in zip(active_rows, active_rows[1:]):
            area += (float(right["labels_used"]) - float(left["labels_used"])) * (
                float(left["validation_metric"]) + float(right["validation_metric"])
            ) / 2
        span = float(active_rows[-1]["labels_used"]) - float(active_rows[0]["labels_used"])
        output["active_learning_label_efficiency"] = {
            "curve": [
                {
                    "round": int(row["active_learning_round"]),
                    "labels_used": int(row["labels_used"]),
                    "validation_metric": float(row["validation_metric"]),
                }
                for row in active_rows
            ],
            "normalized_area_under_learning_curve": area / span if span > 0 else None,
        }
    else:
        output["active_learning_label_efficiency"] = "TBD — requires learning-curve experiment"
    return output
