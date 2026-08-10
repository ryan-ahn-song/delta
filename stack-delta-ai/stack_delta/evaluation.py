from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Iterable


@dataclass(slots=True)
class BinaryMetrics:
    true_positive: int
    false_positive: int
    true_negative: int
    false_negative: int
    precision: float
    recall: float
    f1: float
    false_positive_rate: float

    def to_dict(self):
        return asdict(self)


def binary_metrics(labels: Iterable[bool], predictions: Iterable[bool]) -> BinaryMetrics:
    pairs = list(zip(labels, predictions, strict=True))
    tp = sum(label and prediction for label, prediction in pairs)
    fp = sum(not label and prediction for label, prediction in pairs)
    tn = sum(not label and not prediction for label, prediction in pairs)
    fn = sum(label and not prediction for label, prediction in pairs)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return BinaryMetrics(tp, fp, tn, fn, precision, recall, f1, fpr)


def unsafe_approval_rate(false_approved: int, actually_unexpected: int) -> float:
    return false_approved / actually_unexpected if actually_unexpected else 0.0

