from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import Any

from .models import Declaration, DocumentAnalysis, ExpectedBehavior, ObservedEvent


def _norm(value: str) -> str:
    return value.replace("\\", "/").strip()


def _target_matches(value: str, pattern: str) -> bool:
    value, pattern = _norm(value), _norm(pattern)
    if fnmatch.fnmatchcase(value, pattern):
        return True
    # Network sensors may include a port while the document declares only a host.
    if ":" in value and ":" not in pattern:
        return fnmatch.fnmatchcase(value.rsplit(":", 1)[0], pattern)
    return False


@dataclass(slots=True)
class SensitiveMatch:
    weight: float
    label: str
    promote: str | None = None


class PolicyEngine:
    def __init__(self, config: dict[str, Any] | None = None, path: Path | None = None):
        if config is None:
            policy_path = path or files("stack_delta").joinpath("config/policy.json")
            config = json.loads(policy_path.read_text(encoding="utf-8"))
        self.config = config
        self.threshold = float(config.get("threshold", 6.0))

    def is_never_auto_approved(self, capability: str, target: str) -> bool:
        return any(
            rule["capability"] == capability and _target_matches(target, rule["pattern"])
            for rule in self.config["never_auto_approve"]
        )

    def expectations(self, analysis: DocumentAnalysis) -> list[ExpectedBehavior]:
        result: list[ExpectedBehavior] = []
        seen: set[tuple[str, str]] = set()
        for category, confidence in analysis.categories.items():
            if confidence < 0.5:
                continue
            for item in self.config["category_expectations"].get(category, []):
                key = (item["capability"], item["target"])
                if key not in seen:
                    result.append(ExpectedBehavior(
                        capability=item["capability"],
                        target=item["target"],
                        purpose=item["purpose"],
                        source=f"category:{category}",
                        approval="policy",
                    ))
                    seen.add(key)

        allowed = set(self.config["auto_approvable_capabilities"])
        for declaration in analysis.declarations:
            key = (declaration.capability, declaration.target)
            if (
                declaration.confidence < 0.65
                or declaration.capability not in allowed
                or self.is_never_auto_approved(*key)
                or key in seen
            ):
                continue
            result.append(ExpectedBehavior(
                capability=declaration.capability,
                target=declaration.target,
                purpose=declaration.purpose,
                source="document",
                evidence=declaration.evidence,
                approval="document",
            ))
            seen.add(key)
        return result

    def match_expected(
        self, event: ObservedEvent, expectations: list[ExpectedBehavior]
    ) -> ExpectedBehavior | None:
        for expected in expectations:
            if expected.capability == event.capability and _target_matches(event.target, expected.target):
                return expected
        return None

    def sensitive_match(self, event: ObservedEvent) -> SensitiveMatch | None:
        for rule in self.config["sensitive_targets"]:
            if rule["capability"] == event.capability and _target_matches(event.target, rule["pattern"]):
                return SensitiveMatch(float(rule["weight"]), rule["label"], rule.get("promote"))
        return None

    def weight_for(self, event: ObservedEvent) -> tuple[float, str]:
        sensitive = self.sensitive_match(event)
        if sensitive:
            return sensitive.weight, sensitive.label
        return float(self.config["weights"].get(event.capability, 2)), "undeclared behavior"

