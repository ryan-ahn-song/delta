from __future__ import annotations

from dataclasses import dataclass

from .models import ExpectedBehavior, Mismatch, ObservedEvent
from .policy import PolicyEngine


@dataclass(slots=True)
class ScoreResult:
    mismatches: list[Mismatch]
    base_score: float
    chain_bonus: float
    final_score: float
    threshold: float
    decision: str


def score_events(
    events: list[ObservedEvent], expectations: list[ExpectedBehavior], policy: PolicyEngine
) -> ScoreResult:
    mismatches: list[Mismatch] = []
    unmatched: list[ObservedEvent] = []
    base_score = 0.0
    for event in events:
        matched = policy.match_expected(event, expectations)
        if matched:
            mismatches.append(Mismatch(event, True, f"{matched.capability}:{matched.target}", 0.0, matched.purpose))
            continue
        weight, reason = policy.weight_for(event)
        factor = 0.5 if event.status == "attempted" else 1.0
        applied = weight * factor
        base_score += applied
        unmatched.append(event)
        mismatches.append(Mismatch(event, False, None, applied, reason))

    tags = _event_tags(unmatched)
    chain_bonus = 0.0
    for chain in policy.config.get("chain_bonuses", []):
        if set(chain["requires"]).issubset(tags):
            chain_bonus += float(chain["bonus"])
    final_score = round(base_score + chain_bonus, 2)
    threshold = policy.threshold
    critical_success = any(
        not item.expected and item.weight >= 5 and item.event.status == "success"
        for item in mismatches
    )
    if final_score >= threshold or critical_success:
        decision = "REVIEW REQUIRED"
    elif final_score > 0:
        decision = "LOW RISK MISMATCH"
    else:
        decision = "NO MISMATCH OBSERVED"
    return ScoreResult(mismatches, round(base_score, 2), round(chain_bonus, 2), final_score, threshold, decision)


def _event_tags(events: list[ObservedEvent]) -> set[str]:
    tags: set[str] = set()
    for event in events:
        if event.capability == "network_connect":
            tags.add("network_connect")
        if event.capability == "process_spawn":
            tags.add("process_spawn")
        if event.capability == "download_execute":
            tags.add("download")
        if event.capability == "env_read" and any(x in event.target.upper() for x in ("TOKEN", "SECRET", "PASSWORD", "KEY")):
            tags.add("secret_access")
        if event.capability == "file_read" and any(x in event.target for x in ("/.ssh/", "/.aws/", "/.kube/", "/.npmrc")):
            tags.add("secret_access")
    return tags
