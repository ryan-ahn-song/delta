from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal


Capability = Literal[
    "file_read",
    "file_write",
    "network_connect",
    "process_spawn",
    "env_read",
    "process_inspect",
    "persistence",
    "download_execute",
]

EventStatus = Literal["attempted", "success"]


@dataclass(slots=True)
class Declaration:
    capability: str
    target: str
    purpose: str
    evidence: str
    confidence: float = 1.0

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "Declaration":
        return cls(**value)


@dataclass(slots=True)
class DocumentAnalysis:
    categories: dict[str, float] = field(default_factory=dict)
    declarations: list[Declaration] = field(default_factory=list)
    injection_signals: list[str] = field(default_factory=list)
    provider: str = "heuristic"
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ExpectedBehavior:
    capability: str
    target: str
    purpose: str
    source: str
    evidence: str = ""
    approval: Literal["policy", "document", "manual"] = "policy"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ObservedEvent:
    capability: str
    target: str
    status: EventStatus = "success"
    timestamp: float = 0.0
    source: str = "trace"
    detail: str = ""

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ObservedEvent":
        return cls(**value)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Mismatch:
    event: ObservedEvent
    expected: bool
    matched_rule: str | None
    weight: float
    reason: str

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        return value


@dataclass(slots=True)
class AnalysisReport:
    analysis_id: str
    package_name: str
    package_version: str
    created_at: str
    document: DocumentAnalysis
    expected: list[ExpectedBehavior]
    observed: list[ObservedEvent]
    mismatches: list[Mismatch]
    base_score: float
    chain_bonus: float
    final_score: float
    threshold: float
    decision: str
    observation_window: int
    runner: str
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

