from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .analyzer import DocumentAnalyzer, HeuristicDocumentAnalyzer, OpenAIDocumentAnalyzer, load_package_document
from .models import AnalysisReport, ObservedEvent
from .policy import PolicyEngine
from .runner import BehaviorRunner
from .scoring import score_events
from .storage import ReportStore


LIMITATIONS = [
    "관측되지 않은 행위가 안전을 의미하지는 않습니다.",
    "결과는 지정된 실행 환경과 관측 시간 안에서 발생한 이벤트만 반영합니다.",
    "문서 기반 기대 행위는 패키지의 안전성을 증명하지 않습니다.",
]


class AnalysisService:
    def __init__(self, store: ReportStore, policy: PolicyEngine | None = None):
        self.store = store
        self.policy = policy or PolicyEngine()

    def analyze(
        self,
        package_dir: Path,
        runner: BehaviorRunner,
        provider: str = "heuristic",
        window: int = 30,
    ) -> AnalysisReport:
        readme, package_json = load_package_document(package_dir)
        analyzer = self._analyzer(provider)
        document = analyzer.analyze(readme, package_json)
        events = runner.run(package_dir, window)
        return self.analyze_values(readme, package_json, events, document=document, runner=runner.name, window=window)

    def analyze_values(
        self,
        readme: str,
        package_json: dict[str, Any],
        events: list[ObservedEvent],
        provider: str = "heuristic",
        document=None,
        runner: str = "inline",
        window: int = 30,
    ) -> AnalysisReport:
        document = document or self._analyzer(provider).analyze(readme, package_json)
        expected = self.policy.expectations(document)
        score = score_events(events, expected, self.policy)
        report = AnalysisReport(
            analysis_id=f"sd-{uuid.uuid4().hex[:12]}",
            package_name=str(package_json.get("name", "unknown-package")),
            package_version=str(package_json.get("version", "0.0.0")),
            created_at=datetime.now(timezone.utc).isoformat(),
            document=document,
            expected=expected,
            observed=events,
            mismatches=score.mismatches,
            base_score=score.base_score,
            chain_bonus=score.chain_bonus,
            final_score=score.final_score,
            threshold=score.threshold,
            decision=score.decision,
            observation_window=window,
            runner=runner,
            limitations=list(LIMITATIONS),
        )
        self.store.save(report)
        return report

    @staticmethod
    def _analyzer(provider: str) -> DocumentAnalyzer:
        if provider == "heuristic":
            return HeuristicDocumentAnalyzer()
        if provider == "openai":
            return OpenAIDocumentAnalyzer()
        raise ValueError(f"Unknown document analyzer provider: {provider}")


def load_inline_events(values: list[dict[str, Any]]) -> list[ObservedEvent]:
    if len(values) > 5000:
        raise ValueError("At most 5000 events are accepted")
    return [ObservedEvent.from_dict(value) for value in values]

