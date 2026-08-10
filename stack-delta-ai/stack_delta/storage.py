from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from .models import AnalysisReport


class ReportStore:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        return connection

    def _init(self) -> None:
        with self._connect() as connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS reports (
                    analysis_id TEXT PRIMARY KEY,
                    package_name TEXT NOT NULL,
                    package_version TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    final_score REAL NOT NULL,
                    payload TEXT NOT NULL
                )
            """)
            connection.execute("CREATE INDEX IF NOT EXISTS reports_created_at ON reports(created_at DESC)")

    def save(self, report: AnalysisReport) -> None:
        payload = json.dumps(report.to_dict(), ensure_ascii=False, separators=(",", ":"))
        with self._connect() as connection:
            connection.execute(
                """INSERT OR REPLACE INTO reports
                   (analysis_id, package_name, package_version, created_at, decision, final_score, payload)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (report.analysis_id, report.package_name, report.package_version, report.created_at,
                 report.decision, report.final_score, payload),
            )

    def get(self, analysis_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute("SELECT payload FROM reports WHERE analysis_id = ?", (analysis_id,)).fetchone()
        return json.loads(row["payload"]) if row else None

    def list(self, limit: int = 50) -> list[dict[str, Any]]:
        safe_limit = max(1, min(limit, 200))
        with self._connect() as connection:
            rows = connection.execute(
                """SELECT analysis_id, package_name, package_version, created_at, decision, final_score
                   FROM reports ORDER BY created_at DESC LIMIT ?""", (safe_limit,)
            ).fetchall()
        return [dict(row) for row in rows]

    def count(self) -> int:
        with self._connect() as connection:
            return int(connection.execute("SELECT COUNT(*) FROM reports").fetchone()[0])

