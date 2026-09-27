"""Local metadata-only case index for the single-analyst desktop console."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _connection(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS cases (
            run_id TEXT PRIMARY KEY,
            created_at_utc TEXT NOT NULL,
            source_kind TEXT NOT NULL,
            capture_sha256 TEXT,
            packet_count INTEGER,
            risk_minimum REAL,
            risk_maximum REAL,
            application_label TEXT,
            report_directory TEXT NOT NULL
        )
        """
    )
    return connection


def record_case(database_path: str | Path, assessment_path: str | Path, *, source_kind: str) -> dict[str, Any]:
    """Index an assessment; deliberately does not copy the PCAP or evidence body."""
    assessment = json.loads(Path(assessment_path).read_text(encoding="utf-8"))
    run_id = str(assessment["run"]["run_id"])
    capture = assessment.get("capture", {})
    risk = assessment.get("risk") or {}
    application = assessment.get("application") or {}
    report_directory = str(Path(assessment_path).resolve().parent)
    with _connection(Path(database_path)) as connection:
        connection.execute(
            """INSERT OR REPLACE INTO cases
               (run_id, created_at_utc, source_kind, capture_sha256, packet_count,
                risk_minimum, risk_maximum, application_label, report_directory)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                run_id,
                datetime.now(timezone.utc).isoformat(),
                source_kind,
                capture.get("sha256"),
                capture.get("packet_count"),
                risk.get("minimum"),
                risk.get("maximum"),
                application.get("label"),
                report_directory,
            ),
        )
    return {"run_id": run_id, "database": str(Path(database_path).resolve())}


def list_cases(database_path: str | Path, *, limit: int = 25) -> list[dict[str, Any]]:
    if limit < 1 or limit > 100:
        raise ValueError("limit must be between 1 and 100")
    path = Path(database_path)
    if not path.exists():
        return []
    with _connection(path) as connection:
        rows = connection.execute(
            """SELECT run_id, created_at_utc, source_kind, capture_sha256, packet_count,
                      risk_minimum, risk_maximum, application_label, report_directory
                 FROM cases ORDER BY created_at_utc DESC LIMIT ?""",
            (limit,),
        ).fetchall()
    columns = ("run_id", "created_at_utc", "source_kind", "capture_sha256", "packet_count", "risk_minimum", "risk_maximum", "application_label", "report_directory")
    return [dict(zip(columns, row, strict=True)) for row in rows]
