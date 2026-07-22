"""SQLite decision store (ported from ``core/decision_store.py``, stripped).

The upstream module could persist to Upstash over ``httpx`` under a
``tenant_scope`` for multi-tenant deployments.  Per the locked-in decisions that
whole path is removed here: this is **plain SQLite only**, single-node.  It
records one row per decision the pipeline makes — *including* ``ALLOW`` — so the
dashboard can report total-through vs total-blocked, not just incidents.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .types import Verdict


@dataclass
class Decision:
    request_id: str
    receipt_id: str
    agent: str
    verdict: Verdict
    suspicion: float
    reason: str
    timestamp: float = field(default_factory=time.time)
    findings: list[dict[str, Any]] = field(default_factory=list)
    receipt: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "receipt_id": self.receipt_id,
            "agent": self.agent,
            "verdict": self.verdict.value if isinstance(self.verdict, Verdict) else self.verdict,
            "suspicion": round(self.suspicion, 4),
            "reason": self.reason,
            "timestamp": self.timestamp,
            "findings": self.findings,
            "receipt": self.receipt,
        }


_SCHEMA = """
CREATE TABLE IF NOT EXISTS decisions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp    REAL    NOT NULL,
    request_id   TEXT    NOT NULL,
    receipt_id   TEXT    NOT NULL,
    agent        TEXT    NOT NULL,
    verdict      TEXT    NOT NULL,
    suspicion    REAL    NOT NULL,
    reason       TEXT    NOT NULL,
    findings_json TEXT   NOT NULL,
    receipt_json  TEXT   NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_decisions_ts ON decisions(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_decisions_verdict ON decisions(verdict);
"""


class DecisionStore:
    def __init__(self, db_path: str | Path = ":memory:") -> None:
        self.db_path = str(db_path)
        if self.db_path != ":memory:":
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def record(self, decision: Decision) -> int:
        verdict = decision.verdict.value if isinstance(decision.verdict, Verdict) else decision.verdict
        with self._lock:
            cur = self._conn.execute(
                """INSERT INTO decisions
                   (timestamp, request_id, receipt_id, agent, verdict, suspicion, reason,
                    findings_json, receipt_json)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    decision.timestamp,
                    decision.request_id,
                    decision.receipt_id,
                    decision.agent,
                    verdict,
                    decision.suspicion,
                    decision.reason,
                    json.dumps(decision.findings, ensure_ascii=False),
                    json.dumps(decision.receipt, ensure_ascii=False),
                ),
            )
            self._conn.commit()
            return int(cur.lastrowid)

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "timestamp": row["timestamp"],
            "request_id": row["request_id"],
            "receipt_id": row["receipt_id"],
            "agent": row["agent"],
            "verdict": row["verdict"],
            "suspicion": row["suspicion"],
            "reason": row["reason"],
            "findings": json.loads(row["findings_json"]),
            "receipt": json.loads(row["receipt_json"]),
        }

    def recent(self, limit: int = 50, verdict: str | None = None) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 1000))
        with self._lock:
            if verdict:
                rows = self._conn.execute(
                    "SELECT * FROM decisions WHERE verdict = ? ORDER BY id DESC LIMIT ?",
                    (verdict, limit),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM decisions ORDER BY id DESC LIMIT ?", (limit,)
                ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get(self, request_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM decisions WHERE request_id = ? ORDER BY id DESC LIMIT 1",
                (request_id,),
            ).fetchone()
        return self._row_to_dict(row) if row else None

    def stats(self) -> dict[str, Any]:
        with self._lock:
            total = self._conn.execute("SELECT COUNT(*) AS c FROM decisions").fetchone()["c"]
            by_verdict = {
                r["verdict"]: r["c"]
                for r in self._conn.execute(
                    "SELECT verdict, COUNT(*) AS c FROM decisions GROUP BY verdict"
                ).fetchall()
            }
        blocked = by_verdict.get(Verdict.BLOCK.value, 0)
        return {
            "total": total,
            "by_verdict": by_verdict,
            "total_through": total - blocked,
            "total_blocked": blocked,
        }

    def close(self) -> None:
        with self._lock:
            self._conn.close()
