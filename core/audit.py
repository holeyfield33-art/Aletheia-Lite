"""SQLite audit log — the single source of truth (ported from ``core/audit.py``).

Same schema idea as aletheia-core's watcher: an append-only ledger keyed by id
and timestamp holding the verdict (``status``), the request fingerprint, the
full signed receipt JSON and the violation log.  Because every receipt carries
its ``prev_hash``, the audit log doubles as the hash chain: :meth:`last_hash`
lets a restarted process continue the same chain, and :meth:`verify_integrity`
walks the whole log to prove nothing was removed or reordered.

Multi-tenant hooks from the upstream module are dropped — one local ledger.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from .receipts import GENESIS_HASH, Receipt, verify_receipt

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp     REAL NOT NULL,
    status        TEXT NOT NULL,
    request_path  TEXT NOT NULL,
    receipt_hash  TEXT NOT NULL,
    prev_hash     TEXT NOT NULL,
    receipt_json  TEXT NOT NULL,
    violation_log TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit(timestamp DESC);
"""


class AuditLog:
    def __init__(self, db_path: str | Path = ":memory:") -> None:
        self.db_path = str(db_path)
        if self.db_path != ":memory:":
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def append(
        self,
        receipt: Receipt,
        violations: list[dict[str, Any]] | None = None,
        request_path: str | None = None,
    ) -> int:
        """Append a receipt to the ledger.  Returns the row id."""

        with self._lock:
            cur = self._conn.execute(
                """INSERT INTO audit
                   (timestamp, status, request_path, receipt_hash, prev_hash,
                    receipt_json, violation_log)
                   VALUES (?,?,?,?,?,?,?)""",
                (
                    receipt.timestamp or time.time(),
                    receipt.verdict,
                    request_path or receipt.fingerprint,
                    receipt.receipt_hash,
                    receipt.prev_hash,
                    json.dumps(receipt.to_dict(), ensure_ascii=False),
                    json.dumps(violations or receipt.violations, ensure_ascii=False),
                ),
            )
            self._conn.commit()
            return int(cur.lastrowid)

    def last_hash(self) -> str:
        """Return the chain head so a restart can continue signing."""

        with self._lock:
            row = self._conn.execute(
                "SELECT receipt_hash FROM audit ORDER BY id DESC LIMIT 1"
            ).fetchone()
        return row["receipt_hash"] if row else GENESIS_HASH

    def all(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM audit ORDER BY id ASC").fetchall()
        out = []
        for r in rows:
            out.append(
                {
                    "id": r["id"],
                    "timestamp": r["timestamp"],
                    "status": r["status"],
                    "request_path": r["request_path"],
                    "receipt_hash": r["receipt_hash"],
                    "prev_hash": r["prev_hash"],
                    "receipt": json.loads(r["receipt_json"]),
                    "violations": json.loads(r["violation_log"]),
                }
            )
        return out

    def verify_integrity(self) -> tuple[bool, str]:
        """Walk the whole ledger, checking the chain links and each signature.

        Returns ``(ok, detail)``.
        """

        prev = GENESIS_HASH
        for entry in self.all():
            receipt = Receipt.from_dict(entry["receipt"])
            if receipt.prev_hash != prev:
                return False, f"chain break at row {entry['id']}: prev_hash mismatch"
            if not verify_receipt(receipt):
                return False, f"bad signature/hash at row {entry['id']}"
            prev = receipt.receipt_hash
        return True, "ok"

    def close(self) -> None:
        with self._lock:
            self._conn.close()
