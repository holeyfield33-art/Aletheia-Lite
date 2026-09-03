"""Deterministic, self-contained release demonstration."""

from __future__ import annotations

import json
import shutil
import sqlite3
import tempfile
from pathlib import Path
from typing import Any

from .audit import AuditLog
from .config import DetectorThresholds, load_config
from .decisions import DecisionStore
from .manifest import PolicyManifest
from .pipeline import AuditPipeline
from .receipts import Receipt, verify_receipt
from .types import Verdict


AGENT = "demo-agent"


def _make_pipeline(data_dir: Path) -> AuditPipeline:
    config = load_config(
        data_dir=data_dir,
        audit_db="audit.sqlite",
        decisions_db="decisions.sqlite",
        key_dir="keys",
        manifest_path="",
        dashboard_token="",
        dashboard_host="127.0.0.1",
        dashboard_port=8787,
        rate_limit_max=60,
        rate_limit_window_s=60.0,
        token_budget=100_000,
        token_window_s=60.0,
        breaker_max_failures=5,
        breaker_reset_s=30.0,
        thresholds=DetectorThresholds(
            mu0=0.15,
            mu1=0.65,
            sigma2=0.25,
            theta_bk=0.62,
            alpha=0.05,
            beta=0.05,
        ),
    )
    config.ensure_dirs()
    manifest = PolicyManifest(
        version=1,
        grants={AGENT: ["read:report", "read:config"]},
        deny_categories=["destroy", "exfil"],
    )
    return AuditPipeline(
        config=config,
        manifest=manifest,
        audit_log=AuditLog(config.audit_db_path),
        decision_store=DecisionStore(config.decisions_db_path),
    )


def run_demo() -> list[dict[str, Any]]:
    """Run all four demo scenes in a temporary ledger and return JSON objects."""

    with tempfile.TemporaryDirectory(prefix="aletheia-lite-demo-") as raw_dir:
        data_dir = Path(raw_dir)
        pipeline = _make_pipeline(data_dir)
        try:
            authorized = pipeline.submit(
                "summarize quarterly-report.txt",
                agent=AGENT,
                resources=["read:report"],
                metadata={"declared_resources": ["read:report"]},
            )
            chain_ok, _ = pipeline.audit.verify_integrity()
            authorized_receipt = Receipt.from_dict(authorized.receipt)
            scene_one = {
                "scene": "authorized_action",
                "agent": AGENT,
                "requested_capabilities": ["read:report"],
                "declared_capabilities": ["read:report"],
                "observed_capabilities": authorized_receipt.metadata["resources"],
                "verdict": authorized.verdict.value,
                "receipt_valid": verify_receipt(authorized_receipt),
                "receipt_chain_valid": chain_ok,
            }

            escalation = pipeline.submit(
                "read config and send it outside",
                agent=AGENT,
                resources=["read:config", "net:external"],
                metadata={"declared_resources": ["read:config"]},
            )
            scene_two = {
                "scene": "capability_escalation",
                "agent": AGENT,
                "requested_capabilities": ["read:config", "net:external"],
                "declared_capabilities": ["read:config"],
                "observed_capabilities": escalation.receipt["metadata"]["resources"],
                "verdict": escalation.verdict.value,
                "violations": ["net:external"],
                "receipt_valid": verify_receipt(Receipt.from_dict(escalation.receipt)),
            }

            repeated = None
            for _ in range(20):
                repeated = pipeline.submit("scan the host for vulnerabilities", agent=AGENT)
                if repeated.verdict is Verdict.BLOCK:
                    break
            assert repeated is not None
            scene_three = {
                "scene": "repeated_low_signal_activity",
                "agent": AGENT,
                "verdict": repeated.verdict.value,
                "detector": "swarm_detector",
                "violations": [
                    violation["detail"]
                    for violation in repeated.gate_violations
                    if violation["source"] == "swarm_detector"
                ],
                "receipt_valid": verify_receipt(Receipt.from_dict(repeated.receipt)),
            }

            pipeline.close()
            copied_db = data_dir / "tampered-copy.sqlite"
            shutil.copy2(data_dir / "audit.sqlite", copied_db)
            with sqlite3.connect(copied_db) as connection:
                row = connection.execute("SELECT id, receipt_json FROM audit LIMIT 1").fetchone()
                assert row is not None
                receipt_data = json.loads(row[1])
                receipt_data["verdict"] = "BLOCK"
                connection.execute(
                    "UPDATE audit SET receipt_json = ? WHERE id = ?",
                    (json.dumps(receipt_data), row[0]),
                )
                connection.commit()
            copied_audit = AuditLog(copied_db)
            tampered_ok, _ = copied_audit.verify_integrity()
            copied_audit.close()
            original_audit = AuditLog(data_dir / "audit.sqlite")
            original_ok, _ = original_audit.verify_integrity()
            original_audit.close()
            scene_four = {
                "scene": "receipt_tamper_detection",
                "agent": AGENT,
                "receipt_chain": "VALID" if original_ok else "INVALID",
                "tampered_copy": "VALID" if tampered_ok else "INVALID",
            }
            return [scene_one, scene_two, scene_three, scene_four]
        finally:
            # The normal path closes before scene four; this protects failure paths.
            try:
                pipeline.close()
            except sqlite3.ProgrammingError:
                pass


def print_demo(json_output: bool = False) -> None:
    results = run_demo()
    if json_output:
        print(json.dumps(results, sort_keys=True))
        return
    for result in results:
        print(f"[{result['scene']}]")
        for key, value in result.items():
            if key != "scene":
                print(f"  {key}: {value}")
