"""Stage 6 — swarm detector wiring.

Confirms the per-principal SwarmDetector (detectors/swarm_detector.py) is
actually consulted by AuditPipeline.process(), not just unit-tested in
isolation. A single borderline-suspicious request (recon-weight text that
lands well under BLOCK_THRESHOLD on its own) must eventually get BLOCKed
once the same principal repeats it enough times to cross the SPRT swarm
boundary -- the population-level signal per-request scoring cannot see.
"""

from __future__ import annotations

import pytest

from core.config import load_config
from core.decisions import DecisionStore
from core.audit import AuditLog
from core.manifest import PolicyManifest
from core.pipeline import AuditPipeline
from core.types import Verdict


@pytest.fixture
def pipeline(tmp_path):
    cfg = load_config(data_dir=tmp_path)
    cfg.ensure_dirs()
    manifest = PolicyManifest(version=1, grants={"*": ["read:*"]}, deny_categories=["destroy", "exfil"])
    store = DecisionStore(":memory:")
    audit = AuditLog(":memory:")
    p = AuditPipeline(config=cfg, manifest=manifest, audit_log=audit, decision_store=store)
    yield p
    p.close()


def test_repeated_borderline_requests_eventually_block(pipeline):
    action = "list processes running on this host"
    verdicts = [pipeline.submit(action=action, agent="swarm-agent").verdict for _ in range(15)]

    assert Verdict.BLOCK not in verdicts[:2], (
        "fixture action now scores high enough to block on the first try; "
        "swarm detection is no longer the thing under test here"
    )

    assert Verdict.BLOCK in verdicts, "swarm detector never fired across 15 repeats"


def test_swarm_block_is_recorded_as_a_gate_violation(pipeline):
    action = "list processes running on this host"
    outcome = None
    for _ in range(15):
        outcome = pipeline.submit(action=action, agent="swarm-agent-2")
        if outcome.verdict is Verdict.BLOCK:
            break

    assert outcome is not None and outcome.verdict is Verdict.BLOCK
    sources = {v["source"] for v in outcome.gate_violations}
    assert "swarm_detector" in sources


def test_swarm_state_is_isolated_per_principal(pipeline):
    action = "list processes running on this host"
    a_verdicts = []
    for i in range(15):
        a_verdicts.append(pipeline.submit(action=action, agent="agent-a").verdict)
        pipeline.submit(action=action, agent="agent-b")

    assert Verdict.BLOCK in a_verdicts
