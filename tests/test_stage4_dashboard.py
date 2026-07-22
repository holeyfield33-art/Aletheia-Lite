"""Stage 4 — dashboard & rate-limit tests.  Gates Stage 5."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from core.config import load_config
from core.decisions import DecisionStore, Decision
from core.rate_limit import RateLimiter
from core.types import Verdict
from dashboard.server import create_app


# --------------------------------------------------------------------------- #
# rate limiter
# --------------------------------------------------------------------------- #
def test_rate_limiter_allows_then_blocks():
    clock = [0.0]
    rl = RateLimiter(max_requests=3, window_seconds=10, time_func=lambda: clock[0])
    assert all(rl.check("k").allowed for _ in range(3))
    d = rl.check("k")
    assert not d.allowed
    assert d.retry_after > 0


def test_rate_limiter_window_slides():
    clock = [0.0]
    rl = RateLimiter(max_requests=1, window_seconds=5, time_func=lambda: clock[0])
    assert rl.check("k").allowed
    assert not rl.check("k").allowed
    clock[0] = 6.0
    assert rl.check("k").allowed


def test_rate_limiter_per_key():
    rl = RateLimiter(max_requests=1, window_seconds=60)
    assert rl.check("a").allowed
    assert rl.check("b").allowed


# --------------------------------------------------------------------------- #
# dashboard fixtures
# --------------------------------------------------------------------------- #
@pytest.fixture
def store():
    s = DecisionStore(":memory:")
    s.record(Decision("r1", "x1", "agentA", Verdict.ALLOW, 0.1, "cleared all gates"))
    s.record(Decision("r2", "x2", "agentA", Verdict.BLOCK, 0.9, "manifest denies 'exfil'"))
    s.record(Decision("r3", "x3", "agentB", Verdict.OBSERVE, 0.4, "elevated suspicion"))
    yield s
    s.close()


def _client(store, token="secret-token", **cfg_over):
    cfg = load_config(dashboard_token=token, rate_limit_max=1000, **cfg_over)
    app = create_app(store, config=cfg)
    return TestClient(app)


# --------------------------------------------------------------------------- #
# auth
# --------------------------------------------------------------------------- #
def test_events_requires_token(store):
    c = _client(store)
    assert c.get("/events").status_code == 401
    assert c.get("/events", headers={"Authorization": "Bearer wrong"}).status_code == 401


def test_events_fail_closed_without_configured_token(store):
    c = _client(store, token="")
    assert c.get("/events", headers={"Authorization": "Bearer anything"}).status_code == 503


def test_events_authorized_json(store):
    c = _client(store)
    resp = c.get("/events", headers={"Authorization": "Bearer secret-token"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["stats"]["total"] == 3
    assert data["stats"]["total_through"] == 2
    assert data["stats"]["total_blocked"] == 1
    # ALLOW is a real, first-class event present in the feed (the fw-control gap).
    verdicts = {e["verdict"] for e in data["events"]}
    assert "ALLOW" in verdicts and "BLOCK" in verdicts and "OBSERVE" in verdicts


def test_events_limit_and_filter(store):
    c = _client(store)
    resp = c.get("/events?limit=1", headers={"Authorization": "Bearer secret-token"})
    assert len(resp.json()["events"]) == 1
    resp = c.get("/events?verdict=BLOCK", headers={"Authorization": "Bearer secret-token"})
    events = resp.json()["events"]
    assert all(e["verdict"] == "BLOCK" for e in events) and len(events) == 1


def test_events_html_view(store):
    c = _client(store)
    resp = c.get(
        "/events",
        headers={"Authorization": "Bearer secret-token", "Accept": "text/html"},
    )
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "<table>" in resp.text
    assert "ALLOW" in resp.text and "BLOCK" in resp.text


def test_health_is_open(store):
    c = _client(store)
    assert c.get("/health").status_code == 200


def test_rate_limit_returns_429(store):
    cfg = load_config(dashboard_token="t", rate_limit_max=2, rate_limit_window_s=60)
    app = create_app(store, config=cfg)
    c = TestClient(app)
    h = {"Authorization": "Bearer t"}
    assert c.get("/events", headers=h).status_code == 200
    assert c.get("/events", headers=h).status_code == 200
    r = c.get("/events", headers=h)
    assert r.status_code == 429
    assert "Retry-After" in r.headers
