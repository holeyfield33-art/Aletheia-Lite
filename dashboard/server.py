"""Local-only decision dashboard (FastAPI).

Exposes the decision store over a tiny, bearer-token-protected HTTP surface.  It
deliberately fixes the gap found in aletheia-firewall's ``fw-control``: the store
records **every** decision — ``ALLOW`` included — so the dashboard reports
total-through vs total-blocked, not just incidents.

Design notes
------------
* Single local token via ``ALETHEIA_DASHBOARD_TOKEN`` (same pattern as
  ``fw-control``'s ``HELIOS_DASHBOARD_TOKEN``).  No auth provider, no tenants.
* Token comparison is timing-safe (:func:`hmac.compare_digest`).
* Fail-closed: if no token is configured every request is rejected.
* ``GET /events?limit=N`` returns JSON, or an HTML table when the client sends
  ``Accept: text/html``.
* The endpoint is protected by the in-memory sliding-window rate limiter.
"""

from __future__ import annotations

import hmac
import html
from typing import Any

from fastapi import Depends, FastAPI, Header, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse

from core.config import Config, get_config
from core.decisions import DecisionStore
from core.rate_limit import RateLimiter


def _extract_token(authorization: str | None) -> str | None:
    if not authorization:
        return None
    parts = authorization.split(None, 1)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1].strip()
    return authorization.strip()


def create_app(
    store: DecisionStore,
    config: Config | None = None,
    rate_limiter: RateLimiter | None = None,
) -> FastAPI:
    cfg = config or get_config()
    limiter = rate_limiter or RateLimiter(
        max_requests=cfg.rate_limit_max, window_seconds=cfg.rate_limit_window_s
    )
    app = FastAPI(title="aletheia-light dashboard", version="1.0.0")

    def _client_key(request: Request) -> str:
        return request.client.host if request.client else "unknown"

    def rate_limit(request: Request) -> None:
        decision = limiter.check(_client_key(request))
        if not decision.allowed:
            raise _http(429, "rate limit exceeded", {"Retry-After": str(int(decision.retry_after) + 1)})

    def authenticate(
        request: Request,
        authorization: str | None = Header(default=None),
    ) -> None:
        # Fail-closed when unconfigured.
        expected = cfg.dashboard_token
        if not expected:
            raise _http(503, "dashboard token not configured (set ALETHEIA_DASHBOARD_TOKEN)")
        provided = _extract_token(authorization)
        if not provided or not hmac.compare_digest(provided, expected):
            raise _http(401, "invalid or missing bearer token")

    @app.get("/health")
    def health() -> dict[str, Any]:  # unauthenticated liveness probe
        return {"status": "ok", "service": "aletheia-light"}

    @app.get("/events")
    def events(
        request: Request,
        limit: int = Query(default=50, ge=1, le=1000),
        verdict: str | None = Query(default=None),
        accept: str | None = Header(default=None),
        _rl: None = Depends(rate_limit),
        _auth: None = Depends(authenticate),
    ):
        rows = store.recent(limit=limit, verdict=verdict)
        stats = store.stats()
        if accept and "text/html" in accept.lower():
            return HTMLResponse(_render_html(rows, stats))
        return JSONResponse({"stats": stats, "events": rows})

    @app.get("/stats")
    def stats_endpoint(
        request: Request,
        _rl: None = Depends(rate_limit),
        _auth: None = Depends(authenticate),
    ) -> dict[str, Any]:
        return store.stats()

    return app


def _http(status: int, detail: str, headers: dict[str, str] | None = None):
    from fastapi import HTTPException

    return HTTPException(status_code=status, detail=detail, headers=headers)


_VERDICT_COLOR = {"ALLOW": "#1a7f37", "OBSERVE": "#9a6700", "BLOCK": "#cf222e"}


def _render_html(rows: list[dict[str, Any]], stats: dict[str, Any]) -> str:
    header = (
        "<tr><th>timestamp</th><th>verdict</th><th>agent</th>"
        "<th>reason</th><th>request_id</th></tr>"
    )
    body_rows = []
    import datetime

    for r in rows:
        ts = datetime.datetime.utcfromtimestamp(r["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
        color = _VERDICT_COLOR.get(r["verdict"], "#57606a")
        body_rows.append(
            "<tr>"
            f"<td>{html.escape(ts)}</td>"
            f"<td><b style='color:{color}'>{html.escape(r['verdict'])}</b></td>"
            f"<td>{html.escape(str(r['agent']))}</td>"
            f"<td>{html.escape(str(r['reason']))}</td>"
            f"<td><code>{html.escape(str(r['request_id']))}</code></td>"
            "</tr>"
        )
    summary = (
        f"total={stats.get('total', 0)} &nbsp; "
        f"through={stats.get('total_through', 0)} &nbsp; "
        f"blocked={stats.get('total_blocked', 0)}"
    )
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>aletheia-light dashboard</title>
<style>
 body{{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:2rem;color:#1f2328}}
 h1{{font-size:1.3rem}} .summary{{margin:.5rem 0 1rem;color:#57606a;font-variant-numeric:tabular-nums}}
 table{{border-collapse:collapse;width:100%;font-size:.9rem}}
 th,td{{text-align:left;padding:.4rem .6rem;border-bottom:1px solid #d0d7de}}
 th{{background:#f6f8fa}} code{{font-size:.8rem;color:#57606a}}
</style></head>
<body>
<h1>aletheia-light — decisions</h1>
<div class="summary">{summary}</div>
<table>{header}{''.join(body_rows)}</table>
</body></html>"""
