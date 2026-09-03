# Quality Status

Validated locally on Python 3.12.

- Pytest: 340 passed
- Coverage: 88.27% overall with `--cov-fail-under=85`
- Critical coverage: pipeline 92%, receipts 86%, audit 90%, manifest 90%,
  circuit breaker 90%, token velocity 88%, zero-standing privileges 95%,
  safety bounds 96%, dashboard 96%
- Ruff: `ruff check .` passes
- Mypy: strict configuration passes
- CI: `.github/workflows/ci.yml` runs the requested Python 3.10, 3.11, and
  3.12 matrix with pip caching, linting, type checking, and coverage gating

Files changed or added in this quality pass:

- `pyproject.toml`
- `core/__main__.py`
- `core/audit.py`
- `core/decisions.py`
- `core/manifest.py`
- `core/rate_limit.py`
- `core/receipts.py`
- `core/scout.py`
- `core/nitpicker.py`
- `dashboard/server.py`
- `detectors/swarm_detector.py`
- `guards/circuit_breaker.py`
- `guards/token_velocity.py`
- `tests/test_stage7_ci_regressions.py`
- `.github/workflows/ci.yml`
- `.github/dependabot.yml`
