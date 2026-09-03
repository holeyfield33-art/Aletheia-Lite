# Contributing

Install the development environment with:

```bash
pip install -e ".[dev]"
```

Before opening a pull request, run:

```bash
ruff check .
mypy
pytest --cov=core --cov=detectors --cov=guards --cov=dashboard \
  --cov-report=term-missing --cov-fail-under=85
python scripts/release_verify.py
```

Keep changes focused, add deterministic tests under the staged test layout,
and preserve fail-closed behavior, signed receipts, audit-chain integrity, and
dashboard authentication. Do not commit local databases, keys, build output,
or coverage artifacts.