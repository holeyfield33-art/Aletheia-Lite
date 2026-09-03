# Releasing

Release preparation is performed on a clean branch and is never a substitute
for human review. Do not tag or publish until the report is `GO`.

1. Update `CHANGELOG.md` and `pyproject.toml` to the same version.
2. Run `python scripts/release_verify.py`.
3. Run the full coverage-gated test suite and inspect package contents.
4. Open a pull request and wait for the Python 3.10-3.12 CI matrix.
5. After approval, create a matching `vX.Y.Z` tag.

The tag workflow checks tag/package agreement, rebuilds the exact tagged
artifacts, installs the wheel in a clean environment, and publishes through
PyPI Trusted Publishing/OIDC. It does not use a stored PyPI API token.
