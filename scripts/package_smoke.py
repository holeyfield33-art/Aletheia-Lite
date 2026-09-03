"""Smoke-test an installed Aletheia Lite wheel."""

from __future__ import annotations

import subprocess
import sys


def main() -> int:
    subprocess.run(["aletheia-lite", "demo", "--json"], check=True)
    completed = subprocess.run(
        ["aletheia-lite", "check", "benign text", "--agent", "release-smoke"],
        check=True,
        capture_output=True,
        text=True,
    )
    if "ALLOW" not in completed.stdout:
        raise RuntimeError("installed CLI did not produce an ALLOW result")
    completed = subprocess.run(
        [sys.executable, "-c", "import core, detectors, guards, dashboard"], check=True
    )
    del completed
    return 0


if __name__ == "__main__":
    raise SystemExit(main())