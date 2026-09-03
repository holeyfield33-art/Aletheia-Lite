"""Smoke-test an installed Aletheia Lite wheel."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def main() -> int:
    cli_name = "aletheia-lite.exe" if sys.platform == "win32" else "aletheia-lite"
    cli = Path(sys.executable).with_name(cli_name)
    if not cli.is_file():
        raise RuntimeError(f"installed CLI was not found at {cli}")
    subprocess.run([str(cli), "demo", "--json"], check=True)
    completed = subprocess.run(
        [str(cli), "check", "benign text", "--agent", "release-smoke"],
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