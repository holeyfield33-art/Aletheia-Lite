"""Build and verify the exact release artifacts in a clean virtualenv."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def run(*command: str, cwd: Path = ROOT, env: dict[str, str] | None = None) -> None:
    subprocess.run(command, cwd=cwd, env=env, check=True)


def package_version() -> str:
    text = (ROOT / "pyproject.toml").read_text()
    match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
    if match is None:
        raise RuntimeError("package version is missing")
    return match.group(1)


def inspect_artifacts(version: str) -> tuple[Path, Path]:
    wheel = ROOT / "dist" / f"aletheia_lite-{version}-py3-none-any.whl"
    sdist = ROOT / "dist" / f"aletheia_lite-{version}.tar.gz"
    if not wheel.exists() or not sdist.exists():
        raise RuntimeError("expected wheel and source distribution were not built")

    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
    forbidden = {".coverage", ".env", "audit.sqlite", "decisions.sqlite"}
    if any(Path(name).name in forbidden or name.endswith((".key", ".pem")) for name in names):
        raise RuntimeError("release wheel contains a local secret or database artifact")
    required = {"core/", "detectors/", "guards/", "dashboard/"}
    if not all(any(name.startswith(prefix) for name in names) for prefix in required):
        raise RuntimeError("release wheel is missing an expected package")

    with tarfile.open(sdist) as archive:
        names = archive.getnames()
    if any(Path(name).name in forbidden or name.endswith((".key", ".pem")) for name in names):
        raise RuntimeError("source distribution contains a local secret or database artifact")
    return wheel, sdist


def main() -> int:
    version = package_version()
    tag = os.environ.get("RELEASE_TAG")
    if tag and tag != f"v{version}":
        raise RuntimeError(f"release tag {tag!r} does not match package version {version!r}")

    for name in ("dist", "build"):
        shutil.rmtree(ROOT / name, ignore_errors=True)
    for path in ROOT.glob("*.egg-info"):
        shutil.rmtree(path, ignore_errors=True)

    run(sys.executable, "-m", "build")
    dist_files = [str(path) for path in (ROOT / "dist").glob("*")]
    run(sys.executable, "-m", "twine", "check", *dist_files)
    wheel, sdist = inspect_artifacts(version)

    with tempfile.TemporaryDirectory(prefix="aletheia-lite-release-") as raw_dir:
        venv = Path(raw_dir) / "venv"
        run(sys.executable, "-m", "venv", str(venv))
        python_dir = "Scripts" if os.name == "nt" else "bin"
        python_name = "python.exe" if os.name == "nt" else "python"
        python = venv / python_dir / python_name
        run(str(python), "-m", "pip", "install", str(wheel))
        run(str(python), str(ROOT / "scripts" / "package_smoke.py"), cwd=Path(raw_dir))
        run(str(python), "-c", "import core.demo, core.manifest, core.receipts")

    print(json.dumps({"version": version, "wheel": wheel.name, "sdist": sdist.name}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())