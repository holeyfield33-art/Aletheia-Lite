"""Single-node configuration for aletheia-light.

The upstream ``core/config.py`` carried a large surface of multi-tenant / hosted
settings.  This is stripped to the settings a single local install actually
uses: where the SQLite audit log lives, the dashboard token, rate-limit budget,
and the *statically calibrated* detector thresholds (the calibration-manifest
tuning tool is deferred to v2, so these ship as sane defaults).

Everything is overridable through ``ALETHEIA_*`` environment variables so the
tool needs no config file to run.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


def _env_str(name: str, default: str) -> str:
    return os.environ.get(name, default)


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class DetectorThresholds:
    """Statically calibrated defaults for the spectral / SPRT detectors.

    ``mu0``/``mu1`` are the null and alternative means for the SPRT swarm test;
    ``sigma2`` the assumed variance; ``theta_bk`` the Berry-Keating spectral
    rigidity drift threshold above which a request is treated as evasive.
    """

    mu0: float = field(default_factory=lambda: _env_float("ALETHEIA_MU0", 0.15))
    mu1: float = field(default_factory=lambda: _env_float("ALETHEIA_MU1", 0.65))
    sigma2: float = field(default_factory=lambda: _env_float("ALETHEIA_SIGMA2", 0.25))
    theta_bk: float = field(default_factory=lambda: _env_float("ALETHEIA_THETA_BK", 0.55))
    # SPRT error bounds -> decision boundaries.
    alpha: float = field(default_factory=lambda: _env_float("ALETHEIA_SPRT_ALPHA", 0.05))
    beta: float = field(default_factory=lambda: _env_float("ALETHEIA_SPRT_BETA", 0.05))


@dataclass
class Config:
    """Root configuration object."""

    # Storage
    data_dir: Path = field(
        default_factory=lambda: Path(_env_str("ALETHEIA_DATA_DIR", ".aletheia")).expanduser()
    )
    audit_db: str = field(default_factory=lambda: _env_str("ALETHEIA_AUDIT_DB", "audit.sqlite"))
    decisions_db: str = field(
        default_factory=lambda: _env_str("ALETHEIA_DECISIONS_DB", "decisions.sqlite")
    )

    # Crypto / receipts
    key_dir: str = field(default_factory=lambda: _env_str("ALETHEIA_KEY_DIR", "keys"))
    manifest_path: str = field(default_factory=lambda: _env_str("ALETHEIA_MANIFEST", ""))

    # Dashboard
    dashboard_token: str = field(
        default_factory=lambda: _env_str("ALETHEIA_DASHBOARD_TOKEN", "")
    )
    dashboard_host: str = field(
        default_factory=lambda: _env_str("ALETHEIA_DASHBOARD_HOST", "127.0.0.1")
    )
    dashboard_port: int = field(default_factory=lambda: _env_int("ALETHEIA_DASHBOARD_PORT", 8787))

    # Rate limiting (in-memory sliding window protecting the dashboard endpoint)
    rate_limit_max: int = field(default_factory=lambda: _env_int("ALETHEIA_RATE_MAX", 60))
    rate_limit_window_s: float = field(
        default_factory=lambda: _env_float("ALETHEIA_RATE_WINDOW", 60.0)
    )

    # Guards
    token_budget: int = field(default_factory=lambda: _env_int("ALETHEIA_TOKEN_BUDGET", 100_000))
    token_window_s: float = field(default_factory=lambda: _env_float("ALETHEIA_TOKEN_WINDOW", 60.0))
    breaker_max_failures: int = field(
        default_factory=lambda: _env_int("ALETHEIA_BREAKER_FAILURES", 5)
    )
    breaker_reset_s: float = field(default_factory=lambda: _env_float("ALETHEIA_BREAKER_RESET", 30.0))

    # Logging
    log_level: str = field(default_factory=lambda: _env_str("ALETHEIA_LOG_LEVEL", "INFO"))

    thresholds: DetectorThresholds = field(default_factory=DetectorThresholds)

    def __post_init__(self) -> None:
        self.data_dir = Path(self.data_dir)

    # -- derived paths -------------------------------------------------------
    @property
    def audit_db_path(self) -> Path:
        return self.data_dir / self.audit_db

    @property
    def decisions_db_path(self) -> Path:
        return self.data_dir / self.decisions_db

    @property
    def key_dir_path(self) -> Path:
        return self.data_dir / self.key_dir

    def ensure_dirs(self) -> None:
        """Create the data and key directories if they do not exist."""

        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.key_dir_path.mkdir(parents=True, exist_ok=True)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["data_dir"] = str(self.data_dir)
        # Never serialize the secret token verbatim.
        d["dashboard_token"] = "***" if self.dashboard_token else ""
        return d


_ACTIVE: Config | None = None


def load_config(**overrides: Any) -> Config:
    """Build (and cache) a :class:`Config` from the environment.

    ``overrides`` win over environment variables and are handy for tests.
    """

    global _ACTIVE
    cfg = Config()
    for key, value in overrides.items():
        if hasattr(cfg, key):
            setattr(cfg, key, value)
    cfg.__post_init__()
    _ACTIVE = cfg
    return cfg


def get_config() -> Config:
    """Return the active config, loading a default one on first access."""

    global _ACTIVE
    if _ACTIVE is None:
        _ACTIVE = load_config()
    return _ACTIVE
