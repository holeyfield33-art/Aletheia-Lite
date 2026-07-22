"""Trivial structured logging configuration for aletheia-light.

A single-node tool does not need a log aggregation stack.  This module gives
every component a JSON-line logger so that decisions, violations and receipts
can be grepped or shipped later without pulling in a framework.
"""

from __future__ import annotations

import json
import logging
import sys
import time
from typing import Any


class _JsonFormatter(logging.Formatter):
    """Render each record as a single JSON line."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        # Attach any structured fields passed via ``extra={"fields": {...}}``.
        fields = getattr(record, "fields", None)
        if isinstance(fields, dict):
            payload.update(fields)
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, sort_keys=True)


_CONFIGURED = False


def configure(level: str = "INFO") -> None:
    """Install the JSON handler on the root ``aletheia`` logger once."""

    global _CONFIGURED
    if _CONFIGURED:
        return
    handler = logging.StreamHandler(stream=sys.stderr)
    handler.setFormatter(_JsonFormatter())
    root = logging.getLogger("aletheia")
    root.handlers[:] = [handler]
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    root.propagate = False
    _CONFIGURED = True


def get_logger(name: str, level: str = "INFO") -> logging.Logger:
    """Return a child of the ``aletheia`` logger, configuring on first use."""

    configure(level)
    return logging.getLogger(f"aletheia.{name}")


def log_event(logger: logging.Logger, msg: str, **fields: Any) -> None:
    """Emit ``msg`` with arbitrary structured ``fields``."""

    logger.info(msg, extra={"fields": fields})
