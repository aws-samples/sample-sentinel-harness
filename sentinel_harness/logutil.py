"""
sentinel-harness · unified logging (stdlib-only, library-safe, backward-compatible)
====================================================================================
One place to get a namespaced logger and (optionally) configure handlers, so the
library stops swallowing internal errors into ``print()`` on stdout.

Design contract (why this exists and what it must NOT break):

- **Library code uses** :func:`get_logger` and logs at the right level. It NEVER
  configures handlers at import time — that is the application's job (a library that
  calls ``basicConfig`` hijacks its host's logging).
- **Scenario / CLI human output stays on stdout via ``print``.** This module logs to
  **stderr** by default, so wiring it in never pollutes the human-readable scenario
  output (which tests and demos parse). The two channels are deliberately separate:
  stdout = the narrated result a user reads; stderr = structured operational logs.
- **Lambda/CloudWatch safe.** Under ``AWS_LAMBDA_FUNCTION_NAME`` the runtime already
  installs a root handler; :func:`configure_logging` then only sets the level and
  adds NO handler, so log lines are not double-emitted to CloudWatch.
- **Idempotent.** Calling :func:`configure_logging` more than once attaches exactly
  one handler.

Env flags (documented in ``docs/OBSERVABILITY.md``):
- ``SENTINEL_LOG_LEVEL`` — logger level (default ``INFO``).
- ``SENTINEL_LOG_JSON`` — truthy → one-line JSON records (for CloudWatch/ingestion);
  otherwise a compact human text format.
"""
from __future__ import annotations

import json
import logging
import os
import sys
from typing import Any, Optional, TextIO

__all__ = ["get_logger", "configure_logging", "ROOT_LOGGER_NAME"]

ROOT_LOGGER_NAME = "sentinel_harness"

# Reuse the same truthy set the token-metric flag uses so env parsing is consistent.
_TRUTHY = {"1", "true", "yes", "on"}


def get_logger(name: str = ROOT_LOGGER_NAME) -> logging.Logger:
    """Return a namespaced logger under ``sentinel_harness`` (library-safe).

    Does NOT add handlers or set a level — that stays the application's decision via
    :func:`configure_logging`. Call this at module top: ``_log = get_logger(__name__)``.
    A bare ``__name__`` from within the package already sits under the root name, so
    child loggers propagate to the one handler :func:`configure_logging` installs."""
    if name == ROOT_LOGGER_NAME or name.startswith(ROOT_LOGGER_NAME + "."):
        return logging.getLogger(name)
    # A module passing its own __name__ that isn't under the package (e.g. a scenario
    # script run as "__main__") still gets a child of our root, so one configure call
    # governs everything the library emits.
    return logging.getLogger(f"{ROOT_LOGGER_NAME}.{name}")


class _JsonFormatter(logging.Formatter):
    """One-line JSON per record: ``{ts, level, logger, msg, **extras}``.

    ``extras`` are any non-standard attributes attached via ``logger.info(..., extra=)``
    so callers can add structured fields (e.g. ``scenario``) without string-munging."""

    _STD = frozenset(vars(logging.makeLogRecord({})).keys()) | {"message", "asctime"}

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for k, v in record.__dict__.items():
            if k not in self._STD and not k.startswith("_"):
                payload[k] = v
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str, ensure_ascii=False)


def _truthy(val: Optional[str]) -> bool:
    return val is not None and val.strip().lower() in _TRUTHY


def configure_logging(
    level: Optional[str] = None,
    *,
    json: Optional[bool] = None,
    stream: Optional[TextIO] = None,
) -> logging.Logger:
    """Configure the ``sentinel_harness`` logger once (idempotent). Returns it.

    Parameters
    ----------
    level:
        Log level name (``"DEBUG"``/``"INFO"``/...). Defaults to
        ``$SENTINEL_LOG_LEVEL`` then ``"INFO"``. An unknown name falls back to
        ``INFO`` rather than raising (a bad env var must not crash startup).
    json:
        ``True`` → JSON records; ``False`` → text. Defaults to
        ``$SENTINEL_LOG_JSON`` (truthy) then text.
    stream:
        Handler stream; defaults to ``sys.stderr`` so scenario stdout is untouched.

    Under AWS Lambda (``AWS_LAMBDA_FUNCTION_NAME`` set) NO handler is added — the
    runtime's root handler already ships records to CloudWatch — only the level is
    set, preventing double emission."""
    logger = logging.getLogger(ROOT_LOGGER_NAME)

    lvl_name = (level or os.environ.get("SENTINEL_LOG_LEVEL") or "INFO").upper()
    logger.setLevel(getattr(logging, lvl_name, logging.INFO))

    # Don't let records also hit the root logger's handlers (avoids duplicate lines
    # when the host app has its own root config).
    logger.propagate = False

    if os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
        # Lambda already has a handler on the root; just set our level and return.
        logger.propagate = True
        return logger

    use_json = json if json is not None else _truthy(os.environ.get("SENTINEL_LOG_JSON"))
    target = stream if stream is not None else sys.stderr

    # Idempotent: only add our handler once (tagged so re-runs don't stack handlers).
    for h in logger.handlers:
        if getattr(h, "_sentinel_handler", False):
            h.setFormatter(_JsonFormatter() if use_json else _text_formatter())
            return logger

    handler = logging.StreamHandler(target)
    handler._sentinel_handler = True  # type: ignore[attr-defined]
    handler.setFormatter(_JsonFormatter() if use_json else _text_formatter())
    logger.addHandler(handler)
    return logger


def _text_formatter() -> logging.Formatter:
    """Compact human text: ``LEVEL sentinel_harness.mod: message``."""
    return logging.Formatter("%(levelname)s %(name)s: %(message)s")
