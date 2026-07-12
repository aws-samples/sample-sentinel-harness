"""
Offline tests for sentinel_harness.logutil — the unified logging module.
=========================================================================
Proves the library-safe logging contract with ZERO AWS / ZERO network:
- get_logger returns loggers under the sentinel_harness root (so one configure call
  governs everything the library emits);
- configure_logging is idempotent (never stacks handlers), honors env level + JSON
  mode, writes to stderr by default (never stdout), and under AWS Lambda adds NO
  handler (so CloudWatch does not double-emit);
- the JSON formatter emits one parseable line with the extra fields callers attach.
"""
from __future__ import annotations

import io
import json
import logging

import pytest

from sentinel_harness import logutil


@pytest.fixture(autouse=True)
def _clean_root():
    """Reset the sentinel_harness logger between tests so handler state can't leak."""
    lg = logging.getLogger(logutil.ROOT_LOGGER_NAME)
    saved = list(lg.handlers)
    lg.handlers.clear()
    yield
    lg.handlers.clear()
    lg.handlers.extend(saved)


def test_get_logger_is_namespaced():
    assert logutil.get_logger().name == "sentinel_harness"
    assert logutil.get_logger("sentinel_harness.core").name == "sentinel_harness.core"
    # a bare module name is reparented under the root so one config governs it
    assert logutil.get_logger("scenario_x").name == "sentinel_harness.scenario_x"


def test_configure_is_idempotent(monkeypatch):
    monkeypatch.delenv("AWS_LAMBDA_FUNCTION_NAME", raising=False)
    logutil.configure_logging(stream=io.StringIO())
    logutil.configure_logging(stream=io.StringIO())
    logutil.configure_logging(stream=io.StringIO())
    ours = [h for h in logging.getLogger("sentinel_harness").handlers
            if getattr(h, "_sentinel_handler", False)]
    assert len(ours) == 1  # never stacks


def test_env_level_applied(monkeypatch):
    monkeypatch.delenv("AWS_LAMBDA_FUNCTION_NAME", raising=False)
    monkeypatch.setenv("SENTINEL_LOG_LEVEL", "DEBUG")
    logutil.configure_logging(stream=io.StringIO())
    assert logging.getLogger("sentinel_harness").level == logging.DEBUG


def test_bad_level_falls_back_to_info(monkeypatch):
    monkeypatch.delenv("AWS_LAMBDA_FUNCTION_NAME", raising=False)
    logutil.configure_logging(level="NOPE", stream=io.StringIO())
    assert logging.getLogger("sentinel_harness").level == logging.INFO


def test_json_mode_emits_parseable_line_with_extras(monkeypatch):
    monkeypatch.delenv("AWS_LAMBDA_FUNCTION_NAME", raising=False)
    buf = io.StringIO()
    logutil.configure_logging(level="INFO", json=True, stream=buf)
    logutil.get_logger("sentinel_harness.t").warning("hi %s", "there", extra={"scenario": "cve"})
    rec = json.loads(buf.getvalue().strip())
    assert rec["level"] == "WARNING"
    assert rec["msg"] == "hi there"
    assert rec["scenario"] == "cve"
    assert rec["logger"] == "sentinel_harness.t"
    assert "ts" in rec


def test_text_mode_default_no_json(monkeypatch):
    monkeypatch.delenv("AWS_LAMBDA_FUNCTION_NAME", raising=False)
    monkeypatch.delenv("SENTINEL_LOG_JSON", raising=False)
    buf = io.StringIO()
    logutil.configure_logging(stream=buf)
    logutil.get_logger("sentinel_harness.t").info("plain message")
    out = buf.getvalue()
    assert "plain message" in out
    with pytest.raises(json.JSONDecodeError):
        json.loads(out.strip())  # text mode is NOT json


def test_lambda_adds_no_handler(monkeypatch):
    monkeypatch.setenv("AWS_LAMBDA_FUNCTION_NAME", "some-fn")
    logutil.configure_logging(level="INFO")
    ours = [h for h in logging.getLogger("sentinel_harness").handlers
            if getattr(h, "_sentinel_handler", False)]
    assert ours == []  # Lambda root handler ships to CloudWatch; we add none


def test_json_env_flag_truthy(monkeypatch):
    monkeypatch.delenv("AWS_LAMBDA_FUNCTION_NAME", raising=False)
    monkeypatch.setenv("SENTINEL_LOG_JSON", "yes")
    buf = io.StringIO()
    logutil.configure_logging(stream=buf)
    logutil.get_logger("sentinel_harness.t").info("x")
    json.loads(buf.getvalue().strip())  # must parse as JSON (flag honored)
