"""
Offline tests for the litellm.gateway inference-gateway skeleton
================================================================
ZERO AWS calls, ZERO network. The point of the skeleton is that it is importable
and inspectable WITHOUT the heavy ``litellm`` / ``strands`` stack installed:

- The import + entry-point-surface + audit-record tests run everywhere (they touch
  no heavy deps — those are imported lazily inside InferenceGateway._model).
- The audit hook records model + token fields and NEVER logs a secret.
- InferenceGateway.complete emits exactly one audit record (ok + error paths) with
  a stubbed model — no litellm needed. The real LiteLLMModel path is importorskip'd.
"""
from __future__ import annotations

import importlib.util
import logging
import os
import sys

import pytest

# Load the proxy module by explicit path under a UNIQUE name so it can never collide
# with anything else in sys.modules (mirrors tests/test_specialist.py loading style).
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_MODULE_PATH = os.path.join(REPO_ROOT, "litellm", "gateway", "proxy.py")
_UNIQUE_NAME = "sentinel_litellm_gateway_proxy"
_spec = importlib.util.spec_from_file_location(_UNIQUE_NAME, _MODULE_PATH)
proxy = importlib.util.module_from_spec(_spec)
sys.modules[_UNIQUE_NAME] = proxy
_spec.loader.exec_module(proxy)


# --------------------------------------------------------------------------- #
# Import is dependency-free                                                    #
# --------------------------------------------------------------------------- #
def test_module_imports_without_litellm():
    """proxy must import even when litellm/strands are absent — the heavy deps are
    imported lazily inside InferenceGateway._model, not at module top."""
    assert proxy.DEFAULT_MODEL_ID  # non-empty default model id
    for attr in ("InferenceGateway", "complete", "audit_record", "build_audit_record"):
        assert hasattr(proxy, attr), f"{attr} must be present"


def test_package_import_is_guarded():
    """The real litellm.gateway package must import without litellm installed too."""
    sys.path.insert(0, REPO_ROOT)
    import importlib
    pkg = importlib.import_module("litellm.gateway")
    assert callable(pkg.complete)
    assert callable(pkg.InferenceGateway)


# --------------------------------------------------------------------------- #
# Audit record: records model + token fields                                  #
# --------------------------------------------------------------------------- #
def test_audit_record_captures_model_and_tokens():
    usage = {"prompt_tokens": 12, "completion_tokens": 34, "total_tokens": 46}
    rec = proxy.build_audit_record(model_id="bedrock/claude", usage=usage,
                                   latency_ms=123.456, status="ok")
    assert rec["event"] == "inference"
    assert rec["model"] == "bedrock/claude"
    assert rec["prompt_tokens"] == 12
    assert rec["completion_tokens"] == 34
    assert rec["total_tokens"] == 46
    assert rec["latency_ms"] == 123.46  # rounded
    assert rec["status"] == "ok"


def test_audit_record_handles_object_usage():
    class _Usage:
        prompt_tokens = 5
        completion_tokens = 7
        total_tokens = 12

    rec = proxy.build_audit_record(model_id="openai/gpt", usage=_Usage())
    assert (rec["prompt_tokens"], rec["completion_tokens"], rec["total_tokens"]) == (5, 7, 12)


def test_audit_record_null_tokens_when_no_usage():
    rec = proxy.build_audit_record(model_id="m", usage=None)
    assert rec["prompt_tokens"] is None
    assert rec["total_tokens"] is None
    assert rec["status"] == "ok"


def test_audit_record_error_carries_type_only():
    rec = proxy.build_audit_record(model_id="m", status="error", error_type="RateLimitError")
    assert rec["status"] == "error"
    assert rec["error_type"] == "RateLimitError"


# --------------------------------------------------------------------------- #
# Audit record: NEVER logs a secret                                           #
# --------------------------------------------------------------------------- #
def test_audit_record_never_contains_secret_fields():
    usage = {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
    rec = proxy.build_audit_record(model_id="m", usage=usage, latency_ms=1.0)
    lowered = {k.lower() for k in rec}
    # None of the secret-hint keys may appear in an audit record.
    for banned in ("api_key", "authorization", "token", "secret", "password",
                   "messages", "prompt", "content", "headers"):
        assert banned not in lowered


def test_audit_record_has_no_secret_shaped_values():
    """No emitted value should carry an obvious credential prefix/content."""
    usage = {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
    rec = proxy.build_audit_record(model_id="bedrock/claude", usage=usage, latency_ms=2.0)
    blob = repr(rec)
    for marker in ("sk-", "AKIA", "Bearer ", "aws_secret", "SECRET-VALUE"):
        assert marker not in blob


# --------------------------------------------------------------------------- #
# InferenceGateway.complete — one audit record, stubbed model (no litellm)    #
# --------------------------------------------------------------------------- #
def test_complete_emits_one_audit_record_on_success(monkeypatch):
    captured: list = []

    class _StubModel:
        def converse(self, messages, **kw):
            return {"usage": {"prompt_tokens": 3, "completion_tokens": 4, "total_tokens": 7},
                    "text": "SECRET-VALUE should never be logged"}

    g = proxy.InferenceGateway(model_id="bedrock/claude", audit_sink=captured.append)
    # Inject the stub so no litellm import happens.
    g._model_obj = _StubModel()

    out = g.complete([{"role": "user", "content": "sk-fake-key-do-not-log"}])
    assert out["text"].startswith("SECRET-VALUE")  # returned to caller, not logged
    assert len(captured) == 1
    rec = captured[0]
    assert rec["model"] == "bedrock/claude"
    assert rec["total_tokens"] == 7
    assert rec["status"] == "ok"
    # The input message (a fake key) must NOT appear anywhere in the audit record.
    assert "sk-fake-key-do-not-log" not in repr(rec)
    assert "SECRET-VALUE" not in repr(rec)


def test_complete_audits_and_reraises_on_error(monkeypatch):
    captured: list = []

    class _BoomModel:
        def converse(self, messages, **kw):
            raise RuntimeError("provider blew up with sk-secret in the message")

    g = proxy.InferenceGateway(model_id="openai/gpt", audit_sink=captured.append)
    g._model_obj = _BoomModel()

    with pytest.raises(RuntimeError):
        g.complete([{"role": "user", "content": "x"}])
    # Exactly one record, error status, type only — no message (which held a secret).
    assert len(captured) == 1
    rec = captured[0]
    assert rec["status"] == "error"
    assert rec["error_type"] == "RuntimeError"
    assert "sk-secret" not in repr(rec)


def test_audit_sink_default_logs_structured_record(caplog):
    rec = proxy.build_audit_record(model_id="m", usage={"total_tokens": 1})
    with caplog.at_level(logging.INFO, logger="sentinel.litellm.gateway.audit"):
        proxy.audit_record(rec)
    assert any("inference audit" in r.getMessage() for r in caplog.records)


# --------------------------------------------------------------------------- #
# Real LiteLLMModel path is importorskip'd (skips cleanly without the stack)   #
# --------------------------------------------------------------------------- #
def test_real_litellm_model_build_when_installed():
    pytest.importorskip("litellm")
    pytest.importorskip("strands")
    g = proxy.InferenceGateway(model_id="bedrock/global.anthropic.claude-haiku-4-5")
    # _model() builds the real LiteLLMModel; just prove it constructs, no call made.
    model = g._model()
    assert model is not None
