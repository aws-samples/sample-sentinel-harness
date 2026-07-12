"""
Offline tests for the SentinelHarness/TokensPerScenario emit path (M11)
========================================================================
Two contracts are proven here, with ZERO AWS / ZERO network:

1. ``sentinel_harness.observability.emit_token_metric`` writes the EXACT structured
   JSON line the CDK ``ObservabilityStack`` MetricFilter parses
   (``iac-cdk/lib/observability-stack.ts``: ``FilterPattern.exists("$.tokens")`` +
   ``metricValue: "$.tokens"``). The load-bearing invariant is
   ``tokens == input_tokens + output_tokens`` — that is what becomes the metric.

2. ``core._consume_stream`` now SURFACES token ``usage`` from the ``metadata`` stream
   event as a top-level ``result["usage"]`` (additive — the existing keys are
   untouched), so a scenario can emit the metric straight from an invoke result.

The default emit path is pure stdout/log (no boto3). The opt-in direct-PutMetricData
path is GATED behind ``SENTINEL_TOKEN_METRIC_LIVE`` and is NOT exercised here; we
assert only that leaving the flag unset builds no client and touches no AWS. A
monkeypatched fake CloudWatch client covers the gated branch without any network.

No real account/role/secret: the 000000000000 placeholder is set below.
"""
from __future__ import annotations

import json
import os

import pytest

# --- Hermetic import: no real region/profile/credentials resolution. ---
os.environ.setdefault("SENTINEL_REGION", "us-east-1")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault(
    "SENTINEL_EXECUTION_ROLE_ARN", "arn:aws:iam::000000000000:role/test-harness-role"
)
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
# Ensure the opt-in live path is OFF for the offline suite (belt-and-suspenders).
os.environ.pop("SENTINEL_TOKEN_METRIC_LIVE", None)

from sentinel_harness import core as sh  # noqa: E402
from sentinel_harness import observability as obs  # noqa: E402


# --------------------------------------------------------------------------- #
# The MetricFilter selector, re-implemented offline. FilterPattern.exists      #
# ("$.tokens") matches any JSON event that HAS a numeric $.tokens; the metric  #
# value is $.tokens. If this predicate matches, the CDK filter would emit.     #
# --------------------------------------------------------------------------- #
def _metric_filter_matches(line: str):
    """Return the numeric $.tokens the CDK MetricFilter would extract, or None."""
    try:
        obj = json.loads(line)
    except (ValueError, TypeError):
        return None
    if not isinstance(obj, dict):
        return None
    tok = obj.get("tokens")
    if not isinstance(tok, (int, float)) or isinstance(tok, bool):
        return None
    return tok


class _CaptureLog:
    """A ``log=`` sink that captures the exact string emit_token_metric writes."""

    def __init__(self):
        self.lines: list[str] = []

    def __call__(self, s):
        self.lines.append(s)


# =========================================================================== #
# emit_token_metric — the structured line the MetricFilter parses             #
# =========================================================================== #
def test_emit_writes_json_line_the_metric_filter_matches():
    """The emitted line is valid JSON with a numeric $.tokens the filter extracts."""
    sink = _CaptureLog()
    obs.emit_token_metric("cve_triage", 5352, 791, log=sink)
    assert len(sink.lines) == 1
    matched = _metric_filter_matches(sink.lines[0])
    assert matched == 5352 + 791  # the filter's $.tokens metric value


def test_emit_tokens_equals_input_plus_output():
    """The load-bearing invariant: tokens == input_tokens + output_tokens."""
    sink = _CaptureLog()
    obs.emit_token_metric("detection_gen", 100, 250, log=sink)
    obj = json.loads(sink.lines[0])
    assert obj["tokens"] == obj["input_tokens"] + obj["output_tokens"] == 350


def test_emit_line_has_the_expected_keys():
    """scenario + tokens + input_tokens + output_tokens are all present."""
    sink = _CaptureLog()
    obs.emit_token_metric("threat_hunt", 10, 20, log=sink)
    obj = json.loads(sink.lines[0])
    assert obj["scenario"] == "threat_hunt"
    for k in ("scenario", "tokens", "input_tokens", "output_tokens"):
        assert k in obj


def test_emit_returns_the_emitted_dict():
    """The return value mirrors the emitted line so callers/tests can assert on it."""
    sink = _CaptureLog()
    out = obs.emit_token_metric("s", 3, 4, log=sink)
    assert out == json.loads(sink.lines[0])
    assert out["tokens"] == 7


def test_emit_defaults_to_print(capsys):
    """With no log= override the line goes to stdout (default print)."""
    obs.emit_token_metric("stdout_case", 1, 2)
    captured = capsys.readouterr().out.strip()
    assert _metric_filter_matches(captured) == 3


def test_emit_none_counts_coerce_to_zero():
    """A partial/errored invoke (None usage) still emits a well-formed zero line."""
    sink = _CaptureLog()
    obs.emit_token_metric("empty", None, None, log=sink)
    obj = json.loads(sink.lines[0])
    assert obj["tokens"] == 0
    assert _metric_filter_matches(sink.lines[0]) == 0


def test_emit_extra_fields_never_clobber_tokens():
    """Extra structured fields merge in but cannot displace the metric contract."""
    sink = _CaptureLog()
    obs.emit_token_metric("s", 5, 5, log=sink, session_id="sid-1", tokens=99999)
    obj = json.loads(sink.lines[0])
    assert obj["session_id"] == "sid-1"
    assert obj["tokens"] == 10  # extra tokens= override is ignored


def test_emit_line_is_ascii_safe_json_for_unicode_scenario():
    """A non-ASCII scenario name stays valid parseable JSON (ensure_ascii=False)."""
    sink = _CaptureLog()
    obs.emit_token_metric("威胁狩猎", 2, 3, log=sink)
    obj = json.loads(sink.lines[0])  # must still parse
    assert obj["scenario"] == "威胁狩猎"
    assert _metric_filter_matches(sink.lines[0]) == 5


def test_namespace_and_metric_match_cdk_stack():
    """The constants must equal the CDK stack's METRIC_NAMESPACE / TOKENS_METRIC_NAME."""
    assert obs.METRIC_NAMESPACE == "SentinelHarness"
    assert obs.TOKENS_METRIC_NAME == "TokensPerScenario"


# =========================================================================== #
# emit_token_metric_from_result — bridge from an invoke() result              #
# =========================================================================== #
def test_emit_from_result_reads_usage_field():
    """Pulls inputTokens/outputTokens out of result['usage'] (GA key shape)."""
    sink = _CaptureLog()
    result = {"usage": {"inputTokens": 5352, "outputTokens": 791, "totalTokens": 6143}}
    obs.emit_token_metric_from_result("cve_triage", result, log=sink)
    obj = json.loads(sink.lines[0])
    assert obj["input_tokens"] == 5352
    assert obj["output_tokens"] == 791
    assert obj["tokens"] == 6143


def test_emit_from_result_falls_back_to_metadata_usage():
    """When ['usage'] is absent it reads ['metadata']['usage']."""
    sink = _CaptureLog()
    result = {"metadata": {"usage": {"inputTokens": 8, "outputTokens": 2}}}
    obs.emit_token_metric_from_result("s", result, log=sink)
    assert json.loads(sink.lines[0])["tokens"] == 10


def test_emit_from_result_no_usage_emits_zero_line():
    """An errored/empty result (no usage) still emits a well-formed zero line."""
    sink = _CaptureLog()
    obs.emit_token_metric_from_result("s", {"usage": None, "metadata": {}}, log=sink)
    assert json.loads(sink.lines[0])["tokens"] == 0


# =========================================================================== #
# core._consume_stream surfaces usage — additive, no contract break           #
# =========================================================================== #
def test_consume_stream_surfaces_usage_top_level():
    """The metadata event's usage is lifted to result['usage'] (top-level)."""
    stream = [
        {"contentBlockDelta": {"delta": {"text": "done"}}},
        {"metadata": {"usage": {"inputTokens": 5352, "outputTokens": 791, "totalTokens": 6143}}},
        {"messageStop": {"stopReason": "end_turn"}},
    ]
    r = sh._consume_stream(iter(stream))
    assert r["usage"] == {"inputTokens": 5352, "outputTokens": 791, "totalTokens": 6143}
    # metadata still carries it too (nothing removed — purely additive).
    assert r["metadata"]["usage"] == r["usage"]


def test_consume_stream_usage_none_when_absent():
    """A stream with no metadata usage yields usage=None (not a crash)."""
    stream = [
        {"contentBlockDelta": {"delta": {"text": "hi"}}},
        {"messageStop": {"stopReason": "end_turn"}},
    ]
    r = sh._consume_stream(iter(stream))
    assert r["usage"] is None


def test_consume_stream_preserves_existing_contract_keys():
    """The pre-existing result keys are all still present (additive-only change)."""
    r = sh._consume_stream(iter([{"messageStop": {"stopReason": "end_turn"}}]))
    for k in ("text", "events", "stop_reason", "tools_used", "tool_use", "metadata", "error"):
        assert k in r
    assert "usage" in r  # the new one


def test_consume_stream_result_feeds_emit_end_to_end():
    """End-to-end: surface usage from a stream, then emit the metric line from it."""
    stream = [
        {"contentBlockStart": {"start": {"toolUse": {"toolUseId": "tu-1", "name": "gate"}}}},
        {"contentBlockDelta": {"delta": {"toolUse": {"input": "{}"}}}},
        {"contentBlockStop": {}},
        {"metadata": {"usage": {"inputTokens": 40, "outputTokens": 60}}},
        {"messageStop": {"stopReason": "tool_use"}},
    ]
    r = sh._consume_stream(iter(stream))
    sink = _CaptureLog()
    obs.emit_token_metric_from_result("hitl", r, log=sink)
    assert _metric_filter_matches(sink.lines[0]) == 100


# =========================================================================== #
# opt-in direct PutMetricData — GATED, no AWS unless the flag is set           #
# =========================================================================== #
def test_default_path_never_touches_aws(monkeypatch):
    """With the flag unset, emit must NOT call put_metric (no client is built)."""
    def _boom(*a, **k):  # pragma: no cover - asserted not called
        raise AssertionError("offline default path must not PutMetricData")

    monkeypatch.setattr(obs, "put_metric", _boom)
    monkeypatch.delenv("SENTINEL_TOKEN_METRIC_LIVE", raising=False)
    sink = _CaptureLog()
    obs.emit_token_metric("s", 1, 1, log=sink)  # must not raise
    assert json.loads(sink.lines[0])["tokens"] == 2


def test_live_flag_triggers_put_metric_with_injected_client(monkeypatch):
    """When the flag is truthy, emit calls put_metric; a fake client proves the
    namespace/metric/value WITHOUT any real AWS."""
    calls: list = []

    # Capture the gated put_metric call directly (no recursion into the real fn,
    # no boto3). Proves the flag triggers exactly one emit with the right tokens.
    def _fake_put(tokens, **kw):
        calls.append((tokens, kw))
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    monkeypatch.setattr(obs, "put_metric", _fake_put)
    monkeypatch.setenv("SENTINEL_TOKEN_METRIC_LIVE", "1")

    sink = _CaptureLog()
    obs.emit_token_metric("cve_triage", 30, 70, log=sink)

    assert len(calls) == 1
    tokens, kw = calls[0]
    assert tokens == 100  # tokens == input + output
    assert kw.get("scenario") == "cve_triage"
    # And the line was still written for the MetricFilter path.
    assert _metric_filter_matches(sink.lines[0]) == 100


def test_live_flag_variants_are_recognized(monkeypatch):
    """Common truthy spellings all enable the gated path."""
    for val in ("1", "true", "TRUE", "yes", "on"):
        monkeypatch.setenv("SENTINEL_TOKEN_METRIC_LIVE", val)
        assert obs._live_enabled() is True
    for val in ("0", "false", "no", "off", ""):
        monkeypatch.setenv("SENTINEL_TOKEN_METRIC_LIVE", val)
        assert obs._live_enabled() is False


def test_put_metric_uses_injected_client_no_boto3():
    """put_metric with an injected client does zero AWS and emits the right shape."""
    calls: list = []

    class _FakeCW:
        def put_metric_data(self, **kw):
            calls.append(kw)
            return {"ok": True}

    out = obs.put_metric(42, scenario="s", client=_FakeCW())
    assert out == {"ok": True}
    assert calls[0]["MetricData"][0]["Value"] == 42.0
    assert calls[0]["Namespace"] == "SentinelHarness"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))


# --------------------------------------------------------------------------- #
# Multi-signal emitters (latency / tool-calls / errors / hitl / eval-score)    #
# --------------------------------------------------------------------------- #
def test_metric_line_carries_named_numeric_field():
    line = obs.metric_line("latency_ms", 123.4, scenario="cve", unit="Milliseconds")
    assert line["metric"] == "latency_ms"
    assert line["latency_ms"] == 123.4
    assert line["unit"] == "Milliseconds"
    assert line["scenario"] == "cve"


def test_metric_line_coerces_bad_value_to_zero():
    assert obs.metric_line("x", None)["x"] == 0.0
    assert obs.metric_line("x", float("nan"))["x"] == 0.0
    assert obs.metric_line("x", "not-a-number")["x"] == 0.0


def test_metric_line_dims_never_clobber_metric_field():
    # a dim named the same as the metric must not overwrite the numeric value
    line = obs.metric_line("tool_calls", 3, tool_calls="oops")
    assert line["tool_calls"] == 3.0


def test_emit_helpers_write_expected_fields():
    out = []
    obs.emit_invoke_latency("s", 50, log=out.append)
    obs.emit_tool_calls("s", 2, log=out.append)
    obs.emit_error("s", "throttle", log=out.append)
    obs.emit_hitl_gate("s", "request_human_review", log=out.append)
    obs.emit_eval_score("s", "safety", 0.9, True, log=out.append)
    lines = [json.loads(x) for x in out]
    assert lines[0]["latency_ms"] == 50.0 and lines[0]["unit"] == "Milliseconds"
    assert lines[1]["tool_calls"] == 2.0
    assert lines[2]["errors"] == 1.0 and lines[2]["kind"] == "throttle"
    assert lines[3]["hitl_gate"] == 1.0 and lines[3]["gate"] == "request_human_review"
    assert lines[4]["eval_score"] == 0.9 and lines[4]["dimension"] == "safety" and lines[4]["passed"] is True


def test_metric_fields_map_matches_emitters():
    # the METRIC_FIELDS registry must name every field the emitters produce
    for f in ("tokens", "latency_ms", "tool_calls", "errors", "hitl_gate", "eval_score"):
        assert f in obs.METRIC_FIELDS


# --------------------------------------------------------------------------- #
# core.invoke_and_meter — closes the "metric had no emitter" gap               #
# --------------------------------------------------------------------------- #
def test_invoke_and_meter_emits_all_signals(monkeypatch):
    captured = []
    fake_result = {
        "text": "done", "tools_used": ["nvd_lookup", "epss_kev"],
        "usage": {"inputTokens": 100, "outputTokens": 40}, "error": None,
    }
    monkeypatch.setattr(sh, "invoke", lambda *a, **k: fake_result)
    out = sh.invoke_and_meter("arn:aws:...:harness/h", "sess-" + "x" * 30,
                              "hi", scenario="cve", log=captured.append)
    assert out is fake_result
    lines = [json.loads(x) for x in captured]
    # The token line uses the legacy shape (no "metric" key; keyed by $.tokens); the
    # generalized emitters carry a "metric" tag. Assert both shapes are present.
    tok = next(ln for ln in lines if "tokens" in ln and "metric" not in ln)
    assert tok["tokens"] == 140          # 100 + 40
    metrics = {ln["metric"] for ln in lines if "metric" in ln}
    assert {"latency_ms", "tool_calls"} <= metrics
    tc = next(ln for ln in lines if ln.get("metric") == "tool_calls")
    assert tc["tool_calls"] == 2.0


def test_invoke_and_meter_meters_then_reraises_on_throttle(monkeypatch):
    captured = []

    class _Throttle(Exception):
        pass
    _Throttle.__name__ = "ThrottlingException"

    def _boom(*a, **k):
        raise _Throttle("slow down")
    monkeypatch.setattr(sh, "invoke", _boom)
    with pytest.raises(_Throttle):
        sh.invoke_and_meter("arn", "sess-" + "y" * 30, "hi", scenario="cve", log=captured.append)
    lines = [json.loads(x) for x in captured]
    err = next(ln for ln in lines if ln.get("metric") == "errors")
    assert err["kind"] == "throttle"       # classified as a throttle, not internal


def test_invoke_and_meter_emits_error_metric_on_structured_error(monkeypatch):
    captured = []
    monkeypatch.setattr(sh, "invoke", lambda *a, **k: {
        "text": "", "tools_used": [], "usage": None, "error": "upstream_error"})
    sh.invoke_and_meter("arn", "sess-" + "z" * 30, "hi", scenario="cve", log=captured.append)
    lines = [json.loads(x) for x in captured]
    assert any(ln.get("metric") == "errors" and ln["errors"] == 1.0 for ln in lines)
