"""
Offline tests for sentinel_harness.tracing — OTEL/GenAI span emission.

ZERO AWS, ZERO network, no clock. The default path is a pure structured-line
emitter with deterministic ids, so every property is exactly checkable:
- parent/child nesting (meta→ops→judge→promote),
- deterministic trace/span ids (byte-reproducible),
- OK vs ERROR status (exception re-raises, never swallowed),
- GenAI semantic-convention attributes,
- the SENTINEL_OTEL gate stays OFF in tests (no opentelemetry import needed).
"""
from __future__ import annotations

import json

import pytest

from sentinel_harness import tracing as T


# --------------------------------------------------------------------------- #
# nesting + emission                                                          #
# --------------------------------------------------------------------------- #
def test_nested_spans_have_correct_parents():
    tr = T.Tracer("run", log=lambda x: None)
    with tr.span("root"):
        with tr.span("child"):
            with tr.span("grandchild"):
                pass
    root, child, grand = tr.spans
    assert root.parent_span_id is None
    assert child.parent_span_id == root.span_id
    assert grand.parent_span_id == child.span_id


def test_sibling_spans_share_parent():
    tr = T.Tracer("run", log=lambda x: None)
    with tr.span("parent"):
        with tr.span("a"):
            pass
        with tr.span("b"):
            pass
    parent, a, b = tr.spans
    assert a.parent_span_id == parent.span_id
    assert b.parent_span_id == parent.span_id


def test_all_spans_share_one_trace_id():
    tr = T.Tracer("run", log=lambda x: None)
    with tr.span("a"):
        with tr.span("b"):
            pass
    assert {s.trace_id for s in tr.spans} == {tr.trace_id}


def test_emits_one_line_per_span():
    lines = []
    tr = T.Tracer("run", log=lines.append)
    with tr.span("a"):
        with tr.span("b"):
            pass
    assert len(lines) == 2
    for ln in lines:
        obj = json.loads(ln)
        assert {"span", "trace_id", "span_id", "parent_span_id", "status", "attributes"} <= set(obj)


# --------------------------------------------------------------------------- #
# determinism                                                                 #
# --------------------------------------------------------------------------- #
def test_trace_id_is_deterministic_per_name():
    a = T.Tracer("same", log=lambda x: None)
    b = T.Tracer("same", log=lambda x: None)
    assert a.trace_id == b.trace_id


def test_different_names_differ():
    a = T.Tracer("one", log=lambda x: None)
    b = T.Tracer("two", log=lambda x: None)
    assert a.trace_id != b.trace_id


def test_span_ids_unique_and_deterministic():
    def ids():
        tr = T.Tracer("run", log=lambda x: None)
        with tr.span("a"):
            with tr.span("b"):
                pass
        return [s.span_id for s in tr.spans]
    first = ids()
    assert len(set(first)) == 2          # unique within a trace
    assert first == ids()                # deterministic across runs


def test_trace_to_dict_json_serializable():
    tr = T.Tracer("run", log=lambda x: None)
    with tr.span("a", **T.genai_attributes(operation="chat", model="opus")):
        pass
    d = tr.trace_to_dict()
    json.dumps(d)
    assert d["trace_id"] == tr.trace_id
    assert len(d["spans"]) == 1


# --------------------------------------------------------------------------- #
# status: OK vs ERROR                                                         #
# --------------------------------------------------------------------------- #
def test_ok_status_on_clean_exit():
    tr = T.Tracer("run", log=lambda x: None)
    with tr.span("a"):
        pass
    assert tr.spans[0].status == T.STATUS_OK


def test_error_status_and_reraise_on_exception():
    tr = T.Tracer("run", log=lambda x: None)
    with pytest.raises(ValueError):
        with tr.span("boom"):
            raise ValueError("kaboom")
    span = tr.spans[0]
    assert span.status == T.STATUS_ERROR
    assert any(e["event"] == "exception" for e in span.events)
    assert "kaboom" in span.events[0]["message"]


def test_body_can_set_status():
    tr = T.Tracer("run", log=lambda x: None)
    with tr.span("a") as s:
        s.status = T.STATUS_OK
    assert tr.spans[0].status == T.STATUS_OK


def test_error_in_child_bubbles_and_parent_recorded():
    tr = T.Tracer("run", log=lambda x: None)
    with pytest.raises(RuntimeError):
        with tr.span("parent"):
            with tr.span("child"):
                raise RuntimeError("x")
    # both spans recorded; child ERROR, parent also ERROR (the exception passed through it)
    names = {s.name: s.status for s in tr.spans}
    assert names["child"] == T.STATUS_ERROR
    assert names["parent"] == T.STATUS_ERROR


# --------------------------------------------------------------------------- #
# GenAI attributes                                                            #
# --------------------------------------------------------------------------- #
def test_genai_attributes_semantic_keys():
    a = T.genai_attributes(operation="chat", model="opus", input_tokens=100,
                           output_tokens=50, scenario="s", harness_id="h1", eval_score=0.9)
    assert a["gen_ai.system"] == T.GEN_AI_SYSTEM
    assert a["gen_ai.operation.name"] == "chat"
    assert a["gen_ai.request.model"] == "opus"
    assert a["gen_ai.usage.input_tokens"] == 100
    assert a["gen_ai.usage.output_tokens"] == 50
    assert a["sentinel.scenario"] == "s"
    assert a["sentinel.harness_id"] == "h1"
    assert a["sentinel.eval_score"] == 0.9


def test_genai_attributes_drops_none():
    a = T.genai_attributes(operation="chat")  # everything else None
    assert "gen_ai.request.model" not in a
    assert "gen_ai.usage.input_tokens" not in a
    assert "sentinel.scenario" not in a
    assert a["gen_ai.operation.name"] == "chat"


# --------------------------------------------------------------------------- #
# the SENTINEL_OTEL gate                                                       #
# --------------------------------------------------------------------------- #
def test_otel_gate_off_by_default(monkeypatch):
    monkeypatch.delenv(T.LIVE_ENV_FLAG, raising=False)
    assert T._live_enabled() is False


def test_otel_gate_reads_truthy(monkeypatch):
    for val in ("1", "true", "YES", "on"):
        monkeypatch.setenv(T.LIVE_ENV_FLAG, val)
        assert T._live_enabled() is True
    monkeypatch.setenv(T.LIVE_ENV_FLAG, "0")
    assert T._live_enabled() is False


def test_offline_path_needs_no_opentelemetry(monkeypatch):
    """The default (gate off) path must never import opentelemetry — emitting a
    span with the gate off works even if the SDK is absent."""
    monkeypatch.delenv(T.LIVE_ENV_FLAG, raising=False)
    tr = T.Tracer("run", log=lambda x: None)
    with tr.span("a"):  # must not touch opentelemetry
        pass
    assert tr.spans[0].status == T.STATUS_OK


# --------------------------------------------------------------------------- #
# regression: audited tracing determinism + JSON-ability findings             #
# --------------------------------------------------------------------------- #
def test_set_attribute_is_deterministic_and_sorted():
    tr = T.Tracer("x", log=lambda line: None)
    with tr.span("a", tags={"z", "a", "m"}):
        pass
    assert tr.spans[0].attributes["tags"] == ["a", "m", "z"]  # sorted, deterministic


def test_trace_to_dict_json_able_with_nonprimitive_attr():
    import datetime
    import json
    tr = T.Tracer("x", log=lambda line: None)
    with tr.span("a", ts=datetime.datetime(2020, 1, 1), obj=object()):
        pass
    d = tr.trace_to_dict()
    json.dumps(d)  # must NOT raise (non-primitive attrs str-coerced)
    assert isinstance(d["spans"][0]["attributes"]["ts"], str)
