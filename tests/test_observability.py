"""
Offline tests for ``sentinel_harness/observability.py`` and the metric sink.
=========================================================================
ZERO AWS, ZERO network. These lock two round-20 findings:

* INV-METRIC-1 — a metered metric is emitted as a BARE top-level JSON line, because
  CloudWatch's ``FilterPattern.exists("$.tokens")`` matches only a message that IS a
  JSON object. The old text-logger default prepended ``INFO sentinel_harness.telemetry:``
  and no metered metric ever matched the filter.
* INV-COERCE — ``emit_eval_score`` coerces the pass flag with the canonical coercer, so
  a judge reporting ``passed="false"`` is published as ``passed: false``, not ``true``.
"""
from __future__ import annotations

import io
import json

from sentinel_harness import observability as obs
from sentinel_harness.logutil import get_metric_sink


def test_metric_sink_emits_bare_json():
    """Every metric line must be a top-level JSON object (first char '{')."""
    buf = io.StringIO()
    sink = get_metric_sink(stream=buf)
    obs.emit_token_metric("scenario_x", 1000, 234, log=sink)
    obs.emit_invoke_latency("scenario_x", 42.0, log=sink)
    obs.emit_error("scenario_x", "throttle", log=sink)

    lines = [ln for ln in buf.getvalue().splitlines() if ln.strip()]
    assert len(lines) == 3
    for line in lines:
        assert line.startswith("{"), (
            f"metric line is not a top-level JSON object, so the CloudWatch $.<field> "
            f"filter will not match it: {line!r}"
        )
        json.loads(line)  # must parse

    # and each carries the field its MetricFilter keys on
    fields = [next(iter(k for k in ("tokens", "latency_ms", "errors")
                        if k in json.loads(ln)), None) for ln in lines]
    assert fields == ["tokens", "latency_ms", "errors"]


def test_emit_eval_score_does_not_string_truthy_the_pass_flag():
    """INV-COERCE: a judge that reports a stringified false is published as false."""
    for falsey in ("false", "False", "no", "0"):
        rec = obs.emit_eval_score("s", "safety", 0.2, falsey, log=lambda *_a, **_k: None)
        assert rec["passed"] is False, (
            f"a judge reporting passed={falsey!r} was published as passed=True"
        )
    for truthy in ("true", "True", True, "yes"):
        rec = obs.emit_eval_score("s", "safety", 0.9, truthy, log=lambda *_a, **_k: None)
        assert rec["passed"] is True
