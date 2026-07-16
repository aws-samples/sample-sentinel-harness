"""
sentinel-harness · OTEL / GenAI span emission
==============================================
Closes the ``docs/OBSERVABILITY.md`` "future item": the library did not emit
OpenTelemetry spans from code, so the managed online-eval path (which scores the
``aws/spans`` Transaction-Search source) had no *code-emitted* traffic to score —
only spans the AgentCore runtime itself produced. This module lets an invoke /
harness-op / evaluation / autonomous-loop step emit a **GenAI span**, so the
whole meta→ops→judge→promote chain shows up as one distributed trace.

.. warning::
   **Offline-first and DETERMINISTIC by default — zero AWS, zero network, no
   clock.** By default :func:`span` writes a structured JSON span line (the same
   "emit a line the pipeline turns into signal" contract as
   ``observability.py``) via an injectable ``log`` sink; it reads no clock and
   opens no socket, so tests are byte-reproducible. Only when ``SENTINEL_OTEL``
   is truthy does it ALSO drive a real OpenTelemetry span — and the heavy
   ``opentelemetry`` import happens lazily inside that gated path, so the
   dependency is never required for the offline/CI path.

The GenAI span shape
--------------------
Attributes follow the OpenTelemetry **GenAI semantic conventions** (the ones
CloudWatch Transaction Search / Bedrock AgentCore surface): ``gen_ai.system``,
``gen_ai.operation.name``, ``gen_ai.request.model``, ``gen_ai.usage.input_tokens``
/ ``output_tokens``, plus sentinel-specific ``sentinel.*`` attributes (scenario,
harness id, eval score, hitl gate). A parent/child relationship is expressed with
``trace_id`` + ``span_id`` + ``parent_span_id`` so meta→ops→judge→promote nests.

Why a thin homegrown span (not always the OTEL SDK)
---------------------------------------------------
The offline contract must run everywhere with no extra dependency and be
deterministic for tests. So the *structured line* is always produced by pure
local code; the OTEL SDK is engaged only behind the flag, for a real deployment
that wants spans in X-Ray / Transaction Search. Same design as the token-metric
emitter: a zero-AWS default line + a gated live path.

Nothing here is customer- or company-specific.
"""
from __future__ import annotations

import json
import os
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional

# Gate for the opt-in real-OTEL path. Default off => the pure structured-line path.
LIVE_ENV_FLAG = "SENTINEL_OTEL"
_TRUTHY = {"1", "true", "yes", "on"}

# GenAI semantic-convention system marker for AgentCore harness invokes.
GEN_AI_SYSTEM = "aws.bedrock.agentcore"

# The status vocabulary a span can end in (mirrors OTEL StatusCode names).
STATUS_OK = "OK"
STATUS_ERROR = "ERROR"
STATUS_UNSET = "UNSET"


def _live_enabled() -> bool:
    """True iff the opt-in real-OpenTelemetry path is explicitly turned on."""
    return os.environ.get(LIVE_ENV_FLAG, "").strip().lower() in _TRUTHY


# --------------------------------------------------------------------------- #
# Deterministic id generation (no clock / no randomness)                      #
# --------------------------------------------------------------------------- #
# OTEL trace ids are 32 hex chars, span ids 16 hex. Offline we derive them
# deterministically from a caller-provided seed (trace name + a monotonically
# increasing counter within a Tracer), so a test gets identical ids every run —
# real randomness would break reproducibility (same rule as the workflow engine's
# no-Math.random constraint). A live deployment overrides these with the OTEL SDK.
def _hex_id(seed: str, width: int) -> str:
    """A deterministic width-hex id derived from ``seed`` (no clock/rand).

    Uses a stable hash of the seed, zero-padded/truncated to ``width`` hex chars.
    Collision-resistant enough for grouping spans of one offline run; real trace
    ids come from the OTEL SDK on the live path."""
    import hashlib
    h = hashlib.sha256(seed.encode("utf-8")).hexdigest()
    return h[:width]


def _json_safe(value: Any) -> Any:
    """Coerce one attribute value into a JSON-serializable, DETERMINISTIC form.

    Fixes two audited issues at once:
      - a ``set``/``frozenset`` is emitted with unordered iteration → non-repeatable
        output (PYTHONHASHSEED-dependent); we sort it to a list;
      - a non-JSON-primitive (datetime, custom object) made ``trace_to_dict``
        raise on ``json.dumps`` even though ``_emit`` tolerated it via default=str;
        we str-coerce it here so BOTH paths are JSON-able and identical.
    Primitives (str/int/float/bool/None) pass through; lists/tuples and dict values
    are coerced element-wise (recursively)."""
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, (set, frozenset)):
        return sorted(_json_safe(v) for v in value)
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in sorted(value.items(), key=lambda kv: str(kv[0]))}
    return str(value)  # datetime / arbitrary object → stable string


def _json_safe_attrs(attributes: Dict[str, Any]) -> Dict[str, Any]:
    """Coerce a whole attribute dict to JSON-safe, deterministic values."""
    return {k: _json_safe(v) for k, v in attributes.items()}


@dataclass
class SpanRecord:
    """One emitted span (the auditable record + the OTEL/GenAI line source)."""

    name: str
    trace_id: str
    span_id: str
    parent_span_id: Optional[str]
    attributes: Dict[str, Any] = field(default_factory=dict)
    status: str = STATUS_UNSET
    events: List[Dict[str, Any]] = field(default_factory=list)

    def to_line(self) -> Dict[str, Any]:
        """The structured dict a log/Transaction-Search pipeline ingests."""
        return {
            "span": self.name,
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "parent_span_id": self.parent_span_id,
            "status": self.status,
            "attributes": self.attributes,
            "events": self.events,
        }


class Tracer:
    """A deterministic span factory for one logical trace (e.g. one scenario run).

    All spans created from one Tracer share a ``trace_id`` (derived from the
    Tracer's ``name``); child spans nest via ``parent_span_id``. A per-Tracer
    counter makes each span id deterministic and unique within the trace — no
    clock, no randomness — so the whole trace is byte-reproducible in tests.

    ``log`` is the sink for the structured span line (default ``print`` → stdout;
    pass a logger bound to the scenario LogGroup to feed Transaction Search). If
    ``SENTINEL_OTEL`` is set, each span ALSO drives a real OTEL span (lazy import).
    """

    def __init__(self, name: str, *, log=print):
        self.name = name
        self.trace_id = _hex_id(f"trace:{name}", 32)
        self._log = log
        self._counter = 0
        self._stack: List[str] = []   # span_id stack for parent nesting
        self.spans: List[SpanRecord] = []

    def _next_span_id(self, span_name: str) -> str:
        self._counter += 1
        return _hex_id(f"{self.trace_id}:{span_name}:{self._counter}", 16)

    @contextmanager
    def span(self, name: str, **attributes: Any) -> Iterator[SpanRecord]:
        """Open a GenAI span named ``name`` with ``attributes``. Context manager.

        On normal exit the span status is ``OK`` (unless the body set it); on an
        exception the status is ``ERROR`` (an ``exception`` event is attached) and
        the exception re-raises — a span never swallows the error it traced. The
        structured line is emitted on exit via ``log``; the SpanRecord is also
        retained on the Tracer for assertions/evidence."""
        parent = self._stack[-1] if self._stack else None
        span_id = self._next_span_id(name)
        record = SpanRecord(
            name=name, trace_id=self.trace_id, span_id=span_id,
            parent_span_id=parent, attributes=_json_safe_attrs(attributes),
        )
        self._stack.append(span_id)
        self.spans.append(record)

        live_span = None
        if _live_enabled():
            live_span = _start_live_span(name, record)

        _error: BaseException | None = None
        try:
            yield record
        except BaseException as exc:  # noqa: BLE001 — catch ALL (incl KeyboardInterrupt/SystemExit)
            _error = exc
            record.status = STATUS_ERROR
            record.events.append({"event": "exception", "type": type(exc).__name__,
                                  "message": str(exc)[:200]})
            raise
        finally:
            # ALWAYS: emit the span + pop the stack, even on BaseException (Ctrl-C,
            # SystemExit, asyncio.CancelledError). This is the fix for the audited
            # finding: `except Exception` left BaseExceptions unrecorded + the stack
            # mis-parented subsequent siblings.
            if record.status == STATUS_UNSET:
                record.status = STATUS_OK
            if live_span is not None:
                _end_live_span(live_span, record, error=_error)
            self._emit(record)
            self._stack.pop()

    def _emit(self, record: SpanRecord) -> None:
        """Write the structured span line via the sink. Zero AWS."""
        self._log(json.dumps(record.to_line(), ensure_ascii=False, default=str))

    def trace_to_dict(self) -> Dict[str, Any]:
        """The whole trace as a JSON-able dict (evidence): id + all span lines."""
        return {"trace_id": self.trace_id, "spans": [s.to_line() for s in self.spans]}


# --------------------------------------------------------------------------- #
# GenAI attribute builders (semantic-convention keys)                         #
# --------------------------------------------------------------------------- #
def genai_attributes(
    *,
    operation: str,
    model: Optional[str] = None,
    input_tokens: Optional[int] = None,
    output_tokens: Optional[int] = None,
    scenario: Optional[str] = None,
    harness_id: Optional[str] = None,
    **extra: Any,
) -> Dict[str, Any]:
    """Build GenAI semantic-convention span attributes for an AgentCore invoke.

    Emits the ``gen_ai.*`` keys CloudWatch Transaction Search / online-eval key on
    (system, operation, model, usage tokens) plus ``sentinel.*`` context. ``None``
    values are dropped so a span carries only what it actually knows."""
    attrs: Dict[str, Any] = {
        "gen_ai.system": GEN_AI_SYSTEM,
        "gen_ai.operation.name": operation,
    }
    if model is not None:
        attrs["gen_ai.request.model"] = model
    if input_tokens is not None:
        attrs["gen_ai.usage.input_tokens"] = int(input_tokens)
    if output_tokens is not None:
        attrs["gen_ai.usage.output_tokens"] = int(output_tokens)
    if scenario is not None:
        attrs["sentinel.scenario"] = scenario
    if harness_id is not None:
        attrs["sentinel.harness_id"] = harness_id
    for k, v in extra.items():
        if v is not None:
            attrs[f"sentinel.{k}"] = v
    return attrs


# --------------------------------------------------------------------------- #
# Gated real-OTEL path (lazy import; only reached when SENTINEL_OTEL is set)   #
# --------------------------------------------------------------------------- #
def _start_live_span(name: str, record: SpanRecord):
    """Start a real OpenTelemetry span. GATED — only called when SENTINEL_OTEL is
    truthy. The heavy import lives here so the offline path never needs the dep.
    Returns the live span (or None if the SDK isn't installed — the structured
    line still emits, so tracing degrades gracefully rather than crashing)."""
    try:
        from opentelemetry import trace as _otel_trace  # noqa: PLC0415 — lazy, gated
    except ImportError:
        return None
    tracer = _otel_trace.get_tracer("sentinel-harness")
    otel_span = tracer.start_span(name)
    for k, v in record.attributes.items():
        try:
            otel_span.set_attribute(k, v)
        except Exception:  # noqa: BLE001 — a non-primitive attr must not crash tracing
            otel_span.set_attribute(k, str(v))
    return otel_span


def _end_live_span(otel_span, record: SpanRecord, *, error) -> None:
    """End a real OTEL span, mapping the record's status. GATED."""
    try:
        from opentelemetry.trace import Status, StatusCode  # noqa: PLC0415
        if error is not None:
            otel_span.set_status(Status(StatusCode.ERROR, str(error)[:200]))
            otel_span.record_exception(error)
        else:
            otel_span.set_status(Status(StatusCode.OK))
    except Exception:  # noqa: BLE001 — status mapping must never mask the traced op
        pass
    finally:
        otel_span.end()
