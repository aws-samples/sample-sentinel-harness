"""
sentinel-harness · connector base contract
===========================================
A **connector** is a pure translator between sentinel-harness's neutral query /
event shape and one backend's native shape. It is the thing that turns a generic
``*_LIVE`` HTTP seam into a real, plug-and-play SIEM/ticketing integration.

.. warning::
   **Connectors do NO network I/O.** A connector only (a) builds the request a
   tool should send to a backend, and (b) parses a backend's JSON reply into
   sentinel's neutral events. The actual HTTP round-trip stays in the tool's
   ``*_LIVE`` path (stdlib urllib, SSRF-guarded). This separation is what makes a
   connector trivially DETERMINISTIC and CONTRACT-TESTABLE: given a native
   response fixture, ``parse_response`` must yield the exact neutral shape — no
   server, no clock, no creds needed.

Why this exists
---------------
The ``*_LIVE`` seams (``SIEM_QUERY_LIVE`` etc.) shipped as a single generic
``POST {key: value}`` and expected a reply already near sentinel's shape — which
no real Splunk / Elastic / OpenSearch / ServiceNow returns. A connector closes
that gap: it knows the backend's query DSL and response envelope, so an adopter
sets ``SIEM_QUERY_CONNECTOR=splunk`` and it just works, rather than writing a
translation shim.

The neutral SIEM event shape (what every SIEM connector must emit)
------------------------------------------------------------------
Exactly the 10 fields ``tools/siem_query`` normalizes to::

    {alert_id, ts, severity, rule_name, host, src_ip, dst_ip,
     technique, summary, false_positive}

Nothing here is customer- or company-specific: connectors carry only the vendor's
public API shape, never an endpoint, token, or tenant.
"""
from __future__ import annotations

from typing import Any, Dict, List, Protocol, runtime_checkable

# The canonical neutral SIEM event field set (kept in lockstep with
# tools/siem_query/handler.py::_normalize_event). A connector's parse_response
# must return dicts carrying exactly these keys.
NEUTRAL_EVENT_FIELDS = (
    "alert_id", "ts", "severity", "rule_name", "host",
    "src_ip", "dst_ip", "technique", "summary", "false_positive",
)

# String tokens a backend uses for a truthy boolean. Real SIEMs commonly
# JSON-serialize booleans as strings, and `bool("false")` is True (any non-empty
# string is truthy) — so a naive bool() would flip a genuine alert to a false
# positive and it might be dropped. Only these tokens (case-insensitive) are True.
_TRUE_TOKENS = frozenset({"true", "1", "yes", "y", "t"})


def _coerce_bool(value: Any) -> bool:
    """Coerce a backend truthiness value to bool WITHOUT the string-truthiness trap.

    ``True``/``1`` → True; a string is True only if it is a recognized true token
    ("true"/"1"/"yes"…), so the common string ``"false"``/``"0"`` correctly maps to
    False (audited: bool("false") is True). Anything else falls back to Python
    truthiness for non-string values only."""
    if isinstance(value, str):
        return value.strip().lower() in _TRUE_TOKENS
    return bool(value)


def neutral_event(record: Dict[str, Any]) -> Dict[str, Any]:
    """Coerce a partially-mapped record into the full neutral 10-field event.

    Defaults every field so a backend that omits optionals still yields a
    byte-consistent shape. ``src_ip``/``dst_ip`` default to ``None`` (they are
    legitimately absent on host-only alerts); the rest default to ``""``/``False``.
    A connector maps the backend's fields, then passes the dict through this to
    guarantee the contract."""
    return {
        "alert_id": record.get("alert_id", ""),
        "ts": record.get("ts", ""),
        "severity": record.get("severity", ""),
        "rule_name": record.get("rule_name", ""),
        "host": record.get("host", ""),
        "src_ip": record.get("src_ip"),
        "dst_ip": record.get("dst_ip"),
        "technique": record.get("technique", ""),
        "summary": record.get("summary", record.get("raw_summary", "")),
        "false_positive": _coerce_bool(record.get("false_positive", False)),
    }


class ConnectorError(ValueError):
    """A connector could not translate a request or a response (malformed native
    shape). Distinct from a network fault so the tool labels the two differently."""


# --------------------------------------------------------------------------- #
# Result-set semantics — the thing that must be EQUAL across connectors        #
# --------------------------------------------------------------------------- #
# A connector is only a faithful translator if the SAME neutral query returns the
# SAME result set from every backend. Round 13 found that it did not: only QRadar
# applied a time window (LAST 24 HOURS), while Elastic/OpenSearch/Sentinel/Sumo
# capped at 1000 rows and Splunk/QRadar/Chronicle/Datadog had no cap at all. A
# detection validated offline therefore behaved differently per backend — and the
# conformance suite passed all of them, because it only asserted response SHAPE
# (dict, right field set) and never cross-connector EQUIVALENCE.
#
# These constants make the result-set contract explicit and shared, so every
# connector emits the same bound and `conformance` can assert it. The window is
# deliberately UNBOUNDED: sentinel's neutral query carries no time filter, so a
# connector must not invent one (QRadar's silent 24h window dropped older true
# hits with nothing in the result to say so).
DEFAULT_RESULT_LIMIT = 1000
RESULT_WINDOW_UNBOUNDED = None


class ResultSemantics:
    """The declared result-set semantics of a connector's ``build_request``.

    ``limit`` is the maximum number of rows the emitted query may return;
    ``window_hours`` is the time bound it applies (``None`` == unbounded, the
    contract, since the neutral query carries no time filter). Declaring these
    lets :mod:`conformance` assert that every connector agrees, instead of each
    quietly imposing its own."""

    __slots__ = ("limit", "window_hours")

    def __init__(self, limit: int = DEFAULT_RESULT_LIMIT,
                 window_hours: Any = RESULT_WINDOW_UNBOUNDED) -> None:
        self.limit = limit
        self.window_hours = window_hours

    def as_tuple(self) -> tuple:
        return (self.limit, self.window_hours)

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, ResultSemantics) and self.as_tuple() == other.as_tuple()

    def __repr__(self) -> str:  # pragma: no cover - diagnostics only
        return f"ResultSemantics(limit={self.limit}, window_hours={self.window_hours})"


@runtime_checkable
class SiemConnector(Protocol):
    """The contract a SIEM/search connector implements. Pure translation only.

    - :meth:`build_request` turns sentinel's validated ``(selector, value)`` query
      into the native request body + an optional path suffix the tool appends to
      the configured base URL.
    - :meth:`parse_response` turns the backend's parsed JSON reply into a list of
      neutral events (via :func:`neutral_event`).
    Neither method touches the network, a clock, or credentials."""

    name: str

    def build_request(self, selector: str, value: str) -> Dict[str, Any]:
        """Return ``{"body": <json-able>, "path": <str suffix or "">}`` for the query."""
        ...

    def parse_response(self, payload: Any) -> List[Dict[str, Any]]:
        """Return neutral events parsed from the backend's JSON reply."""
        ...
