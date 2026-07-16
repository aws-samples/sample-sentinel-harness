"""
sentinel-harness · connector conformance kit
=============================================
A reusable, importable contract checker that certifies ANY connector — the ones
shipped here AND a third party's own — against the sentinel connector contract.
This is what makes the connector framework genuinely extensible: write a
connector, run it through :func:`check_siem_connector` /
:func:`check_ticketing_connector`, and a green result means it will slot into the
tool's ``*_LIVE`` path correctly.

.. warning::
   **Pure, offline, deterministic — no network, no AWS.** The kit exercises a
   connector only through its two pure methods with synthetic native fixtures. It
   never opens a socket. A connector that passes here is contract-correct; whether
   its *live* endpoint works is a deployment concern the kit deliberately does not
   touch.

What "conformant" means
-----------------------
A SIEM connector is conformant iff:
  1. it exposes ``name`` (non-empty str), ``build_request(selector, value)``,
     ``parse_response(payload)``;
  2. ``build_request`` returns ``{"body": <json-able>, "path": <str>}`` for the
     wildcard query and for a field selector, and the body is JSON-serializable;
  3. ``parse_response`` of the connector's OWN sample native reply yields a list of
     dicts, each carrying EXACTLY the neutral 10-field event shape;
  4. ``parse_response`` of a malformed/foreign envelope raises ``ConnectorError``
     (never returns a bare list or swallows the error) — so a broken backend reply
     is never mistaken for "zero events".

A ticketing connector is conformant iff:
  1. it exposes ``name``, ``build_request(request)``, ``parse_response(payload)``;
  2. ``build_request`` of a neutral ticket returns ``{"body", "path"}`` (json-able);
  3. it rejects a title-less request with ``ConnectorError``;
  4. ``parse_response`` of its OWN sample reply yields ``{ticket_id, status, url}``
     with a non-empty ``ticket_id``; a malformed reply raises ``ConnectorError``.

Because different backends have different native envelopes, the kit asks the
connector to *provide its own* sample native reply via an optional
``sample_response()`` method; if absent, the shipped connectors are covered by the
built-in fixtures below (keyed by ``name``). A third-party connector should
implement ``sample_response()`` so the kit can certify it with no edits here.

Nothing here is customer- or company-specific.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List

from .base import NEUTRAL_EVENT_FIELDS, ConnectorError

# Built-in sample native replies for the SHIPPED SIEM connectors (keyed by name),
# used when a connector does not provide its own sample_response(). Each is a
# minimal but valid native envelope for that backend.
_SIEM_SAMPLES: Dict[str, Any] = {
    "splunk": {"results": [
        {"id": "s1", "_time": "2026-06-28T00:00:00Z", "level": "high",
         "signature": "R", "host": "web-01", "src": "203.0.113.66", "mitre_technique": "T1190"}]},
    "elastic": {"hits": {"hits": [
        {"_source": {"alert_id": "e1", "@timestamp": "2026-06-28T00:00:00Z",
                     "severity": "high", "rule": "R", "host": "web-01",
                     "src_ip": "203.0.113.66", "technique": "T1190"}}]}},
    "opensearch": {"hits": {"hits": [
        {"_source": {"alert_id": "o1", "severity": "high", "rule": "R",
                     "host": "web-01", "src_ip": "203.0.113.66", "technique": "T1190"}}]}},
    "qradar": {"events": [
        {"id": "q1", "severity": "high", "rule": "R", "host": "web-01",
         "src": "203.0.113.66", "technique": "T1190"}]},
    "microsoft_sentinel": {"tables": [{
        "columns": [{"name": "alert_id"}, {"name": "severity"}, {"name": "host"},
                    {"name": "src_ip"}, {"name": "technique"}],
        "rows": [["m1", "high", "web-01", "203.0.113.66", "T1190"]]}]},
    "chronicle": {"events": [
        {"udm": {"alert_id": "c1", "severity": "high", "rule": "R", "host": "web-01",
                 "src_ip": "203.0.113.66", "technique": "T1190"}}]},
    "sumologic": {"messages": [
        {"map": {"alert_id": "su1", "severity": "high", "rule": "R", "host": "web-01",
                 "src_ip": "203.0.113.66", "technique": "T1190"}}]},
    "datadog": {"data": [
        {"attributes": {"alert_id": "dd1", "severity": "high", "rule": "R",
                        "host": "web-01", "src_ip": "203.0.113.66", "technique": "T1190"}}]},
}

_TICKETING_SAMPLES: Dict[str, Any] = {
    "servicenow": {"result": {"number": "INC001", "state": "new"}},
    "jira": {"key": "SEC-1", "self": "http://x/SEC-1"},
    "pagerduty": {"incident": {"id": "P1", "status": "triggered", "html_url": "http://x"}},
}

# A native envelope no connector should accept — the malformed-input probe.
_FOREIGN_ENVELOPE = {"totally": "unexpected", "shape": [1, 2, 3]}


@dataclass
class ConformanceResult:
    """The outcome of certifying one connector. ``ok`` iff no checks failed."""

    name: str
    kind: str                              # "siem" | "ticketing"
    ok: bool
    checks: List[str] = field(default_factory=list)   # passed check names
    failures: List[str] = field(default_factory=list)  # human-readable failures


# Sentinel meaning "no sample native reply is available to certify parsing with"
# (distinct from a connector legitimately returning None). Used so the parse check
# FAILS loudly instead of silently calling parse_response(None) against a sample
# that never existed (audited: a third-party connector with no sample_response and
# no built-in fixture would otherwise be certified on a vacuous check).
_NO_SAMPLE = object()


def _sample_for(connector: Any, table: Dict[str, Any]) -> Any:
    """Return a connector's own ``sample_response()`` if provided, else the built-in
    fixture for its name, else :data:`_NO_SAMPLE`.

    Callers MUST treat ``_NO_SAMPLE`` as a certification failure (cannot validate
    parsing without a sample) rather than passing it to ``parse_response``."""
    if hasattr(connector, "sample_response"):
        return connector.sample_response()
    name = getattr(connector, "name", "")
    return table[name] if name in table else _NO_SAMPLE


def _record(res: ConformanceResult, name: str, ok: bool, detail: str = "") -> None:
    if ok:
        res.checks.append(name)
    else:
        res.ok = False
        res.failures.append(f"{name}: {detail}")


def check_siem_connector(connector: Any) -> ConformanceResult:
    """Certify a SIEM/search connector against the contract. PURE, offline.

    Returns a :class:`ConformanceResult`; ``.ok`` is True iff every check passed.
    Never raises — a thrown exception inside a check is recorded as a failure so
    one broken method can't abort the whole certification."""
    res = ConformanceResult(name=getattr(connector, "name", "?"), kind="siem", ok=True)

    _record(res, "has_name",
            isinstance(getattr(connector, "name", None), str) and bool(connector.name),
            "name must be a non-empty string")
    _record(res, "has_methods",
            hasattr(connector, "build_request") and hasattr(connector, "parse_response"),
            "must expose build_request + parse_response")
    if res.failures:
        return res  # can't proceed without the surface

    # build_request: wildcard + field selector, json-able body, str path
    try:
        for sel, val in (("*", "*"), ("host", "web-01")):
            req = connector.build_request(sel, val)
            assert isinstance(req, dict) and "body" in req and "path" in req, "shape"
            assert isinstance(req["path"], str), "path must be str"
            json.dumps(req["body"])  # json-able
        _record(res, "build_request_shape", True)
    except Exception as exc:  # noqa: BLE001 — record, don't abort
        _record(res, "build_request_shape", False, str(exc))

    # parse_response: own sample -> list of neutral events. The _sample_for call is
    # INSIDE the try so a throwing/absent/non-callable sample_response is recorded
    # as a failure, never propagated (audited: it must "never raise").
    try:
        sample = _sample_for(connector, _SIEM_SAMPLES)
        if sample is _NO_SAMPLE:
            raise AssertionError(
                "no sample_response() and no built-in fixture; cannot certify parsing")
        events = connector.parse_response(sample)
        assert isinstance(events, list) and events, "must return a non-empty list for the sample"
        for ev in events:
            assert isinstance(ev, dict), "each event must be a dict"
            assert set(ev) == set(NEUTRAL_EVENT_FIELDS), (
                f"event fields {sorted(ev)} != neutral {sorted(NEUTRAL_EVENT_FIELDS)}"
            )
        _record(res, "parse_sample_to_neutral", True)
    except Exception as exc:  # noqa: BLE001
        _record(res, "parse_sample_to_neutral", False, str(exc))

    # malformed envelopes -> ConnectorError for EACH of several shapes (not just one
    # dict). A connector that rejects the fixed dict but returns [] for junk
    # list/str/None still swallows a broken reply — audited. Require ConnectorError
    # for every probe.
    _record_foreign_envelope_check(res, connector)
    return res


def _record_foreign_envelope_check(res: ConformanceResult, connector: Any) -> None:
    """Assert parse_response raises ConnectorError for EVERY malformed probe shape.

    Shared by the SIEM + ticketing checks. A connector must never mistake a junk
    backend reply (dict / bare list / string / None / int) for 'zero events'. All
    probes must raise ConnectorError; the first that is accepted (or raises the
    wrong type) fails the check."""
    for probe in (_FOREIGN_ENVELOPE, [1, 2, 3], "not json", None, 42):
        try:
            connector.parse_response(probe)
        except ConnectorError:
            continue  # correct: this probe was rejected
        except Exception as exc:  # noqa: BLE001 — wrong exception type is still a miss
            _record(res, "rejects_foreign_envelope", False,
                    f"probe {probe!r}: raised {type(exc).__name__}, expected ConnectorError")
            return
        else:
            _record(res, "rejects_foreign_envelope", False,
                    f"probe {probe!r}: accepted (should raise ConnectorError)")
            return
    _record(res, "rejects_foreign_envelope", True)


def check_ticketing_connector(connector: Any) -> ConformanceResult:
    """Certify a ticketing connector against the contract. PURE, offline."""
    res = ConformanceResult(name=getattr(connector, "name", "?"), kind="ticketing", ok=True)

    _record(res, "has_name",
            isinstance(getattr(connector, "name", None), str) and bool(connector.name),
            "name must be a non-empty string")
    _record(res, "has_methods",
            hasattr(connector, "build_request") and hasattr(connector, "parse_response"),
            "must expose build_request + parse_response")
    if res.failures:
        return res

    # build_request of a neutral ticket -> {body, path}, json-able
    try:
        req = connector.build_request({"title": "T", "severity": "high",
                                       "related_alert_ids": ["a1"], "assigned_team": "x",
                                       "body": "b"})
        assert isinstance(req, dict) and "body" in req and "path" in req, "shape"
        assert isinstance(req["path"], str), "path must be str"
        json.dumps(req["body"])
        _record(res, "build_request_shape", True)
    except Exception as exc:  # noqa: BLE001
        _record(res, "build_request_shape", False, str(exc))

    # title-less request -> ConnectorError
    try:
        connector.build_request({"severity": "high"})
        _record(res, "rejects_titleless", False, "accepted a title-less request")
    except ConnectorError:
        _record(res, "rejects_titleless", True)
    except Exception as exc:  # noqa: BLE001
        _record(res, "rejects_titleless", False, f"raised {type(exc).__name__}")

    # parse_response of own sample -> {ticket_id, status, url}, non-empty id. The
    # _sample_for call is INSIDE the try so a throwing/absent sample_response is a
    # recorded failure, never propagated.
    try:
        sample = _sample_for(connector, _TICKETING_SAMPLES)
        if sample is _NO_SAMPLE:
            raise AssertionError(
                "no sample_response() and no built-in fixture; cannot certify parsing")
        result = connector.parse_response(sample)
        assert isinstance(result, dict), "result must be a dict"
        assert {"ticket_id", "status", "url"} <= set(result), "missing neutral result keys"
        assert result["ticket_id"], "ticket_id must be non-empty"
        _record(res, "parse_sample_result", True)
    except Exception as exc:  # noqa: BLE001
        _record(res, "parse_sample_result", False, str(exc))

    # malformed replies -> ConnectorError for EVERY probe shape (dict/list/str/None/int)
    _record_foreign_envelope_check(res, connector)
    return res


def certify_all(get_siem, get_ticketing, siem_names, ticketing_names) -> Dict[str, ConformanceResult]:
    """Run the conformance kit over every registered connector.

    Parameters are the registry accessors + name lists (injected so this stays
    import-cycle-free and reusable by third parties over their own registry).
    Returns ``{name: ConformanceResult}``.

    Each connector is certified independently: if resolving or certifying one
    connector RAISES (a broken registry entry, a check that leaks an exception),
    it is recorded as a failed result and the run CONTINUES — one bad connector
    can never abort certification of the rest (audited)."""
    out: Dict[str, ConformanceResult] = {}
    for kind, names, getter, check in (
        ("siem", siem_names, get_siem, check_siem_connector),
        ("ticketing", ticketing_names, get_ticketing, check_ticketing_connector),
    ):
        for n in names:
            try:
                out[n] = check(getter(n))
            except Exception as exc:  # noqa: BLE001 — isolate a broken connector, keep going
                res = ConformanceResult(name=n, kind=kind, ok=False)
                _record(res, "certification_ran", False,
                        f"resolving/certifying raised {type(exc).__name__}: {exc}")
                out[n] = res
    return out
