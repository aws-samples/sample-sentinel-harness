"""siem_query — read-only SIEM alert/event query tool over the mock world.

.. warning::
   **This serves CLEARLY-LABELED MOCK DATA for POC / testing only.** It is
   *not* a real SIEM and returns *no* real threat intelligence. Every event it
   returns is fictional data from ``mockdata.load_world()`` (RFC 5737
   documentation IPs, ``example.test`` / ``example.com`` domains, generic host
   ids). See ``README.md`` and ``mockdata/README.md``.

SecOps purpose
--------------
Alert triage starts at the SIEM: an analyst (or an agent) pulls the events for
a host, a technique, or a severity band, then pivots to enrichment, asset
lookup, and ticketing. This tool is that first hop — a **read-only** query
surface over the fictional SecOps world's alert stream. It never writes; it
only filters the deterministic event set and returns a normalized view.

Because every data-plane tool (``siem_query``, ``asset_lookup``,
``enrich_ioc``, ``create_ticket``) reads the SAME ``mockdata`` world, the host
an alert names here is the same host ``asset_lookup`` knows and the IP it
carries is the same indicator ``enrich_ioc`` scores. The headline cross-link:
``alert-1001`` (Log4Shell / ``T1190``) on ``web-01`` from the C2 IP
``203.0.113.66`` — findable here by host ``web-01`` AND by technique ``T1190``.

Input contract
--------------
Exactly one selector per call (a query shape):
    {"host": "web-01"}       # all events whose host == web-01
    {"technique": "T1190"}   # all events with that ATT&CK technique id
    {"severity": "high"}     # all events at that severity band
    {"alert_id": "alert-1001"}  # a single event by id
    {"since": "2026-06-30T00:00:00Z"}  # events at/after an ISO-8601 instant
    {"query": "*"}           # the whole alert stream

An empty event, an unknown/typo'd selector key, a non-string selector value, or
more than one selector at once is a ``validation_error`` — never a silent empty
result. An unknown *value* for a valid selector (e.g. an unknown host) is NOT
an error: it returns an empty ``events`` list, so "no matches" is
distinguishable from "malformed query".

Output contract (on success)
----------------------------
{
    "ok": True,
    "source": "stub",             # "live" only if a future backend is wired
    "count": 1,
    "events": [                    # normalized, deterministic, sorted by ts
        {
            "alert_id": "alert-1001",
            "ts": "2026-06-28T14:03:11Z",
            "severity": "critical",
            "rule_name": "Log4Shell JNDI Exploit Attempt",
            "host": "web-01",
            "src_ip": "203.0.113.66",
            "dst_ip": "192.0.2.10",
            "technique": "T1190",
            "summary": "Inbound HTTP request ...",
            "false_positive": False,
        },
        ...
    ],
}

Read-only posture
-----------------
This tool performs NO writes to the mock world (or anywhere). ``load_world()``
hands back a fresh deep copy each call, so filtering here can never mutate the
shared source. There is no clock and no randomness: the same query returns the
same events every time.

Egress & secrets posture
------------------------
- Egress is CONTROLLED. The default (offline) path has zero network I/O — it
  reads the embedded mock world only. A live SIEM backend call happens only
  when ``SIEM_QUERY_LIVE=1`` (a documented future opt-in) AND the runtime
  network policy permits egress.
- Secrets are CONTROLLED. Any future backend endpoint/token is read only from
  the environment (``SIEM_QUERY_URL`` / ``SIEM_QUERY_TOKEN``) — never
  hardcoded, logged, or echoed back in responses.
- Execution role / region are referenced via the standard harness environment
  variables ``SENTINEL_EXECUTION_ROLE_ARN`` / ``SENTINEL_REGION`` /
  ``AWS_PROFILE`` (never hardcoded account IDs or ARNs).
"""

from __future__ import annotations

import os
from typing import Any, Dict, List

import mockdata

# The selector keys this tool understands. Exactly one must be present per call.
# Kept explicit (not inferred) so a typo'd key is a loud validation_error rather
# than a silently-empty query. ``query`` is the wildcard ("*" -> everything).
_SELECTOR_KEYS = ("host", "technique", "severity", "alert_id", "since", "query")

# Guard rail: reject absurdly long selector values before they hit filtering.
_MAX_VALUE_LEN = 256

# Live-backend client tunables. Kept small and explicit so a hung or oversized
# backend can never wedge the tool: a bounded timeout and a bounded read.
_LIVE_TIMEOUT_S = 15
_MAX_RESPONSE_BYTES = 2_000_000

# SSRF guard: only plain HTTP(S) egress to a routable host is permitted for the
# operator-configured SIEM_QUERY_URL. file://, gopher://, ftp:// etc. and
# non-routable/metadata IP literals (notably 169.254.169.254) are refused.
_ALLOWED_URL_SCHEMES = frozenset({"https", "http"})


def _assert_safe_url(url: str) -> None:
    """Refuse an outbound URL that is not plain HTTP(S) to a routable host.

    Applied before ANY live request opens: enforce a scheme allowlist (https/http
    only) and refuse link-local/loopback/metadata targets (the cloud metadata IP
    ``169.254.169.254`` and ``file://``). Raises ``RuntimeError`` on a rejected URL
    so the handler maps it to ``upstream_error`` (never a silent fallback).
    Hostnames that are not IP literals pass through (DNS resolution is the runtime
    egress policy's job); only IP-literal hosts are range-checked.
    """
    import ipaddress
    from urllib.parse import urlsplit

    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in _ALLOWED_URL_SCHEMES:
        raise RuntimeError(
            f"refusing to open non-HTTP(S) URL scheme {scheme!r}; "
            "only https/http egress is permitted"
        )
    host = parts.hostname
    if not host:
        raise RuntimeError("backend URL has no host component")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return  # not an IP literal — leave DNS-name egress to the network policy
    # Block the genuinely-dangerous ranges (cloud metadata + unspecified/multicast/
    # reserved). Loopback is deliberately NOT blocked: an on-box / self-hosted SIEM
    # backend at 127.0.0.1 is a legitimate operator choice (and is what the mock
    # server in the test suite uses); the SSRF threat we care about is the metadata
    # endpoint and link-local, which stay refused.
    if (
        ip.is_link_local          # 169.254.0.0/16 (incl. 169.254.169.254) & fe80::/10
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified      # 0.0.0.0, ::
    ):
        raise RuntimeError(
            f"refusing to open URL targeting non-routable/metadata address {host!r}"
        )


def _normalize_event(alert: Dict[str, Any]) -> Dict[str, Any]:
    """Project a raw mock-world alert into the stable SIEM event shape.

    WHY normalize: callers key off a fixed set of fields; the raw record uses
    ``raw_summary`` and may omit ``false_positive``. We map to ``summary`` and
    default ``false_positive`` to False so every returned event has the same
    shape regardless of which optional keys the source record carried.
    """
    return {
        "alert_id": alert["alert_id"],
        "ts": alert["ts"],
        "severity": alert["severity"],
        "rule_name": alert["rule_name"],
        "host": alert["host"],
        "src_ip": alert.get("src_ip"),
        "dst_ip": alert.get("dst_ip"),
        "technique": alert["technique"],
        "summary": alert.get("raw_summary", ""),
        "false_positive": bool(alert.get("false_positive", False)),
    }


def _validate(event: Dict[str, Any]) -> tuple[str, str]:
    """Validate input and return the ``(selector_key, value)`` to filter on.

    Exactly one recognized selector must be present. We reject: a non-dict
    event, an empty event, an unknown selector key, more than one selector,
    a non-string value, a blank value, and an over-long value. Each is a
    ``validation_error`` so the triage layer never sees malformed input as a
    (never-matching) empty result.
    """
    if not isinstance(event, dict):
        raise ValueError("event must be a dict")
    if not event:
        raise ValueError(
            "empty query; expected exactly one of "
            f"{', '.join(_SELECTOR_KEYS)}"
        )
    present = [k for k in _SELECTOR_KEYS if k in event]
    unknown = [k for k in event if k not in _SELECTOR_KEYS]
    if unknown:
        raise ValueError(
            f"unknown query key(s) {unknown}; expected exactly one of "
            f"{', '.join(_SELECTOR_KEYS)}"
        )
    if not present:
        raise ValueError(
            "no recognized query selector; expected exactly one of "
            f"{', '.join(_SELECTOR_KEYS)}"
        )
    if len(present) > 1:
        raise ValueError(
            f"exactly one query selector allowed, got {len(present)}: {present}"
        )
    key = present[0]
    value = event[key]
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"selector {key!r} must be a non-empty string")
    value = value.strip()
    if len(value) > _MAX_VALUE_LEN:
        raise ValueError(
            f"selector {key!r} value too long "
            f"({len(value)} > {_MAX_VALUE_LEN} chars)"
        )
    return key, value


def _match(alert: Dict[str, Any], key: str, value: str) -> bool:
    """Return whether a raw alert satisfies the ``(key, value)`` selector.

    Matching is deterministic and case-sensitive on the world's own literals:
      - host / severity  -> exact field equality.
      - technique        -> exact ATT&CK id equality (upper-cased so "t1190"
                            still matches the canonical "T1190").
      - alert_id         -> exact id equality.
      - since            -> ISO-8601 lexical >= (the world's timestamps are all
                            zulu ``...Z`` and thus lexically comparable).
      - query "*"        -> handled by the caller (matches everything).
    """
    if key == "host":
        return alert["host"] == value
    if key == "severity":
        return alert["severity"] == value
    if key == "technique":
        return alert["technique"].upper() == value.upper()
    if key == "alert_id":
        return alert["alert_id"] == value
    if key == "since":
        # Zulu ISO-8601 strings of equal shape sort lexically == chronologically.
        return alert["ts"] >= value
    # key == "query": only "*" is meaningful; anything else matched nothing and
    # would have been caught here as a non-match (handled in _select).
    return False


def _select(key: str, value: str) -> List[Dict[str, Any]]:
    """Return normalized events matching the selector, sorted by timestamp.

    Reads a fresh copy of the mock world (read-only) and filters it. Sorting by
    ``ts`` then ``alert_id`` makes output ordering stable and deterministic even
    when two events share a timestamp.
    """
    alerts = mockdata.load_world()["alerts"]
    if key == "query":
        if value != "*":
            raise ValueError(
                f"unsupported 'query' value {value!r}; only '*' (all events) "
                "is supported"
            )
        matched = alerts
    else:
        matched = [a for a in alerts if _match(a, key, value)]
    events = [_normalize_event(a) for a in matched]
    return sorted(events, key=lambda e: (e["ts"], e["alert_id"]))


def _normalize_live_event(record: Dict[str, Any]) -> Dict[str, Any]:
    """Project one backend record into the SAME 10-field event shape the stub
    emits (see ``_normalize_event``).

    WHY a separate normalizer: a live SIEM record may already use the public
    ``summary`` field name (or the mock world's ``raw_summary``) and may omit
    optional fields. We map both summary spellings and default every field so a
    live event is byte-for-byte the same shape as an offline one — the caller
    cannot tell offline from live apart from the top-level ``source`` marker.
    """
    if not isinstance(record, dict):
        raise RuntimeError(
            f"SIEM backend returned a non-object event: {type(record).__name__}"
        )
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
        "false_positive": bool(record.get("false_positive", False)),
    }


def _fetch_live(key: str, value: str) -> List[Dict[str, Any]]:
    """Query a live SIEM backend for matching events (stdlib HTTP, no deps).

    Only reached when ``SIEM_QUERY_LIVE=1``. Builds a POST from environment
    configuration only — the endpoint ``SIEM_QUERY_URL`` (required) and an
    OPTIONAL bearer token ``SIEM_QUERY_TOKEN`` (env only; never hardcoded,
    logged, or echoed). The validated ``{selector: value}`` query is sent as the
    JSON request body; the JSON reply is parsed and normalized into the SAME
    event shape the offline stub returns.

    Failure posture (no silent fixture fallback, no swallowed exceptions):
      - missing ``SIEM_QUERY_URL``  -> RuntimeError (become ``upstream_error``),
        the message telling the operator to unset ``SIEM_QUERY_LIVE``.
      - timeout / connection refused / DNS -> RuntimeError.
      - non-2xx HTTP status                -> RuntimeError.
      - malformed / non-JSON body          -> RuntimeError.
    Every one surfaces to the handler as an ``upstream_error`` — opting into
    live and getting nothing back is never mistaken for "no events".
    """
    import json
    import urllib.error
    import urllib.request

    url = os.environ.get("SIEM_QUERY_URL")
    if not url:
        raise RuntimeError(
            "SIEM_QUERY_LIVE=1 but SIEM_QUERY_URL is not set; no backend to "
            "query. Unset SIEM_QUERY_LIVE to use the offline mock world."
        )
    # SSRF/exfil hardening: refuse a non-HTTP(S) scheme or a non-routable/metadata
    # target before opening the request (raises -> upstream_error, no silent fallback).
    _assert_safe_url(url)
    # Optional bearer token: read from the environment only. Never hardcoded,
    # never logged, never placed in an error message or the response.
    token = os.environ.get("SIEM_QUERY_TOKEN")

    body = json.dumps({key: value}).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "sentinel-harness",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        # noqa: S310 — the endpoint is operator-configured via env, not attacker
        # controlled; timeout + bounded read keep a bad backend from wedging us.
        with urllib.request.urlopen(req, timeout=_LIVE_TIMEOUT_S) as resp:  # noqa: S310
            # Read cap+1 then reject over-limit, rather than silently truncating —
            # matches the ops_query/asset_lookup/enrich_ioc reject pattern so the
            # whole tool family behaves identically on an oversized reply.
            raw = resp.read(_MAX_RESPONSE_BYTES + 1)
        if len(raw) > _MAX_RESPONSE_BYTES:
            raise RuntimeError(
                f"SIEM backend reply exceeds {_MAX_RESPONSE_BYTES} bytes; refusing to parse"
            )
    except urllib.error.HTTPError as exc:  # non-2xx status line
        raise RuntimeError(
            f"SIEM backend returned HTTP {exc.code} for {url!r}"
        ) from exc
    except urllib.error.URLError as exc:  # DNS / refused / timeout / TLS
        raise RuntimeError(
            f"could not reach SIEM backend at {url!r}: {exc.reason}"
        ) from exc

    # json.JSONDecodeError subclasses ValueError; the handler routes bare
    # ValueError to validation_error, so re-raise as RuntimeError to keep a
    # malformed backend reply classified as an upstream_error.
    try:
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise RuntimeError(
            f"SIEM backend at {url!r} returned malformed JSON: {exc}"
        ) from exc

    if isinstance(data, dict):
        records = data.get("events", [])
    elif isinstance(data, list):
        records = data
    else:
        raise RuntimeError(
            f"SIEM backend at {url!r} returned an unexpected JSON shape "
            f"({type(data).__name__}); expected an object or a list"
        )
    if not isinstance(records, list):
        raise RuntimeError(
            f"SIEM backend at {url!r} returned a non-list 'events' field"
        )

    events = [_normalize_live_event(r) for r in records]
    # Same stable ordering as the stub path so live/offline output is identical.
    return sorted(events, key=lambda e: (e["ts"], e["alert_id"]))


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Return the SIEM events matching a single query selector (read-only).

    Runs offline (deterministic mock world) by default; performs a live backend
    call only when the environment opts in via ``SIEM_QUERY_LIVE=1``. All egress
    and secrets are controlled through environment configuration, never
    hardcoded. Performs NO writes.
    """
    try:
        key, value = _validate(event)
    except ValueError as exc:
        return {"ok": False, "error": "validation_error", "message": str(exc)}

    live = os.environ.get("SIEM_QUERY_LIVE") == "1"
    try:
        if live:
            events = _fetch_live(key, value)
            source = "live"
        else:
            events = _select(key, value)
            source = "stub"
    except ValueError as exc:
        # e.g. an unsupported 'query' value — a client error, not upstream.
        return {"ok": False, "error": "validation_error", "message": str(exc)}
    except Exception as exc:  # backend failures — surface, never swallow
        return {"ok": False, "error": "upstream_error", "message": str(exc)}

    return {"ok": True, "source": source, "count": len(events), "events": events}


if __name__ == "__main__":
    import json

    # Demo: the Log4Shell spine, found by host and by technique.
    print(json.dumps(handler({"host": "web-01"}, None), indent=2))
    print(json.dumps(handler({"technique": "T1190"}, None), indent=2))
