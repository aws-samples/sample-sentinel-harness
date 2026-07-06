"""create_ticket — ticketing WRITE tool (offline, deterministic mock).

.. warning::
   **CLEARLY-LABELED MOCK TOOL for POC / testing only.** In the default offline
   mode this tool does **not** talk to any real ticketing system (Jira / ServiceNow
   / SIM / GitHub Issues). It "creates" a ticket purely as an in-process, returned
   data structure. Nothing is persisted, nothing leaves the process, no network
   I/O happens. It is *not* a real tracker.

SecOps purpose
--------------
The alert-triage flow (``harnesses/alert-triage``) ends with a *write*: once an
analyst (or agent) has correlated a SIEM alert, enriched its indicators, and
looked up the targeted asset, the finding needs to be recorded as a ticket so a
human can own containment / remediation. This tool is that terminal step —
turning a triaged finding into a ticket record with an id, a status, and the
echoed finding fields (title, severity, description, and optional links back to
the alert / IOC / host that motivated it).

HITL gate (important)
---------------------
Opening a ticket is a **containment / ticketing action**, which in the
alert-triage design is **human-in-the-loop (HITL) gated**: an autonomous agent
proposes it, but a human approves before it fires against any real tracker. The
offline mock is side-effect-free precisely so the POC can exercise the *shape*
of that write end-to-end without a human ever needing to gate a real mutation.
When wired live (``CREATE_TICKET_LIVE=1``, future work), the HITL approval must
sit in front of the real POST — see README.md.

Determinism (why a content hash)
--------------------------------
Tests and reproducible demos need the *same input to yield the same ticket id*.
Two id strategies were considered:

  1. a monotonic in-process counter seeded from ``mockdata.tickets_seed()``
     (next id ``SEC-1003``), which is stateful — the same input yields a
     *different* id on the second call, so it is order-dependent and awkward to
     assert on; and
  2. a **content-hash id**: a short, stable digest of the ticket's semantic
     content (title + severity + description + the optional links).

We use strategy (2): ``ticket_id = "SEC-" + sha256(content)[:12]``. It is purely
a function of the request content, so it is deterministic offline with **no
shared mutable state**, and identical requests naturally de-duplicate to the
same id (a desirable property for an idempotent "create"). The mock world's
``SEC-1003`` monotonic seed is documented for the live path (a real tracker
assigns its own sequential id), but the offline mock deliberately does NOT use a
process counter — that is the honest, test-friendly choice. ``created_ts`` is
likewise derived deterministically from the content hash (a fixed synthetic
timestamp), never from the wall clock, so the whole record is reproducible.

Egress & secrets posture
-------------------------
- Egress is CONTROLLED. A real tracker POST happens only when
  ``CREATE_TICKET_LIVE=1`` AND the runtime network policy permits egress. Default
  (offline) mode performs zero network I/O.
- Secrets are CONTROLLED. Any tracker endpoint/token is read only from the
  environment (``CREATE_TICKET_URL`` / ``CREATE_TICKET_TOKEN``) — never hardcoded,
  logged, or echoed back in responses.
- Execution role / region are referenced via the standard harness environment
  variables (``SENTINEL_EXECUTION_ROLE_ARN`` etc.); no account ids or ARNs are
  hardcoded.

Input contract
--------------
event = {
    "title": "Log4Shell exploitation attempt against web-01",  # required, str
    "severity": "critical",                                     # required enum
    "description": "Inbound JNDI payload matched CVE-2021-44228; ...",  # required
    "assignee": "secops",            # optional
    "related_alert_id": "alert-1001",# optional
    "related_host": "web-01",        # optional
}
severity is one of {"low", "medium", "high", "critical"}.

Output contract (on success)
----------------------------
{
    "ok": True,
    "source": "stub" | "live",
    "ticket": {
        "ticket_id": "SEC-...",       # deterministic content-hash id (offline)
        "status": "open",
        "created_ts": "2026-...Z",     # derived deterministically, not wall clock
        "title": ...,
        "severity": ...,
        "description": ...,
        "assignee": ... | None,
        "related_alert_id": ... | None,
        "related_host": ... | None,
    },
}

On validation failure:
    {"ok": False, "error": "validation_error", "message": ...}
"""

from __future__ import annotations

import hashlib
import json
import os
from typing import Any, Dict, Optional

# The severity taxonomy this tool accepts, mirroring the mock world's alert
# severities (see mockdata/world.py). "info" is intentionally NOT a valid ticket
# severity — you don't open a containment ticket for an informational event.
_VALID_SEVERITIES = ("low", "medium", "high", "critical")

# Ticket id prefix, matching the mock world's seed tickets (SEC-1001 / SEC-1002).
# The live path lets a real tracker assign its own id; offline we derive one.
_TICKET_ID_PREFIX = "SEC-"

# Bound free-text fields so a malformed / abusive payload is a validation_error,
# never an unbounded record.
_MAX_TITLE_LEN = 256
_MAX_DESCRIPTION_LEN = 8192
_MAX_FIELD_LEN = 256  # assignee / related_alert_id / related_host


def _require_str(event: Dict[str, Any], key: str, max_len: int) -> str:
    """Return a required non-empty string field, or raise ValueError.

    WHY: title / severity / description are the minimum a ticket must carry; a
    missing or blank one is a hard validation error — we never fabricate a
    placeholder to let a malformed create through.
    """
    val = event.get(key)
    if not isinstance(val, str) or not val.strip():
        raise ValueError(f"missing required non-empty string field {key!r}")
    val = val.strip()
    if len(val) > max_len:
        raise ValueError(f"{key!r} too long ({len(val)} > {max_len} chars)")
    return val


def _optional_str(event: Dict[str, Any], key: str) -> Optional[str]:
    """Return an optional string field (trimmed) or None.

    An explicit ``None`` or an absent key means "not provided". A present-but
    non-string (e.g. a number) is a validation error — we surface the bad type
    rather than silently coercing it.
    """
    if key not in event or event[key] is None:
        return None
    val = event[key]
    if not isinstance(val, str) or not val.strip():
        raise ValueError(
            f"optional field {key!r}, if provided, must be a non-empty string"
        )
    val = val.strip()
    if len(val) > _MAX_FIELD_LEN:
        raise ValueError(f"{key!r} too long ({len(val)} > {_MAX_FIELD_LEN} chars)")
    return val


def _validate(event: Dict[str, Any]) -> Dict[str, Any]:
    """Validate the create-ticket request and return normalized fields.

    Enforces: title + severity + description required; severity in the allowed
    enum; optional fields (assignee / related_alert_id / related_host) are
    strings when present. Never swallows — a bad request raises ValueError which
    the handler maps to a ``validation_error`` response.
    """
    if not isinstance(event, dict):
        raise ValueError("event must be a dict")

    title = _require_str(event, "title", _MAX_TITLE_LEN)
    severity = _require_str(event, "severity", _MAX_FIELD_LEN).lower()
    if severity not in _VALID_SEVERITIES:
        raise ValueError(
            f"invalid severity {severity!r}; expected one of {_VALID_SEVERITIES}"
        )
    description = _require_str(event, "description", _MAX_DESCRIPTION_LEN)

    return {
        "title": title,
        "severity": severity,
        "description": description,
        "assignee": _optional_str(event, "assignee"),
        "related_alert_id": _optional_str(event, "related_alert_id"),
        "related_host": _optional_str(event, "related_host"),
    }


def _content_digest(fields: Dict[str, Any]) -> str:
    """Return a stable hex digest of the ticket's semantic content.

    WHY canonical JSON with sorted keys: the digest must depend only on the
    *values*, not on dict insertion order, so the same logical ticket always
    hashes the same. This is the backbone of offline determinism and idempotent
    "create" (identical requests -> identical id).
    """
    canonical = json.dumps(fields, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _make_ticket(fields: Dict[str, Any]) -> Dict[str, Any]:
    """Build the deterministic offline ticket record from validated fields.

    The id and created_ts are both derived from the content digest, so the whole
    record is a pure function of the request — no counter, no clock, no I/O.
    """
    digest = _content_digest(fields)
    ticket_id = f"{_TICKET_ID_PREFIX}{digest[:12]}"
    # A deterministic synthetic timestamp (not the wall clock). We map the first
    # bytes of the digest into a fixed year so the value is obviously synthetic
    # yet stable per-content. Format is ISO-8601 Zulu to match the mock world.
    created_ts = f"2026-01-01T00:00:00Z#{digest[:8]}"
    return {
        "ticket_id": ticket_id,
        "status": "open",
        "created_ts": created_ts,
        "title": fields["title"],
        "severity": fields["severity"],
        "description": fields["description"],
        "assignee": fields["assignee"],
        "related_alert_id": fields["related_alert_id"],
        "related_host": fields["related_host"],
    }


def _create_live(fields: Dict[str, Any]) -> Dict[str, Any]:
    """POST the ticket to a live tracker backend.

    Only reached when ``CREATE_TICKET_LIVE=1``. The concrete tracker client is
    wired in later work; until then this raises an explicit error rather than
    silently pretending a real ticket was opened. This is the point where a
    human-in-the-loop approval gate must sit in front of the real mutation.
    """
    url = os.environ.get("CREATE_TICKET_URL")
    if not url:
        raise RuntimeError(
            "CREATE_TICKET_LIVE=1 but CREATE_TICKET_URL is not set; no tracker "
            "to POST to. Unset CREATE_TICKET_LIVE to use the offline mock."
        )
    # The live client is intentionally not implemented here: writing to a real
    # tracker is a HITL-gated, later-milestone action. Raising keeps the contract
    # honest — we never fabricate a "created" real ticket.
    raise NotImplementedError(
        "live ticketing backend not wired yet; a human-in-the-loop approval must "
        f"gate the real POST to {url!r} before setting CREATE_TICKET_LIVE=1"
    )


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Create a ticket from a triaged finding (offline mock by default).

    Runs offline (deterministic, side-effect-free in-memory record) by default;
    performs a live tracker POST only when the environment opts in via
    ``CREATE_TICKET_LIVE=1`` (a HITL-gated action, not wired yet). All egress and
    secrets are controlled through environment configuration, never hardcoded.
    """
    try:
        fields = _validate(event)
    except ValueError as exc:
        return {"ok": False, "error": "validation_error", "message": str(exc)}

    live = os.environ.get("CREATE_TICKET_LIVE") == "1"
    try:
        if live:
            ticket = _create_live(fields)
            source = "live"
        else:
            ticket = _make_ticket(fields)
            source = "stub"
    except Exception as exc:  # backend failures — surface, never swallow
        return {"ok": False, "error": "upstream_error", "message": str(exc)}

    return {"ok": True, "source": source, "ticket": ticket}


if __name__ == "__main__":
    demo = handler(
        {
            "title": "Log4Shell exploitation attempt against web-01",
            "severity": "critical",
            "description": (
                "Inbound HTTP JNDI payload matched CVE-2021-44228 (Log4Shell) "
                "against web-01; outbound LDAP callback to 203.0.113.66 observed."
            ),
            "assignee": "secops",
            "related_alert_id": "alert-1001",
            "related_host": "web-01",
        },
        None,
    )
    print(json.dumps(demo, indent=2))
