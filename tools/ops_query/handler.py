"""ops_query — read-only multi-account operations query tool.

Ops purpose
-----------
A multi-account ops-automation supervisor (see ``harnesses/ops-automation``)
needs to enumerate the accounts it owns, inspect each account's resource
footprint, and pull the open operational findings across the estate so it can
triage them and open tickets for the real issues. Given an account id, a
wildcard, or a finding-type filter, this tool returns that view in a
normalized, deterministic structure — the multi-account analog of
``asset_lookup`` for the SecOps world.

This is a *reference implementation* for wiring into an Amazon Bedrock
AgentCore Gateway as an MCP target (Lambda-style handler). It runs entirely
OFFLINE by default from the fictional inventory in ``mockdata/accounts.py``; a
live backend (AWS Organizations for account enumeration, a support/Trusted-
Advisor-style API for findings, or per-account CloudWatch) is opted into later
via ``OPS_QUERY_LIVE=1``. That keeps the template testable in CI with no
network, no secrets, and no external dependencies.

What is real vs. stubbed
------------------------
- The OFFLINE inventory is REAL, deterministic data: the same query always
  yields the same accounts/findings. It is *synthetic* (no real environment),
  but nothing is fabricated at call time.
- The LIVE path is a documented, guarded stub: it raises an explicit
  ``upstream_error`` until a concrete backend is wired later. It never silently
  falls back to fixtures, so an operator who *opts into* live and gets nothing
  learns why.

Egress & secrets posture
------------------------
- Egress is CONTROLLED. A live backend call happens only when
  ``OPS_QUERY_LIVE=1`` AND the runtime network policy permits egress. In the
  default (offline) mode there is zero network I/O.
- Secrets are CONTROLLED. Any backend endpoint/token is read only from the
  environment (``OPS_QUERY_URL`` / ``OPS_QUERY_TOKEN``) — never hardcoded,
  logged, or echoed back in responses.
- Execution role / region are referenced via the standard harness environment
  variables ``SENTINEL_EXECUTION_ROLE_ARN``, ``SENTINEL_REGION`` and
  ``AWS_PROFILE`` (never hardcoded account IDs or ARNs).

Input contract
--------------
event = {"account": "111111111111"}      # one account's full record, or
event = {"query": "*"}                    # every account (estate-wide), or
event = {"finding_type": "public_s3"}     # open findings of one type, estate-wide

Exactly one selector is required. Combining selectors is a validation_error so
the query intent is never ambiguous.

Output contract (on success)
----------------------------
Account/estate selectors return an ``accounts`` list::

    {"ok": True, "source": "stub", "accounts": [ {account record}, ... ]}

A finding_type selector returns a flat ``findings`` list, each finding tagged
with the account it belongs to::

    {"ok": True, "source": "stub", "finding_type": "public_s3",
     "findings": [ {account_id, account_name, ...finding fields}, ... ]}
"""

from __future__ import annotations

import os
from typing import Any, Dict, List

from mockdata.accounts import accounts as _load_accounts
from mockdata.accounts import finding_types as _known_finding_types

# A 12-digit AWS account id. We validate shape only (never that it is a *real*
# account) — the offline inventory uses fictional repeated-digit demo ids.
_ACCOUNT_ID_LEN = 12
_MAX_QUERY_LEN = 64


def _validate(event: Dict[str, Any]) -> Dict[str, str]:
    """Validate input and return the normalized selector.

    Exactly ONE of ``account`` / ``query`` / ``finding_type`` must be present.
    Returns a single-key dict naming the selector, e.g. ``{"account": "1..."}``
    or ``{"query": "*"}`` or ``{"finding_type": "public_s3"}``. Malformed or
    ambiguous input is a ``ValueError`` (surfaced as validation_error) so the
    reasoning layer never sees an ambiguous query and no query silently
    matches nothing by accident.
    """
    if not isinstance(event, dict):
        raise ValueError("event must be a dict")

    selectors = [k for k in ("account", "query", "finding_type") if k in event]
    if not selectors:
        raise ValueError(
            "missing selector: provide exactly one of 'account', 'query', "
            "or 'finding_type'"
        )
    if len(selectors) > 1:
        raise ValueError(
            f"ambiguous query: provide exactly one selector, got {selectors}"
        )
    key = selectors[0]
    value = event[key]
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"'{key}' must be a non-empty string")
    value = value.strip()
    if len(value) > _MAX_QUERY_LEN:
        raise ValueError(f"'{key}' too long ({len(value)} > {_MAX_QUERY_LEN} chars)")

    if key == "query":
        # Only the wildcard is a valid 'query'; a specific account must use the
        # 'account' selector so the intent is explicit.
        if value != "*":
            raise ValueError("'query' only supports the wildcard '*'")
    elif key == "account":
        if not (len(value) == _ACCOUNT_ID_LEN and value.isdigit()):
            raise ValueError(
                f"invalid account id {value!r}; expected a {_ACCOUNT_ID_LEN}-digit id"
            )
    else:  # finding_type
        known = _known_finding_types()
        if value not in known:
            raise ValueError(
                f"unknown finding_type {value!r}; known types: {known}"
            )
    return {key: value}


def _select_accounts(selector: Dict[str, str]) -> List[Dict[str, Any]]:
    """Return the inventory accounts matching an account/wildcard selector.

    ``{"query": "*"}`` -> every account; ``{"account": id}`` -> that single
    account if known, else an empty list (an unknown-but-well-formed id is not
    an error — it simply matches nothing). Order is stable (inventory order).
    """
    inventory = _load_accounts()
    if "query" in selector:  # wildcard
        return inventory
    wanted = selector["account"]
    return [a for a in inventory if a["account_id"] == wanted]


def _select_findings(finding_type: str) -> List[Dict[str, Any]]:
    """Return open findings of one type across the estate, account-tagged.

    Each finding is flattened with its owning ``account_id`` / ``account_name``
    so the caller can open a ticket without a second lookup. Order is stable
    (inventory order, then per-account finding order).
    """
    out: List[Dict[str, Any]] = []
    for acct in _load_accounts():
        for finding in acct["findings"]:
            if finding["finding_type"] == finding_type:
                tagged = {
                    "account_id": acct["account_id"],
                    "account_name": acct["name"],
                    **finding,
                }
                out.append(tagged)
    return out


def _fetch_live(selector: Dict[str, str]) -> Dict[str, Any]:
    """Fetch the multi-account view from a live ops backend.

    Only reached when ``OPS_QUERY_LIVE=1``. The concrete backend (AWS
    Organizations for account enumeration + a support / Trusted-Advisor-style
    findings API + per-account CloudWatch) is wired later; until then this
    raises an explicit error rather than silently returning fixtures, so opting
    into live and getting nothing back is never mistaken for "no accounts".
    """
    url = os.environ.get("OPS_QUERY_URL")
    if not url:
        raise RuntimeError(
            "OPS_QUERY_LIVE=1 but OPS_QUERY_URL is not set; no backend to query. "
            "Unset OPS_QUERY_LIVE to use the offline fixture inventory."
        )
    raise NotImplementedError(
        "live multi-account ops backend not wired yet; configure a concrete "
        f"client for {url!r} (AWS Organizations / support API / CloudWatch) "
        "before setting OPS_QUERY_LIVE=1"
    )


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Return the multi-account ops view (accounts or findings) for a query.

    Read-only. Runs offline (deterministic fictional inventory) by default;
    performs a live backend call only when the environment opts in via
    ``OPS_QUERY_LIVE=1``. All egress and secrets are controlled through
    environment configuration, never hardcoded.
    """
    try:
        selector = _validate(event)
    except ValueError as exc:
        return {"ok": False, "error": "validation_error", "message": str(exc)}

    live = os.environ.get("OPS_QUERY_LIVE") == "1"
    try:
        if live:
            payload = _fetch_live(selector)
            source = "live"
            return {"ok": True, "source": source, **payload}
        if "finding_type" in selector:
            findings = _select_findings(selector["finding_type"])
            return {
                "ok": True,
                "source": "stub",
                "finding_type": selector["finding_type"],
                "findings": findings,
            }
        accts = _select_accounts(selector)
        return {"ok": True, "source": "stub", "accounts": accts}
    except Exception as exc:  # backend failures — surface, never swallow
        return {"ok": False, "error": "upstream_error", "message": str(exc)}


if __name__ == "__main__":
    import json

    print(json.dumps(handler({"query": "*"}, None), indent=2))
