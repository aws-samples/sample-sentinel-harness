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
- The LIVE path is a REAL, dependency-free HTTP client (``urllib.request`` from
  the standard library — no third-party SDK). It POSTs the validated selector
  as JSON to ``OPS_QUERY_URL`` and normalizes the JSON reply into the *same*
  output contract as the stub, only tagged ``source="live"``. Any failure
  (missing URL, timeout, non-2xx, malformed JSON, connection refused) surfaces
  as an explicit ``upstream_error`` — it never silently falls back to fixtures,
  so an operator who *opts into* live and gets nothing learns why.

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

import json
import os
import urllib.error
import urllib.request
from typing import Any, Dict, List

from mockdata.accounts import accounts as _load_accounts
from mockdata.accounts import finding_types as _known_finding_types

# A 12-digit AWS account id. We validate shape only (never that it is a *real*
# account) — the offline inventory uses fictional repeated-digit demo ids.
_ACCOUNT_ID_LEN = 12
_MAX_QUERY_LEN = 64

# Live backend HTTP settings. The endpoint and bearer token are read from the
# environment ONLY (never hardcoded, logged, or echoed in responses).
_LIVE_TIMEOUT_SECONDS = 10
# Cap the backend reply we buffer, so a hostile/misconfigured backend cannot force
# unbounded memory use within the timeout window (mirrors the sibling *_LIVE tools).
_MAX_LIVE_BODY_BYTES = 4 * 1024 * 1024

# SSRF guard: only plain HTTP(S) egress to a routable host is permitted for the
# operator-configured OPS_QUERY_URL. file://, gopher://, ftp:// etc. and
# non-routable/metadata IP literals (notably 169.254.169.254) are refused.
_ALLOWED_URL_SCHEMES = frozenset({"https", "http"})


def _assert_safe_url(url: str) -> None:
    """Refuse an outbound URL that is not plain HTTP(S) to a routable host.

    Applied before ANY live request opens: enforce a scheme allowlist (https/http
    only) and refuse link-local/metadata targets (the cloud metadata IP
    ``169.254.169.254``) and file://. Raises ``RuntimeError`` on a rejected URL so
    the handler maps it to ``upstream_error`` (never a silent fallback). Hostnames
    that are not IP literals pass through (DNS resolution is the runtime egress
    policy's job); only IP-literal hosts are range-checked. Loopback (127.0.0.1) is
    deliberately allowed — the live-test mock server binds there.
    """
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
    ip = _parse_ip_literal(host)
    if ip is None:
        return
    if (
        ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        raise RuntimeError(
            f"refusing to open URL targeting non-routable/metadata address {host!r}"
        )


def _parse_ip_literal(host: str):
    """Parse an IP-literal host, including the ALTERNATE spellings of one.

    ``ipaddress.ip_address()`` only accepts dotted-quad / standard IPv6, so the
    guard above used to pass a bare integer or hex host straight through as if it
    were a DNS name — and every one of these is 169.254.169.254, the cloud
    metadata service:

        http://2852039166/     (decimal)
        http://0xA9FEA9FE/     (hex)
        http://0251.0376.0251.0376/  (octal dotted)

    Browsers and most HTTP stacks (including urllib, via the OS resolver) accept
    all of them. Returning ``None`` here meant "not an IP, let DNS policy handle
    it", which is exactly the wrong answer for a numeric host.

    Returns an ``ip_address`` object, or ``None`` only for a host that genuinely is
    not an IP literal in any spelling.
    """
    import ipaddress

    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass
    # A wholly-numeric host is a 32-bit address in decimal/hex/octal form.
    candidate = host.strip()
    try:
        if candidate.lower().startswith(("0x", "0X")):
            value = int(candidate, 16)
        elif candidate.isdigit():
            # Leading zero means octal in this notation (0177.0.0.1 style handled
            # below); a plain digit string is decimal.
            value = int(candidate, 8) if candidate.startswith("0") else int(candidate)
        else:
            # Dotted form whose octets may themselves be octal/hex
            # (0251.0376.0251.0376 == 169.254.169.254).
            octets = candidate.split(".")
            if len(octets) != 4:
                return None
            value = 0
            for octet in octets:
                if octet.lower().startswith("0x"):
                    part = int(octet, 16)
                elif octet.startswith("0") and len(octet) > 1:
                    part = int(octet, 8)
                else:
                    part = int(octet)
                if not 0 <= part <= 255:
                    return None
                value = (value << 8) | part
        if not 0 <= value <= 0xFFFFFFFF:
            return None
        return ipaddress.ip_address(value)
    except (ValueError, TypeError):
        return None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse to follow ANY redirect on the live ops call.

    ``urlopen`` follows 3xx by default and ``_assert_safe_url`` only vets the URL
    it is HANDED, so an allowed backend answering ``302 Location:
    http://169.254.169.254/...`` walked the request straight past the guard —
    audited and reproduced. Worse, urllib re-sends the request headers to the
    redirect target, so the ``Authorization: Bearer`` credential leaked to
    whatever host the backend named.

    Refusing outright (rather than re-validating and re-following) is the right
    call here: this client POSTs a selector to ONE configured endpoint, so a
    redirect is never a legitimate part of that contract, and re-validating still
    leaves a TOCTOU window between the check and the socket connect.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        raise RuntimeError(
            f"refusing to follow an HTTP {code} redirect from the ops backend to "
            f"{newurl!r}: the URL allowlist is applied before the request opens, "
            "so following a redirect would bypass it (and forward the bearer "
            "credential to the redirect target)"
        )


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


def _normalize_live_reply(
    selector: Dict[str, str], reply: Any
) -> Dict[str, Any]:
    """Coerce a backend JSON reply into the stub's output payload shape.

    Returns the payload *without* the ``ok`` / ``source`` envelope (the handler
    adds ``source="live"``). For account/wildcard selectors that is
    ``{"accounts": [...]}``; for a finding_type selector it is
    ``{"finding_type": <type>, "findings": [...]}`` — identical in shape to what
    the offline stub produces, so downstream reasoning cannot tell the transport
    apart. A reply that is not a JSON object, or whose list field is not a list,
    is a hard error (surfaced as ``upstream_error``) rather than a silent empty
    result.
    """
    if not isinstance(reply, dict):
        raise ValueError(
            f"backend returned {type(reply).__name__}, expected a JSON object"
        )
    # INV-OPS-2: a backend that reports a PARTIAL result must not have that dropped.
    # "These are all the open findings in the estate" is a stopping decision — a
    # finding that does not appear is never triaged, ticketed or fixed. Discarding
    # `errors[]` turned "3 of 12 accounts denied access" into a confident complete
    # view, and discarding a pagination cursor truncated the estate to page one with
    # no signal. Both are surfaced; neither is silently swallowed.
    _assert_complete(reply)

    if "finding_type" in selector:
        findings = reply.get("findings")
        if not isinstance(findings, list):
            raise ValueError(
                "backend reply missing a 'findings' list for a finding_type query"
            )
        # INV-OPS-3: the requested type was STAMPED onto whatever list came back,
        # without checking the list actually contains that type. A backend that
        # ignores the filter (or a mis-routed reply) therefore had unrelated findings
        # relabelled as the requested type — an operator triaging "all public_s3
        # findings" would act on mfa_disabled records under the wrong heading.
        wanted = selector["finding_type"]
        mismatched = sorted({
            str(f.get("finding_type")) for f in findings
            if isinstance(f, dict) and f.get("finding_type") not in (None, wanted)
        })
        if mismatched:
            raise ValueError(
                f"backend returned findings of type(s) {mismatched} for a "
                f"{wanted!r} query — refusing to relabel another type's findings as "
                f"{wanted!r}"
            )
        return {"finding_type": wanted, "findings": findings}
    accounts = reply.get("accounts")
    if not isinstance(accounts, list):
        raise ValueError(
            "backend reply missing an 'accounts' list for an account/wildcard query"
        )
    # INV-OPS-4: for a SINGLE-account query, the reply must be about that account.
    # Nothing checked it, so a substituted or mis-routed reply reported another
    # account's footprint under the requested id — the same relabelling defect
    # INV-BOUNDARY-4 found in nvd_lookup, one selector over.
    if "account" in selector:
        wanted_id = selector["account"]
        wrong = sorted({
            str(a.get("account_id")) for a in accounts
            if isinstance(a, dict) and a.get("account_id") not in (None, wanted_id)
        })
        if wrong:
            raise ValueError(
                f"backend returned account(s) {wrong} for a query about "
                f"{wanted_id!r} — refusing to report another account's resources "
                f"under the requested id"
            )
    return {"accounts": accounts}


def _assert_complete(reply: Dict[str, Any]) -> None:
    """Refuse a reply the backend itself flagged as partial (INV-OPS-2).

    Two markers, both of which the old normalizer dropped on the floor:

    - ``errors``/``failures``/``partial_failures``: the backend telling us it could
      not read part of the estate. Reporting the readable part as the whole answer
      is the fail-open this repo's INV-BOUNDARY family exists to prevent.
    - ``next_token``/``nextToken``/``next_page``/``marker``: more pages exist. This
      client issues ONE request, so an un-followed cursor means the returned view is
      truncated — and a truncated "all open findings" reads as "fewer problems".

    Raised (→ ``upstream_error``) rather than returned-with-a-warning because the
    caller's contract has no field to carry the caveat, and inventing a silent one
    would be the same defect in a new shape.
    """
    for key in ("errors", "failures", "partial_failures"):
        problems = reply.get(key)
        if problems:
            raise ValueError(
                f"backend reported a PARTIAL result in {key!r} ({problems!r}) — "
                "refusing to present an incomplete estate view as complete"
            )
    for key in ("next_token", "nextToken", "next_page", "marker", "continuation"):
        cursor = reply.get(key)
        if cursor:
            raise ValueError(
                f"backend reply carries a pagination cursor {key!r}={cursor!r}, so "
                "more results exist; this client issues a single request and would "
                "otherwise report page one as the whole estate"
            )


def _fetch_live(selector: Dict[str, str]) -> Dict[str, Any]:
    """Fetch the multi-account view from a live ops backend over HTTP.

    Only reached when ``OPS_QUERY_LIVE=1``. This is a REAL, dependency-free
    client: it POSTs the validated ``selector`` as JSON to ``OPS_QUERY_URL`` and
    parses the JSON reply into the same payload shape the offline stub returns
    (the handler tags it ``source="live"``). An optional bearer token from
    ``OPS_QUERY_TOKEN`` is sent as an ``Authorization`` header — both the URL and
    the token are read from the environment ONLY and are never logged or echoed.

    Raises (all surfaced by the handler as ``upstream_error``, never a silent
    fixture fallback):

    - ``RuntimeError`` if ``OPS_QUERY_URL`` is unset (no backend to query), on a
      non-2xx HTTP status, or on any transport failure (timeout, DNS,
      connection refused).
    - ``ValueError`` if the reply body is not valid JSON or not the expected
      shape.
    """
    url = os.environ.get("OPS_QUERY_URL")
    if not url:
        raise RuntimeError(
            "OPS_QUERY_LIVE=1 but OPS_QUERY_URL is not set; no backend to query. "
            "Unset OPS_QUERY_LIVE to use the offline fixture inventory."
        )
    # SSRF/exfil hardening: refuse a non-HTTP(S) scheme or a non-routable/metadata
    # target before opening the request (raises -> upstream_error, no silent fallback).
    _assert_safe_url(url)

    body = json.dumps(selector).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    token = os.environ.get("OPS_QUERY_TOKEN")
    if token:
        # Bearer credential from env only. Never logged/echoed anywhere.
        headers["Authorization"] = f"Bearer {token}"

    request = urllib.request.Request(
        url, data=body, headers=headers, method="POST"
    )
    # Opener with redirects REFUSED. The default global opener follows 3xx, which
    # bypasses `_assert_safe_url` (it only vets the URL we hand it) and re-sends the
    # Authorization header to whatever host the backend names.
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(
            request, timeout=_LIVE_TIMEOUT_SECONDS
        ) as response:
            status = getattr(response, "status", response.getcode())
            if not (200 <= int(status) < 300):
                raise RuntimeError(
                    f"ops backend returned HTTP {status} (expected 2xx)"
                )
            raw = response.read(_MAX_LIVE_BODY_BYTES + 1)
    except urllib.error.HTTPError as exc:
        # Non-2xx that urllib raises (e.g. 500). Do NOT include the response
        # body (may echo request context); the status alone is diagnostic.
        raise RuntimeError(
            f"ops backend returned HTTP {exc.code} (expected 2xx)"
        ) from exc
    except urllib.error.URLError as exc:
        # Timeout, DNS failure, connection refused, etc.
        raise RuntimeError(
            f"ops backend request failed: {exc.reason}"
        ) from exc

    if len(raw) > _MAX_LIVE_BODY_BYTES:
        raise RuntimeError(
            f"ops backend reply exceeds {_MAX_LIVE_BODY_BYTES} bytes; refusing to parse"
        )

    try:
        reply = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError(
            f"ops backend returned a non-JSON / malformed body: {exc}"
        ) from exc

    return _normalize_live_reply(selector, reply)


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
