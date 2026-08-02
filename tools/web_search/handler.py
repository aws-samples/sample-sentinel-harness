"""web_search — egress-controlled text search tool (reference template).

SecOps purpose
--------------
A security operations team researching a threat (a new CVE, a malware
family, an ATT&CK technique, an IOC) frequently needs open-web context:
vendor advisories, blog write-ups, news of active exploitation. This tool
provides that as TEXT ONLY. It returns titles, URLs, and short snippets so
an agent can reason over them and cite sources.

Egress-control rationale (why this tool is deliberately restricted)
-------------------------------------------------------------------
Threat research routinely brushes up against hostile content. If an agent
tool could fetch arbitrary bytes, an attacker-controlled page could serve a
malicious binary, an exploit payload, or a huge response — and the tool
would happily pull it into the runtime. That turns a research helper into a
malware-delivery / SSRF primitive.

To prevent that, this tool enforces the following invariants:

1. TEXT ONLY. It returns search *results* (title/url/snippet strings). It
   NEVER downloads page bodies, attachments, or binaries. There is no
   "fetch this URL" capability here by design — that belongs to a separate,
   sandboxed, content-type-gated tool if it exists at all.
2. SINGLE EGRESS CHOKEPOINT. All outbound access goes through one
   configured search endpoint (``WEB_SEARCH_ENDPOINT``), not arbitrary
   hosts. In a deployment this endpoint sits behind an egress allowlist /
   NAT policy so the runtime cannot reach the wider internet directly.
3. OPT-IN LIVE MODE. Live search runs only when ``WEB_SEARCH_LIVE=1``.
   Default mode returns deterministic stub results with zero network I/O,
   so the template is CI-safe and offline by default.
4. BOUNDED. Query length and result count are capped to limit blast radius
   and cost.

Secrets posture
---------------
- The search API key is read only from ``WEB_SEARCH_API_KEY`` — never
  hardcoded, logged, or returned in responses.
- Execution role / region are referenced via
  ``SENTINEL_EXECUTION_ROLE_ARN``, ``SENTINEL_REGION`` and ``AWS_PROFILE``.

Input contract
--------------
event = {"query": "Log4Shell active exploitation advisory", "max_results": 5}

Output contract (on success)
----------------------------
{
    "ok": True,
    "source": "stub" | "live",
    "query": "...",
    "results": [
        {"title": "...", "url": "https://...", "snippet": "..."},
        ...
    ],
    "note": "text-only; no page bodies or binaries were downloaded",
}
"""

from __future__ import annotations

import os
import urllib.request  # noqa: F401 - module-level so `_search_live` and tests can reach urllib.request.urlopen
from typing import Any, Dict, List

# The ONE egress guard (INV-EGRESS-1). Imported rather than copied: a local copy
# of this check is how the same SSRF pair reached two tools before it was
# mechanized — see sentinel_harness/egress.py.
from sentinel_harness import egress


_MAX_QUERY_LEN = 512
_MAX_RESULTS = 10
_DEFAULT_RESULTS = 5

# SSRF guard: only plain HTTP(S) egress to a routable host is permitted for the
# operator-configured WEB_SEARCH_ENDPOINT. Re-exported from `sentinel_harness.egress`
# rather than redefined, so the allowlist has one definition.
_ALLOWED_URL_SCHEMES = egress.ALLOWED_URL_SCHEMES


def _assert_safe_url(url: str) -> None:
    """Refuse an outbound URL that is not plain HTTP(S) to a routable host.

    INV-EGRESS-1: delegates to ``sentinel_harness.egress.assert_safe_url``.

    This WAS a local copy whose range check called ``ipaddress.ip_address()`` directly,
    so the alternate spellings of the cloud metadata address passed as DNS names —
    ``http://2852039166/`` (decimal), ``http://0xA9FEA9FE/`` (hex),
    ``http://0251.0376.0251.0376/`` (octal-dotted), all three 169.254.169.254.
    Reproduced against this copy in round 19.

    That matters more here than in its siblings: this tool exists to reach
    attacker-influenceable content, and its docstring above promises a SINGLE EGRESS
    CHOKEPOINT. Two checks of unequal strength are not one chokepoint.

    Not exploitable while it stood (``egress.open_checked`` re-checks downstream), but a
    staged regression for any refactor reasoning "already vetted here".

    ``EgressError`` subclasses ``RuntimeError``, so the ``upstream_error`` mapping holds.
    """
    egress.assert_safe_url(url)


def _validate(event: Dict[str, Any]) -> Dict[str, Any]:
    """Validate input; return {'query': str, 'max_results': int}."""
    if not isinstance(event, dict):
        raise ValueError("event must be a dict")

    query = event.get("query")
    if not isinstance(query, str) or not query.strip():
        raise ValueError("missing required non-empty string field 'query'")
    query = query.strip()
    if len(query) > _MAX_QUERY_LEN:
        raise ValueError(f"'query' too long; max {_MAX_QUERY_LEN} characters")

    max_results = event.get("max_results", _DEFAULT_RESULTS)
    if not isinstance(max_results, int) or isinstance(max_results, bool):
        raise ValueError("'max_results' must be an integer")
    if max_results < 1 or max_results > _MAX_RESULTS:
        raise ValueError(f"'max_results' must be between 1 and {_MAX_RESULTS}")

    return {"query": query, "max_results": max_results}


def _search_stub(query: str, max_results: int) -> List[Dict[str, str]]:
    """Deterministic offline results. Text only — no URLs are fetched."""
    results = [
        {
            "title": f"Reference result {i + 1} for: {query}",
            "url": f"https://example.org/search/{i + 1}",
            "snippet": (
                f"Offline stub snippet {i + 1} describing '{query}'. "
                "Enable WEB_SEARCH_LIVE=1 for live text search."
            ),
        }
        for i in range(max_results)
    ]
    return results


def _search_live(query: str, max_results: int) -> List[Dict[str, str]]:
    """Query the single configured search endpoint for TEXT results only.

    Reached only when WEB_SEARCH_LIVE=1. This helper deliberately parses
    only title/url/snippet fields and never follows result URLs to fetch
    their content.
    """
    import json
    import urllib.parse

    endpoint = os.environ.get("WEB_SEARCH_ENDPOINT")
    if not endpoint:
        raise RuntimeError(
            "WEB_SEARCH_LIVE=1 but WEB_SEARCH_ENDPOINT is not configured"
        )
    api_key = os.environ.get("WEB_SEARCH_API_KEY")  # optional; never hardcoded

    params = urllib.parse.urlencode({"q": query, "count": max_results})
    url = f"{endpoint}?{params}"
    # SSRF/exfil hardening: refuse a non-HTTP(S) scheme or a non-routable/metadata
    # target before opening the request (raises -> upstream_error, no silent fallback).
    _assert_safe_url(url)
    headers = {"User-Agent": "sentinel-harness", "Accept": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    _MAX_RESPONSE_BYTES = 2_000_000
    req = urllib.request.Request(url, headers=headers)
    with egress.open_checked(req, timeout=15) as resp:  # noqa: S310 (operator-configured chokepoint)
        # Read cap+1 then reject over-limit rather than silently truncating —
        # matches the reject pattern the other live-client tools use.
        raw = resp.read(_MAX_RESPONSE_BYTES + 1)
    if len(raw) > _MAX_RESPONSE_BYTES:
        raise RuntimeError(
            f"search backend reply exceeds {_MAX_RESPONSE_BYTES} bytes; refusing to parse"
        )
    data = json.loads(raw.decode("utf-8"))

    # Normalize common search-provider shapes into text-only records. Adjust
    # the field mapping to match the configured provider.
    items = (
        data.get("results")
        or data.get("web", {}).get("results")
        or data.get("items")
        or []
    )
    out: List[Dict[str, str]] = []
    for item in items[:max_results]:
        out.append(
            {
                "title": str(item.get("title", "")),
                "url": str(item.get("url") or item.get("link", "")),
                "snippet": str(
                    item.get("snippet")
                    or item.get("description")
                    or item.get("content", "")
                ),
            }
        )
    return out


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Egress-controlled, text-only open-web search.

    Returns search result metadata (title/url/snippet) only. NEVER
    downloads page bodies or binaries. Live search runs through a single
    configured endpoint only when WEB_SEARCH_LIVE=1; otherwise returns
    offline stub results with zero network I/O.
    """
    try:
        args = _validate(event)
    except ValueError as exc:
        return {"ok": False, "error": "validation_error", "message": str(exc)}

    live = os.environ.get("WEB_SEARCH_LIVE") == "1"
    try:
        if live:
            results = _search_live(args["query"], args["max_results"])
            source = "live"
        else:
            results = _search_stub(args["query"], args["max_results"])
            source = "stub"
    except Exception as exc:  # never swallow upstream failures
        return {"ok": False, "error": "upstream_error", "message": str(exc)}

    return {
        "ok": True,
        "source": source,
        "query": args["query"],
        "results": results,
        "note": "text-only; no page bodies or binaries were downloaded",
    }


if __name__ == "__main__":
    import json

    print(
        json.dumps(
            handler({"query": "Log4Shell active exploitation advisory"}, None),
            indent=2,
        )
    )
