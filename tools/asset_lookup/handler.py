"""asset_lookup — exposure / asset-surface lookup tool (reference template).

SecOps purpose
--------------
Attack-path reasoning (see ``specialists/attack-mapper``) needs a picture of
the environment it is reasoning over: which hosts exist, which services/ports
they expose, whether any exposed service carries a *known-vulnerable* flag, and
what *trust edges* connect one host to another (SSH key reuse, shared admin
credentials, flat network segments, service-account chains). Given an asset or
subnet query, this tool returns that **exposure surface** in a normalized,
deterministic structure the mapper's graph reasoning consumes directly.

This is a *reference implementation* for wiring into an Amazon Bedrock
AgentCore Gateway as an MCP target (Lambda-style handler). It runs entirely
OFFLINE by default from a small embedded, synthetic fixture environment; a live
backend (CMDB / asset-inventory / scanner API) is opted into later via
``ASSET_LOOKUP_LIVE=1``. That keeps the template testable in CI with no
network, no secrets, and no external dependencies.

What is real vs. stubbed
------------------------
- The OFFLINE surface is REAL, deterministic data: the same query always yields
  the same hosts/services/edges. It is *synthetic* (no real environment), but it
  is a faithful shape for the mapper to reason over — nothing is fabricated at
  call time.
- The LIVE path is a REAL stdlib HTTP client (``urllib.request``, no third-party
  dependencies). When ``ASSET_LOOKUP_LIVE=1`` it POSTs the validated query as
  JSON to ``ASSET_LOOKUP_URL`` (with an optional ``ASSET_LOOKUP_TOKEN`` bearer)
  and normalizes the JSON reply into the exact same surface shape as the stub,
  tagged ``source="live"``. On any failure (missing URL, timeout, non-2xx,
  malformed JSON, unreachable backend) it returns an explicit ``upstream_error``
  and NEVER silently falls back to fixtures — so an operator who *opts into*
  live and gets nothing learns why.

Egress & secrets posture
------------------------
- Egress is CONTROLLED. A live backend call happens only when
  ``ASSET_LOOKUP_LIVE=1`` AND the runtime network policy permits egress. In the
  default (offline) mode there is zero network I/O.
- Secrets are CONTROLLED. Any backend endpoint/token is read only from the
  environment (``ASSET_LOOKUP_URL`` / ``ASSET_LOOKUP_TOKEN``) — never hardcoded,
  logged, or echoed back in responses.
- Execution role / region are referenced via the standard harness environment
  variables ``SENTINEL_EXECUTION_ROLE_ARN``, ``SENTINEL_REGION`` and
  ``AWS_PROFILE`` (never hardcoded account IDs or ARNs).

Input contract
--------------
event = {"query": "10.0.0.0/24"}   # a subnet in CIDR form, or
event = {"query": "web-01"}        # a single asset/host id, or
event = {"query": "*"}             # the whole known surface

Output contract (on success)
----------------------------
{
    "ok": True,
    "source": "stub" | "live",
    "query": "10.0.0.0/24",
    "surface": {
        "hosts": [
            {
                "id": "web-01",
                "subnet": "10.0.0.0/24",
                "internet_exposed": True,
                "services": [
                    {"port": 443, "proto": "tcp", "name": "https",
                     "known_vuln": True, "cve_id": "CVE-2021-44228"}
                ],
            },
            ...
        ],
        # Directed trust edges: an attacker who controls ``src`` can pivot to
        # ``dst`` via ``kind`` (ssh_key_reuse / shared_admin_cred / flat_network
        # / service_account). These are what turn a single foothold into a chain.
        "trust_edges": [
            {"src": "web-01", "dst": "app-01", "kind": "ssh_key_reuse"},
            ...
        ],
    },
}
"""

from __future__ import annotations

import ipaddress
import json
import os
import urllib.error
import urllib.request
from typing import Any, Dict, List

# Bound the live backend call so a hung/slow upstream can never wedge the tool.
_LIVE_TIMEOUT_SECS = 10.0
# Cap the response body we will read/parse so a hostile or misconfigured
# backend cannot exhaust memory. 8 MiB is generous for an exposure surface.
_LIVE_MAX_BYTES = 8 * 1024 * 1024

# A query is either a single asset id token, a CIDR subnet, or the "*" wildcard.
# Asset ids are conservative: lowercase alnum plus dash/underscore/dot.
_MAX_QUERY_LEN = 128


# --------------------------------------------------------------------------
# Offline fixture environment (synthetic, deterministic).
#
# A small three-tier network with one obvious high-risk chain and one
# fully-patched host, so the attack-path reasoner has both a positive and a
# negative case to work over:
#   web-01  (internet-exposed https, known-vuln Log4Shell)
#     └─ ssh_key_reuse ─▶ app-01  (internal app tier)
#           └─ shared_admin_cred ─▶ db-01  (crown-jewel database)
#   bastion-01 (internet-exposed ssh, fully patched — no known_vuln)
# --------------------------------------------------------------------------
_STUB_HOSTS: Dict[str, Dict[str, Any]] = {
    "web-01": {
        "id": "web-01",
        "subnet": "10.0.0.0/24",
        "internet_exposed": True,
        "services": [
            {
                "port": 443,
                "proto": "tcp",
                "name": "https",
                "known_vuln": True,
                "cve_id": "CVE-2021-44228",
            },
            {
                "port": 22,
                "proto": "tcp",
                "name": "ssh",
                "known_vuln": False,
                "cve_id": None,
            },
        ],
    },
    "app-01": {
        "id": "app-01",
        "subnet": "10.0.1.0/24",
        "internet_exposed": False,
        "services": [
            {
                "port": 8080,
                "proto": "tcp",
                "name": "http-app",
                "known_vuln": False,
                "cve_id": None,
            },
        ],
    },
    "db-01": {
        "id": "db-01",
        "subnet": "10.0.2.0/24",
        "internet_exposed": False,
        "services": [
            {
                "port": 5432,
                "proto": "tcp",
                "name": "postgres",
                "known_vuln": False,
                "cve_id": None,
            },
        ],
    },
    "bastion-01": {
        "id": "bastion-01",
        "subnet": "10.0.0.0/24",
        "internet_exposed": True,
        "services": [
            {
                "port": 22,
                "proto": "tcp",
                "name": "ssh",
                "known_vuln": False,
                "cve_id": None,
            },
        ],
    },
}

# Directed trust edges between the fixture hosts.
_STUB_EDGES: List[Dict[str, str]] = [
    {"src": "web-01", "dst": "app-01", "kind": "ssh_key_reuse"},
    {"src": "app-01", "dst": "db-01", "kind": "shared_admin_cred"},
    # bastion-01 sits in the same flat segment as web-01 but leads nowhere
    # sensitive on its own — included so the reasoner must not over-claim.
    {"src": "bastion-01", "dst": "web-01", "kind": "flat_network"},
]


def _validate(event: Dict[str, Any]) -> str:
    """Validate input and return the normalized query string.

    A query is a single host id, a CIDR subnet, or ``*`` (whole surface). We
    validate shape here so the reasoning layer never sees malformed input; a
    malformed CIDR or an over-long token is a ``validation_error``, never a
    silent empty result.
    """
    if not isinstance(event, dict):
        raise ValueError("event must be a dict")
    query = event.get("query")
    if not isinstance(query, str) or not query.strip():
        raise ValueError("missing required non-empty string field 'query'")
    query = query.strip()
    if len(query) > _MAX_QUERY_LEN:
        raise ValueError(
            f"'query' too long ({len(query)} > {_MAX_QUERY_LEN} chars)"
        )
    if query == "*":
        return query
    # A CIDR / IP query must parse as a network; surface the parse error rather
    # than treating a typo'd subnet as a (never-matching) host id.
    if "/" in query:
        try:
            ipaddress.ip_network(query, strict=False)
        except ValueError as exc:
            raise ValueError(f"invalid subnet query {query!r}: {exc}") from exc
        return query
    # Otherwise it is a host-id token; keep the character set conservative.
    if not all(c.isalnum() or c in "-_." for c in query):
        raise ValueError(
            f"invalid asset id {query!r}; expected alnum plus '-_.' or a CIDR"
        )
    return query


def _select_hosts(query: str) -> List[Dict[str, Any]]:
    """Return the fixture hosts matching a validated query (deterministic).

    Matching rules:
      - ``*``            -> every known host.
      - a CIDR / subnet  -> every host whose subnet is a subnet-of or equal to
                            the query network (so a /16 query returns /24 hosts).
      - a host id        -> that single host, if known.
    Results are sorted by host id so output ordering is stable.
    """
    if query == "*":
        selected = list(_STUB_HOSTS.values())
    elif "/" in query or _looks_like_ip(query):
        q_net = ipaddress.ip_network(query, strict=False)
        selected = [
            host
            for host in _STUB_HOSTS.values()
            if ipaddress.ip_network(host["subnet"], strict=False).subnet_of(q_net)
            or ipaddress.ip_network(host["subnet"], strict=False) == q_net
        ]
    else:
        host = _STUB_HOSTS.get(query)
        selected = [host] if host is not None else []
    return sorted(selected, key=lambda h: h["id"])


def _looks_like_ip(query: str) -> bool:
    """WHY: a bare IP (no ``/``) is still a network query, not a host id."""
    try:
        ipaddress.ip_address(query)
        return True
    except ValueError:
        return False


def _select_edges(host_ids: set[str]) -> List[Dict[str, str]]:
    """Return trust edges whose *source* is in the selected host set.

    We keep an edge when the attacker's current foothold (``src``) is in scope;
    the destination may be out of the queried subnet (a pivot *out* of the
    surface is exactly the interesting case for the reasoner).
    """
    return [dict(e) for e in _STUB_EDGES if e["src"] in host_ids]


def _normalize_service(raw: Any) -> Dict[str, Any]:
    """Normalize one backend service record into the stub's service shape.

    We coerce into exactly the fields the reasoner consumes
    (``port``/``proto``/``name``/``known_vuln``/``cve_id``) so a live backend
    with extra or differently-typed fields still yields the SAME contract the
    offline surface produces. A missing/absent field is filled with a
    conservative default (never fabricated as vulnerable): ``known_vuln``
    defaults to False and ``cve_id`` to None.
    """
    if not isinstance(raw, dict):
        raise ValueError(f"service entry must be an object, got {type(raw).__name__}")
    port = raw.get("port")
    return {
        "port": port,
        "proto": raw.get("proto"),
        "name": raw.get("name"),
        "known_vuln": bool(raw.get("known_vuln", False)),
        "cve_id": raw.get("cve_id"),
    }


def _normalize_host(raw: Any) -> Dict[str, Any]:
    """Normalize one backend host record into the stub's host shape."""
    if not isinstance(raw, dict):
        raise ValueError(f"host entry must be an object, got {type(raw).__name__}")
    services_raw = raw.get("services", [])
    if not isinstance(services_raw, list):
        raise ValueError("host 'services' must be a list")
    return {
        "id": raw.get("id"),
        "subnet": raw.get("subnet"),
        "internet_exposed": bool(raw.get("internet_exposed", False)),
        "services": [_normalize_service(s) for s in services_raw],
    }


def _normalize_edge(raw: Any) -> Dict[str, Any]:
    """Normalize one backend trust-edge record into the stub's edge shape."""
    if not isinstance(raw, dict):
        raise ValueError(f"trust_edge entry must be an object, got {type(raw).__name__}")
    return {"src": raw.get("src"), "dst": raw.get("dst"), "kind": raw.get("kind")}


def _normalize_surface(payload: Any) -> Dict[str, Any]:
    """Map an arbitrary backend JSON reply into the exact stub surface shape.

    Accepts either a bare surface object (``{"hosts": [...], "trust_edges": [...]}``)
    or a wrapped one (``{"surface": {...}}``) so the client tolerates a couple of
    common backend envelopes without fabricating data. Anything that is not a
    JSON object, or whose hosts/edges are not lists, is a hard error surfaced to
    the caller as ``upstream_error`` — we never coerce a malformed reply into a
    (misleadingly empty) success.
    """
    if not isinstance(payload, dict):
        raise ValueError(
            f"backend reply must be a JSON object, got {type(payload).__name__}"
        )
    surface = payload.get("surface", payload)
    if not isinstance(surface, dict):
        raise ValueError("backend 'surface' must be an object")
    hosts_raw = surface.get("hosts", [])
    edges_raw = surface.get("trust_edges", [])
    if not isinstance(hosts_raw, list):
        raise ValueError("backend 'hosts' must be a list")
    if not isinstance(edges_raw, list):
        raise ValueError("backend 'trust_edges' must be a list")
    return {
        "hosts": [_normalize_host(h) for h in hosts_raw],
        "trust_edges": [_normalize_edge(e) for e in edges_raw],
    }


def _fetch_live(query: str) -> Dict[str, Any]:
    """Fetch the exposure surface from a live asset/CMDB backend over HTTP.

    Only reached when ``ASSET_LOOKUP_LIVE=1``. This is a REAL stdlib client
    (``urllib.request`` — no third-party dependencies): it POSTs the validated
    query as a JSON body to ``ASSET_LOOKUP_URL`` and normalizes the JSON reply
    into the SAME surface shape the offline stub returns. It never silently
    falls back to fixtures, so opting into live and getting nothing back is
    never mistaken for "no assets".

    Secrets posture: the endpoint comes from ``ASSET_LOOKUP_URL`` and an
    optional bearer credential from ``ASSET_LOOKUP_TOKEN`` — both read from the
    environment only, never hardcoded, and never logged or echoed in errors.

    Failure modes (missing URL, timeout, non-2xx, connection refused, malformed
    JSON) all raise, so the handler turns them into an explicit
    ``upstream_error`` rather than a swallowed exception or a fabricated
    surface.
    """
    url = os.environ.get("ASSET_LOOKUP_URL")
    if not url:
        raise RuntimeError(
            "ASSET_LOOKUP_LIVE=1 but ASSET_LOOKUP_URL is not set; no backend to "
            "query. Unset ASSET_LOOKUP_LIVE to use the offline fixture surface."
        )

    body = json.dumps({"query": query}).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    # Bearer auth is applied ONLY from the environment; the token value is never
    # logged or placed in an error message.
    token = os.environ.get("ASSET_LOOKUP_TOKEN")
    if token:
        request.add_header("Authorization", f"Bearer {token}")

    try:
        with urllib.request.urlopen(request, timeout=_LIVE_TIMEOUT_SECS) as resp:
            status = getattr(resp, "status", None) or resp.getcode()
            if not (200 <= int(status) < 300):
                raise RuntimeError(f"backend returned HTTP {status}")
            raw = resp.read(_LIVE_MAX_BYTES + 1)
    except urllib.error.HTTPError as exc:
        # Non-2xx responses raise HTTPError; surface the status, not the body
        # (which could echo sensitive detail).
        raise RuntimeError(f"backend returned HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        # DNS failure, connection refused, timeout, TLS error, etc. ``exc.reason``
        # describes the transport fault without leaking the token.
        raise RuntimeError(f"backend request failed: {exc.reason}") from exc
    except TimeoutError as exc:  # socket timeout can surface directly on 3.10+
        raise RuntimeError("backend request timed out") from exc

    if len(raw) > _LIVE_MAX_BYTES:
        raise RuntimeError(
            f"backend reply exceeds {_LIVE_MAX_BYTES} bytes; refusing to parse"
        )

    try:
        payload = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise RuntimeError(f"backend returned malformed JSON: {exc}") from exc

    return _normalize_surface(payload)


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Return the exposure surface (hosts + services + trust edges) for a query.

    Runs offline (deterministic synthetic fixture) by default; performs a live
    backend call only when the environment opts in via ``ASSET_LOOKUP_LIVE=1``.
    All egress and secrets are controlled through environment configuration,
    never hardcoded.
    """
    try:
        query = _validate(event)
    except ValueError as exc:
        return {"ok": False, "error": "validation_error", "message": str(exc)}

    live = os.environ.get("ASSET_LOOKUP_LIVE") == "1"
    try:
        if live:
            surface = _fetch_live(query)
            source = "live"
        else:
            hosts = _select_hosts(query)
            edges = _select_edges({h["id"] for h in hosts})
            surface = {"hosts": hosts, "trust_edges": edges}
            source = "stub"
    except Exception as exc:  # backend / parse failures — surface, never swallow
        return {"ok": False, "error": "upstream_error", "message": str(exc)}

    return {"ok": True, "source": source, "query": query, "surface": surface}


if __name__ == "__main__":
    import json

    print(json.dumps(handler({"query": "*"}, None), indent=2))
