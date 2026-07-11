"""enrich_ioc — IOC reputation / enrichment tool (mock-world reference stub).

.. warning::
   **This is CLEARLY-LABELED MOCK DATA for POC / testing only.** It is *not*
   real threat intelligence and *not* a real reputation feed. Every indicator
   it scores is drawn from ``mockdata.world`` — fictional but well-formed
   values (RFC 5737 documentation IPs, ``example.test`` / ``example.com``
   domains, fabricated-but-valid-length SHA-256 hashes). Do NOT treat any
   verdict here as a real-world judgement about a real IP/domain/file.

SecOps purpose
--------------
Alert triage starts with indicators of compromise (IOCs): a src_ip on an alert,
a domain a host beaconed to, a file hash EDR flagged. Before an analyst (or an
agent) can decide "act or dismiss", each indicator needs a *reputation* — is it
known-bad, how confident, what category, and crucially *what else in the estate
it relates to*. Given one indicator or a batch, this tool returns that
normalized reputation view, reading the SAME fictional world every other
data-plane tool reads (``mockdata.world``) so enrichment cross-links cleanly to
the SIEM alert and the asset surface.

The headline cross-link (the "Log4Shell story")
------------------------------------------------
The C2 IP ``203.0.113.66`` tied to the Log4Shell alert (``alert-1001``) MUST
resolve to a **malicious** verdict with ``related_hosts`` including ``web-01`` —
that is the spine that lets triage pivot indicator → asset. This is asserted by
the offline test and by ``tests/test_mockworld.py``.

What is real vs. stubbed
------------------------
- The OFFLINE reputation is REAL, deterministic data: the same indicator always
  yields the same type/category/confidence/verdict/related_hosts. It is
  *synthetic* (from ``mockdata.world``), but nothing is fabricated at call time.
  An indicator NOT in the mock set returns ``known: false`` / ``verdict:
  "unknown"`` — never a crash, never a fabricated score.
- The LIVE path is a real, dependency-free client: with ``ENRICH_IOC_LIVE=1``
  it POSTs the validated indicators as JSON to ``ENRICH_IOC_URL`` (with an
  optional ``Bearer`` token from ``ENRICH_IOC_TOKEN``) using only stdlib
  ``urllib.request`` — no third-party deps — then normalizes the JSON reply
  into the SAME output contract as the stub (``source="live"``). Any failure —
  missing URL, connection error, timeout, non-2xx status, or malformed JSON —
  is returned as ``{ok: False, error: "upstream_error", message}``. It NEVER
  silently falls back to the mock data, so opting into live and getting nothing
  back is never mistaken for "clean".

Egress & secrets posture
------------------------
- Egress is CONTROLLED. A live backend call happens only when
  ``ENRICH_IOC_LIVE=1`` AND the runtime network policy permits egress. In the
  default (offline) mode there is zero network I/O.
- Secrets are CONTROLLED. Any backend endpoint/token is read only from the
  environment (``ENRICH_IOC_URL`` / ``ENRICH_IOC_TOKEN``) — never hardcoded,
  logged, or echoed back in responses.
- Execution role / region are referenced via the standard harness environment
  variables ``SENTINEL_EXECUTION_ROLE_ARN``, ``SENTINEL_REGION`` and
  ``AWS_PROFILE`` (never hardcoded account IDs or ARNs).

Input contract
--------------
event = {"indicator": "203.0.113.66"}              # a single indicator, or
event = {"indicators": ["203.0.113.66", "..."]}    # a batch (list of strings)

The indicator TYPE (ip / domain / sha256) is auto-detected by shape; the caller
does not have to declare it.

Output contract (on success)
----------------------------
{
    "ok": True,
    "source": "stub" | "live",
    "results": {
        "203.0.113.66": {
            "type": "ip",              # ip | domain | sha256
            "known": True,             # was it in the mock set?
            "threat_category": "c2",   # c2 | scanner | phishing | malware | ...
            "confidence": "high",      # high | medium | low | None (unknown)
            "first_seen": "2026-06-28T00:00:00Z",  # or None (unknown)
            "related_hosts": ["web-01"],           # hosts it was seen against
            "verdict": "malicious",    # malicious | suspicious | benign | unknown
        },
        ...
    },
}

Output contract (on validation failure)
----------------------------------------
{"ok": False, "error": "validation_error", "message": "..."}
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import sys
import urllib.error
import urllib.request
from typing import Any, Dict, List
from urllib.parse import urlsplit

# This tool reads the shared single-source-of-truth world in ``mockdata.world``.
# When imported normally (via the harness / pytest, which put the repo root on
# sys.path) the plain import works. When run as a bare script from an arbitrary
# cwd (``python handler.py``) the repo root is NOT on sys.path, so bootstrap it
# here (tools/enrich_ioc/ -> repo root) BEFORE the import — keeping the __main__
# demo runnable without changing how the harness imports the tool.
_REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from mockdata.world import load_world  # noqa: E402  (import after path bootstrap)

# A single indicator string is bounded so a caller cannot smuggle a huge blob.
_MAX_INDICATOR_LEN = 256
# A batch is bounded so one call cannot enumerate an unbounded list.
_MAX_BATCH = 256

# Live backend HTTP timeout (seconds). Bounded so a hung/slow upstream surfaces
# as an ``upstream_error`` rather than blocking the caller indefinitely.
_LIVE_TIMEOUT_S = 10
# Cap the live response body we will read/parse so a hostile or broken backend
# cannot force us to buffer an unbounded reply.
_MAX_LIVE_BODY_BYTES = 4 * 1024 * 1024

# SHA-256 is exactly 64 hex chars; that shape is unambiguous vs. IP/domain.
_SHA256_RE = re.compile(r"\A[0-9a-fA-F]{64}\Z")
# A conservative domain shape: labels of alnum/hyphen separated by dots, with a
# final alphabetic TLD. This is intentionally strict enough to reject junk but
# lenient enough for the .test/.example.com fixture domains.
_DOMAIN_RE = re.compile(
    r"\A(?=.{1,253}\Z)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,63}\Z"
)

# Verdict mapping. WHY explicit rather than derived: a security verdict is a
# judgement call, so we make the category+confidence -> verdict policy visible
# and testable instead of hiding it in ad-hoc conditionals.
#   - benign category            -> "benign" (known-good, dismiss)
#   - malicious-ish category with high confidence   -> "malicious"
#   - malicious-ish category with medium/low conf   -> "suspicious"
#   - low-signal categories (anonymizer/scanner)    -> "suspicious" (never
#        auto-"malicious": a Tor exit or opportunistic scanner is not, by
#        itself, a confirmed compromise)
_BENIGN_CATEGORIES = {"benign"}
# Categories that are inherently low-signal: cap their verdict at "suspicious"
# even if the fixture confidence is high, so triage does not over-escalate.
_LOW_SIGNAL_CATEGORIES = {"anonymizer", "scanner"}


def _classify(indicator: str) -> str:
    """Auto-detect the indicator TYPE from its shape (ip / domain / sha256).

    WHY shape-based: the caller passes a bare string; forcing them to also
    declare the type would be redundant and error-prone. Order matters — a
    64-hex hash must be checked before the domain/ip branches so it is never
    misread. Raises ``ValueError`` for anything that is not a recognizable
    indicator so a malformed value is a ``validation_error``, not a silent
    unknown.
    """
    if _SHA256_RE.match(indicator):
        return "sha256"
    # An IP (v4 or v6) is a network address, not a domain. Check before domain
    # so "203.0.113.66" is not mistaken for a dotted domain label.
    if _looks_like_ip(indicator):
        return "ip"
    if _DOMAIN_RE.match(indicator):
        return "domain"
    raise ValueError(
        f"unrecognized indicator shape {indicator!r}; expected an IP, a domain, "
        "or a 64-char SHA-256 hash"
    )


def _looks_like_ip(indicator: str) -> bool:
    """True if the string parses as an IPv4/IPv6 address."""
    import ipaddress

    try:
        ipaddress.ip_address(indicator)
        return True
    except ValueError:
        return False


def _derive_verdict(threat_category: str, confidence: str) -> str:
    """Map a fixture (category, confidence) pair to a triage verdict.

    Deterministic policy (see the module-level constants for the rationale):
      - benign category                       -> "benign"
      - low-signal category (scanner/tor)      -> "suspicious" (never malicious)
      - high confidence otherwise              -> "malicious"
      - medium / low confidence otherwise      -> "suspicious"
    """
    if threat_category in _BENIGN_CATEGORIES:
        return "benign"
    if threat_category in _LOW_SIGNAL_CATEGORIES:
        return "suspicious"
    if confidence == "high":
        return "malicious"
    return "suspicious"


def _build_index() -> Dict[str, Dict[str, Any]]:
    """Build a value -> ioc-record lookup from the shared mock world.

    Read from ``load_world()`` (a fresh deep copy) so this tool never mutates
    the single source of truth and stays consistent with the SIEM/asset planes.
    """
    world = load_world()
    return {ioc["value"]: ioc for ioc in world["iocs"]}


def _enrich_one(indicator: str, index: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """Return the reputation record for a single (already-validated) indicator.

    A hit in the mock set yields the full reputation; a miss yields an explicit
    ``known: false`` / ``verdict: "unknown"`` record (the type is still
    classified from the shape) — never a crash, never a fabricated score.
    """
    ioc_type = _classify(indicator)
    record = index.get(indicator)
    if record is None:
        return {
            "type": ioc_type,
            "known": False,
            "threat_category": None,
            "confidence": None,
            "first_seen": None,
            "related_hosts": [],
            "verdict": "unknown",
        }
    return {
        "type": record["type"],
        "known": True,
        "threat_category": record["threat_category"],
        "confidence": record["confidence"],
        "first_seen": record["first_seen"],
        # ``relates_to`` in the world model is the host(s) the IOC was observed
        # against — surfaced here as ``related_hosts`` for the pivot to assets.
        "related_hosts": list(record.get("relates_to", [])),
        "verdict": _derive_verdict(record["threat_category"], record["confidence"]),
    }


def _validate(event: Dict[str, Any]) -> List[str]:
    """Validate input and return the normalized list of indicator strings.

    Accepts either ``{"indicator": "<str>"}`` (single) or
    ``{"indicators": [<str>, ...]}`` (batch). We validate shape here so the
    reasoning layer never sees malformed input; a non-string, blank, or
    over-long indicator is a ``validation_error`` (raised), never a silent skip.
    """
    if not isinstance(event, dict):
        raise ValueError("event must be a dict")

    has_single = "indicator" in event
    has_batch = "indicators" in event
    if has_single and has_batch:
        raise ValueError(
            "provide exactly one of 'indicator' or 'indicators', not both"
        )
    if not has_single and not has_batch:
        raise ValueError(
            "missing required field: 'indicator' (str) or 'indicators' (list[str])"
        )

    if has_single:
        raw = [event["indicator"]]
    else:
        raw = event["indicators"]
        if not isinstance(raw, list):
            raise ValueError("'indicators' must be a list of strings")
        if not raw:
            raise ValueError("'indicators' must be a non-empty list")
        if len(raw) > _MAX_BATCH:
            raise ValueError(
                f"too many indicators ({len(raw)} > {_MAX_BATCH})"
            )

    normalized: List[str] = []
    for item in raw:
        if not isinstance(item, str) or not item.strip():
            raise ValueError(
                f"each indicator must be a non-empty string; got {item!r}"
            )
        value = item.strip()
        if len(value) > _MAX_INDICATOR_LEN:
            raise ValueError(
                f"indicator too long ({len(value)} > {_MAX_INDICATOR_LEN} chars)"
            )
        # Reject unrecognizable shapes up front so a typo is a validation_error
        # rather than a misleading known:false "unknown" result.
        _classify(value)
        normalized.append(value)
    return normalized


def _normalize_live_record(indicator: str, raw: Any) -> Dict[str, Any]:
    """Normalize ONE backend record into the tool's output contract.

    The live backend is pluggable, so its raw per-indicator payload may be
    loosely shaped. We coerce it into the SAME record shape the offline stub
    returns (type / known / threat_category / confidence / first_seen /
    related_hosts / verdict) so downstream triage cannot tell the planes apart.

    WHY defensive coercion (not blind trust): a backend field being absent or a
    wrong JSON type must never crash the handler; missing signal degrades to an
    explicit ``known: false`` / ``verdict: "unknown"`` — never a fabricated
    score. A ``raw`` that is not an object is treated as "no record".
    """
    if not isinstance(raw, dict):
        # Backend had nothing usable for this indicator: mirror a stub miss,
        # still classifying the type from the (already-validated) shape.
        return {
            "type": _classify(indicator),
            "known": False,
            "threat_category": None,
            "confidence": None,
            "first_seen": None,
            "related_hosts": [],
            "verdict": "unknown",
        }

    # Type: trust the backend only if it names a known type; else derive from
    # the indicator shape so the field is always one of ip/domain/sha256.
    raw_type = raw.get("type")
    ioc_type = raw_type if raw_type in ("ip", "domain", "sha256") else _classify(indicator)

    threat_category = raw.get("threat_category")
    if threat_category is None:
        threat_category = raw.get("category")  # tolerate a common alias
    confidence = raw.get("confidence")
    first_seen = raw.get("first_seen")

    # related_hosts: accept the contract name or the world-model alias; coerce
    # to a list of strings, dropping anything non-string so a malformed entry
    # cannot corrupt the pivot-to-asset list.
    raw_hosts = raw.get("related_hosts")
    if raw_hosts is None:
        raw_hosts = raw.get("relates_to")
    related_hosts = [h for h in raw_hosts if isinstance(h, str)] if isinstance(raw_hosts, list) else []

    # known: honor an explicit boolean; otherwise infer from whether the
    # backend actually returned a category signal.
    raw_known = raw.get("known")
    known = raw_known if isinstance(raw_known, bool) else (threat_category is not None)

    # verdict: honor an explicit backend verdict if it is one of the allowed
    # values; else derive it with the SAME policy the stub uses, or fall back to
    # "unknown" when there is no category to judge.
    verdict = raw.get("verdict")
    if verdict not in ("malicious", "suspicious", "benign", "unknown"):
        if isinstance(threat_category, str) and isinstance(confidence, str):
            verdict = _derive_verdict(threat_category, confidence)
        elif known and isinstance(threat_category, str):
            # Category present but confidence missing: treat conservatively.
            verdict = _derive_verdict(threat_category, "low")
        else:
            verdict = "unknown"

    return {
        "type": ioc_type,
        "known": known,
        "threat_category": threat_category,
        "confidence": confidence,
        "first_seen": first_seen,
        "related_hosts": related_hosts,
        "verdict": verdict,
    }


# SSRF guard: schemes an operator-configured backend URL may use. Only plain
# HTTP(S) egress is permitted; ``file://``, ``gopher://``, ``ftp://`` etc. are
# refused so a misconfigured/hostile URL cannot read local files or reach
# non-HTTP services.
_ALLOWED_URL_SCHEMES = frozenset({"https", "http"})


def _assert_safe_url(url: str) -> None:
    """Refuse an outbound URL that is not plain HTTP(S) to a routable host.

    SSRF/exfiltration hardening applied before ANY live request opens: enforce a
    scheme allowlist (https/http only) and REFUSE link-local, loopback-to-cloud
    metadata, and other non-routable targets — notably the cloud metadata
    endpoint ``169.254.169.254`` and ``file://``. Raises ``RuntimeError`` on a
    rejected URL so the handler maps it to ``upstream_error`` (never a silent
    fallback). Hostnames that are not IP literals are allowed through (DNS is not
    resolved here — that is the runtime egress policy's job); only IP-literal
    hosts are range-checked, which deterministically blocks the metadata IP.
    """
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
    # Range-check IP-literal hosts. A bracketed IPv6 or dotted IPv4 literal is
    # checked against the block ranges below; the metadata IP is caught here.
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return  # not an IP literal — leave DNS-name egress to the network policy
    if (
        ip.is_link_local          # 169.254.0.0/16 (incl. 169.254.169.254) & fe80::/10
        or ip.is_loopback         # 127.0.0.0/8, ::1
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified      # 0.0.0.0, ::
    ):
        raise RuntimeError(
            f"refusing to open URL targeting non-routable/metadata address {host!r}"
        )


def _fetch_live(indicators: List[str]) -> Dict[str, Dict[str, Any]]:
    """Fetch reputation from a live threat-intel backend over stdlib HTTP.

    Only reached when ``ENRICH_IOC_LIVE=1``. Builds a JSON ``POST`` from
    ``ENRICH_IOC_URL`` (required) with an optional ``Bearer`` token from
    ``ENRICH_IOC_TOKEN`` (env only — never hardcoded, logged, or echoed), sends
    it with :mod:`urllib.request` (stdlib only — no third-party deps), and
    normalizes the JSON reply into the SAME per-indicator contract the offline
    stub returns.

    Every failure mode is surfaced as an exception (the handler maps it to
    ``{ok: False, error: "upstream_error", message}``) — a missing URL,
    connection refused, DNS failure, timeout, non-2xx status, an over-large
    body, or malformed JSON. It NEVER silently falls back to the mock world, so
    opting into live and getting nothing back is never mistaken for "clean".
    """
    url = os.environ.get("ENRICH_IOC_URL")
    if not url:
        raise RuntimeError(
            "ENRICH_IOC_LIVE=1 but ENRICH_IOC_URL is not set; no backend to "
            "query. Unset ENRICH_IOC_LIVE to use the offline mock reputation."
        )

    payload = json.dumps({"indicators": indicators}).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    # Secret handling: the bearer token is read ONLY from the environment and
    # placed solely into the outbound Authorization header. It is never logged,
    # echoed into a response, or interpolated into any error message.
    token = os.environ.get("ENRICH_IOC_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    request = urllib.request.Request(
        url, data=payload, headers=headers, method="POST"
    )

    try:
        with urllib.request.urlopen(request, timeout=_LIVE_TIMEOUT_S) as response:
            # urlopen raises HTTPError for non-2xx, so reaching here is 2xx.
            body = response.read(_MAX_LIVE_BODY_BYTES + 1)
    except urllib.error.HTTPError as exc:  # non-2xx status
        raise RuntimeError(
            f"IOC reputation backend returned HTTP {exc.code}"
        ) from exc
    except urllib.error.URLError as exc:  # connection refused, DNS, timeout
        # ``reason`` may be an OSError (e.g. connection refused) or a message.
        raise RuntimeError(
            f"IOC reputation backend request failed: {exc.reason}"
        ) from exc
    except TimeoutError as exc:  # socket-level timeout, surfaced explicitly
        raise RuntimeError(
            "IOC reputation backend request timed out"
        ) from exc

    if len(body) > _MAX_LIVE_BODY_BYTES:
        raise RuntimeError(
            "IOC reputation backend response exceeded "
            f"{_MAX_LIVE_BODY_BYTES} bytes"
        )

    try:
        parsed = json.loads(body.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise RuntimeError(
            f"IOC reputation backend returned malformed JSON: {exc}"
        ) from exc

    if not isinstance(parsed, dict):
        raise RuntimeError(
            "IOC reputation backend returned a non-object JSON payload"
        )
    # Accept either an envelope ``{"results": {ind: rec}}`` or a flat
    # ``{ind: rec}`` map. Anything else is a contract violation.
    raw_results = parsed["results"] if "results" in parsed else parsed
    if not isinstance(raw_results, dict):
        raise RuntimeError(
            "IOC reputation backend 'results' was not a JSON object"
        )

    # Normalize per requested indicator so the output key set is exactly what
    # the caller asked for (a backend omission degrades to known:false/unknown,
    # never a missing key or a crash).
    return {
        indicator: _normalize_live_record(indicator, raw_results.get(indicator))
        for indicator in indicators
    }


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Enrich one or a batch of IOCs with a mock reputation verdict.

    Runs offline (deterministic mock world) by default; performs a live backend
    call only when the environment opts in via ``ENRICH_IOC_LIVE=1``. All egress
    and secrets are controlled through environment configuration, never
    hardcoded. Indicators not in the mock set resolve to ``known: false`` /
    ``verdict: "unknown"`` — never a crash.
    """
    try:
        indicators = _validate(event)
    except ValueError as exc:
        return {"ok": False, "error": "validation_error", "message": str(exc)}

    live = os.environ.get("ENRICH_IOC_LIVE") == "1"
    try:
        if live:
            results = _fetch_live(indicators)
            source = "live"
        else:
            index = _build_index()
            # dict preserves first-seen order; a repeated indicator collapses to
            # one entry (same key) which is the correct, deterministic behavior.
            results = {ind: _enrich_one(ind, index) for ind in indicators}
            source = "stub"
    except Exception as exc:  # backend failures — surface, never swallow
        return {"ok": False, "error": "upstream_error", "message": str(exc)}

    return {"ok": True, "source": source, "results": results}


if __name__ == "__main__":
    import json

    # Demo: the Log4Shell C2 IP, a benign CDN domain, a malware hash, and an
    # indicator that is NOT in the mock set (unknown).
    demo_event = {
        "indicators": [
            "203.0.113.66",              # C2 -> malicious, related web-01
            "assets.example.com",        # benign CDN
            "a" * 63 + "1",              # known malware hash
            "192.0.2.99",                # not in the mock set -> unknown
        ]
    }
    print(json.dumps(handler(demo_event, None), indent=2))
