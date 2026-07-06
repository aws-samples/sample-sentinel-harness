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
- The LIVE path is a documented, guarded stub: with ``ENRICH_IOC_LIVE=1`` it
  raises an explicit ``upstream_error`` until a concrete reputation backend
  (VirusTotal / GreyNoise / internal TIP) is wired in later. It never silently
  falls back to the mock data, so opting into live and getting nothing back is
  never mistaken for "clean".

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

import os
import re
import sys
from typing import Any, Dict, List

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


def _fetch_live(indicators: List[str]) -> Dict[str, Dict[str, Any]]:
    """Fetch reputation from a live threat-intel backend.

    Only reached when ``ENRICH_IOC_LIVE=1``. The concrete backend (VirusTotal /
    GreyNoise / an internal TIP) is wired later; until then this raises an
    explicit error rather than silently returning mock data, so opting into
    live and getting nothing back is never mistaken for "clean".
    """
    url = os.environ.get("ENRICH_IOC_URL")
    if not url:
        raise RuntimeError(
            "ENRICH_IOC_LIVE=1 but ENRICH_IOC_URL is not set; no backend to "
            "query. Unset ENRICH_IOC_LIVE to use the offline mock reputation."
        )
    # The live client is intentionally not implemented here: connecting a real
    # reputation plane is later work. Raising keeps the contract honest — we
    # never fabricate a live verdict.
    raise NotImplementedError(
        "live IOC reputation backend not wired yet; configure a concrete client "
        f"for {url!r} before setting ENRICH_IOC_LIVE=1"
    )


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
