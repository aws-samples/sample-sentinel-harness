"""nvd_lookup — CVE metadata lookup tool (reference template).

SecOps purpose
--------------
A security operations team triaging a vulnerability needs authoritative
metadata for a CVE: description, CVSS severity, affected configurations,
and reference links. This tool fetches that metadata from the NVD
(National Vulnerability Database) CVE API and returns a normalized,
LLM-friendly structure.

This is a *reference implementation* meant to be wired into an Amazon
Bedrock AgentCore Gateway as an MCP target (Lambda-style handler). It is
deliberately written so it runs OFFLINE by default: a stubbed fixture is
returned unless live NVD access is explicitly enabled. That keeps the
template testable in CI with no network, no secrets, and no external
dependencies.

Egress & secrets posture
------------------------
- Egress is CONTROLLED. Live NVD calls happen only when
  ``NVD_LIVE=1`` is set AND the runtime network policy permits egress to
  the NVD host. In the default (stubbed) mode there is zero network I/O.
- Secrets are CONTROLLED. An optional NVD API key is read only from the
  environment variable ``NVD_API_KEY`` — it is never hardcoded, logged,
  or echoed back in responses.
- Execution role / region are referenced via the standard harness
  environment variables ``SENTINEL_EXECUTION_ROLE_ARN``,
  ``SENTINEL_REGION`` and ``AWS_PROFILE`` (never hardcoded account IDs
  or ARNs).

Input contract
--------------
event = {"cve_id": "CVE-2021-44228"}

Output contract (on success)
----------------------------
{
    "ok": True,
    "source": "stub" | "nvd",
    "cve": {
        "id": "CVE-2021-44228",
        "published": "...",
        "last_modified": "...",
        "description": "...",
        "cvss_v3_score": 10.0,
        "cvss_v3_severity": "CRITICAL",
        "cwe_ids": ["CWE-917"],
        "references": ["https://..."],
    },
}
"""

from __future__ import annotations

import os
import re
from typing import Any, Dict

# Strict CVE identifier format: CVE-YYYY-NNNN(+). Year >= 1999 by convention.
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,19}$")

# Offline fixtures. Log4Shell and a generic npm supply-chain CVE are used as
# public, non-sensitive examples. Extend as needed for local testing.
_STUB_DB: Dict[str, Dict[str, Any]] = {
    "CVE-2021-44228": {
        "id": "CVE-2021-44228",
        "published": "2021-12-10T10:15:09.143",
        "last_modified": "2023-11-07T03:39:23.157",
        "description": (
            "Apache Log4j2 JNDI features do not protect against attacker "
            "controlled LDAP and other JNDI related endpoints (Log4Shell)."
        ),
        "cvss_v3_score": 10.0,
        "cvss_v3_severity": "CRITICAL",
        "cwe_ids": ["CWE-917", "CWE-20"],
        "references": [
            "https://logging.apache.org/log4j/2.x/security.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
        ],
    },
    "CVE-2018-1000006": {
        "id": "CVE-2018-1000006",
        "published": "2018-01-24T21:29:00.213",
        "last_modified": "2019-10-03T00:03:26.223",
        "description": (
            "A supply-chain style vulnerability in a widely used package "
            "manager component allowing remote code execution."
        ),
        "cvss_v3_score": 8.8,
        "cvss_v3_severity": "HIGH",
        "cwe_ids": ["CWE-94"],
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2018-1000006",
        ],
    },
}


def _validate(event: Dict[str, Any]) -> str:
    """Validate input and return the normalized (upper-cased) CVE id."""
    if not isinstance(event, dict):
        raise ValueError("event must be a dict")
    cve_id = event.get("cve_id")
    if not isinstance(cve_id, str) or not cve_id.strip():
        raise ValueError("missing required string field 'cve_id'")
    cve_id = cve_id.strip().upper()
    if not _CVE_RE.match(cve_id):
        raise ValueError(
            "invalid 'cve_id' format; expected CVE-YYYY-NNNN, got: "
            f"{cve_id!r}"
        )
    return cve_id


def _fetch_live(cve_id: str) -> Dict[str, Any]:
    """Fetch CVE metadata from the live NVD API.

    Only reached when NVD_LIVE=1. Import of the network client is deferred
    so the default offline path has zero third-party dependencies.
    """
    import json
    import re
    import urllib.parse
    import urllib.request

    # SSRF/injection hardening: the base host is fixed (not operator-controlled),
    # but defend in depth — the CVE id must be a well-formed CVE identifier so it
    # cannot smuggle extra query params / path segments into the URL, and the URL
    # must stay https to the NVD host. Raises -> upstream_error (no silent fallback).
    if not re.fullmatch(r"CVE-\d{4}-\d{4,19}", cve_id or "", re.IGNORECASE):
        raise RuntimeError(f"refusing to query a malformed CVE id: {cve_id!r}")
    base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    url = f"{base}?cveId={urllib.parse.quote(cve_id, safe='')}"
    if urllib.parse.urlsplit(url).scheme != "https":
        raise RuntimeError("refusing to open a non-HTTPS NVD URL")
    req = urllib.request.Request(url, headers={"User-Agent": "sentinel-harness"})
    api_key = os.environ.get("NVD_API_KEY")  # optional; never hardcoded
    if api_key:
        req.add_header("apiKey", api_key)
    # Bound the read so a hostile/oversized upstream cannot force unbounded memory
    # buffering (mirrors the sibling *_LIVE tools).
    _MAX_LIVE_BODY_BYTES = 4 * 1024 * 1024
    with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310 (host is fixed NVD)
        raw = resp.read(_MAX_LIVE_BODY_BYTES + 1)
    if len(raw) > _MAX_LIVE_BODY_BYTES:
        raise RuntimeError(
            f"NVD reply exceeds {_MAX_LIVE_BODY_BYTES} bytes; refusing to parse"
        )
    data = json.loads(raw.decode("utf-8"))
    return _normalize_nvd(cve_id, data)


def _normalize_nvd(cve_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
    """Flatten the NVD 2.0 response into our compact contract."""
    vulns = data.get("vulnerabilities") or []
    if not vulns:
        raise LookupError(f"CVE not found in NVD: {cve_id}")
    cve = vulns[0].get("cve", {})
    descriptions = cve.get("descriptions", [])
    desc = next(
        (d.get("value") for d in descriptions if d.get("lang") == "en"),
        "",
    )
    metrics = cve.get("metrics", {})
    cvss_score = None
    cvss_sev = None
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key) or []
        if entries:
            cvss = entries[0].get("cvssData", {})
            cvss_score = cvss.get("baseScore")
            cvss_sev = cvss.get("baseSeverity")
            break
    cwe_ids = []
    for weakness in cve.get("weaknesses", []):
        for d in weakness.get("description", []):
            val = d.get("value")
            if val and val.startswith("CWE-"):
                cwe_ids.append(val)
    references = [r.get("url") for r in cve.get("references", []) if r.get("url")]
    return {
        "id": cve_id,
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "description": desc,
        "cvss_v3_score": cvss_score,
        "cvss_v3_severity": cvss_sev,
        "cwe_ids": sorted(set(cwe_ids)),
        "references": references,
    }


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Look up CVE metadata for a single CVE identifier.

    Runs offline (stub) by default; performs a live NVD call only when the
    environment opts in via NVD_LIVE=1. All egress and secrets are
    controlled through environment configuration, never hardcoded.
    """
    try:
        cve_id = _validate(event)
    except ValueError as exc:
        return {"ok": False, "error": "validation_error", "message": str(exc)}

    live = os.environ.get("NVD_LIVE") == "1"
    try:
        if live:
            cve = _fetch_live(cve_id)
            source = "nvd"
        else:
            if cve_id not in _STUB_DB:
                return {
                    "ok": False,
                    "error": "not_found",
                    "message": (
                        f"{cve_id} not in offline stub set; set NVD_LIVE=1 to "
                        "query the live NVD API"
                    ),
                }
            cve = _STUB_DB[cve_id]
            source = "stub"
    except LookupError as exc:
        return {"ok": False, "error": "not_found", "message": str(exc)}
    except Exception as exc:  # network / parse failures — surface, never swallow
        return {"ok": False, "error": "upstream_error", "message": str(exc)}

    return {"ok": True, "source": source, "cve": cve}


if __name__ == "__main__":
    import json

    print(json.dumps(handler({"cve_id": "CVE-2021-44228"}, None), indent=2))
