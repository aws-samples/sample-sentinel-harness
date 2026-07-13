"""epss_kev — EPSS score + CISA KEV enrichment tool (reference template).

SecOps purpose
--------------
CVSS severity alone does not tell a security operations team whether a
vulnerability is actually being exploited. Two public signals close that
gap:

- EPSS (Exploit Prediction Scoring System): a 0..1 probability that a CVE
  will be exploited in the wild in the next 30 days.
- CISA KEV (Known Exploited Vulnerabilities) catalog: an authoritative
  list of CVEs with confirmed in-the-wild exploitation, including a
  remediation-due date.

This tool enriches a CVE (or a small batch) with both signals so an agent
can prioritize patching by real-world risk, not just CVSS.

This is a *reference implementation* for wiring into an Amazon Bedrock
AgentCore Gateway as an MCP target. It runs OFFLINE by default from
stubbed fixtures; live lookups are opt-in.

Egress & secrets posture
------------------------
- Egress is CONTROLLED. Live EPSS/KEV calls happen only when
  ``EPSS_KEV_LIVE=1`` and the runtime network policy allows egress.
  Default mode does no network I/O.
- No secrets are required by EPSS or KEV; none are read or stored.
- Execution role / region are referenced via
  ``SENTINEL_EXECUTION_ROLE_ARN``, ``SENTINEL_REGION`` and ``AWS_PROFILE``.

Input contract
--------------
event = {"cve_ids": ["CVE-2021-44228", "CVE-2018-1000006"]}
   (or the singular {"cve_id": "CVE-2021-44228"})

Output contract
---------------
{
    "ok": True,
    "source": "stub" | "live",
    "results": {
        "CVE-2021-44228": {
            "epss": 0.975,
            "epss_percentile": 0.999,
            "in_kev": True,
            "kev_date_added": "2021-12-10",
            "kev_due_date": "2021-12-24",
        },
        ...
    },
}
"""

from __future__ import annotations

import os
import re
from typing import Any, Dict, List

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,19}$")
_MAX_BATCH = 50

# Offline fixtures using public, non-sensitive examples.
_STUB_EPSS: Dict[str, Dict[str, float]] = {
    "CVE-2021-44228": {"epss": 0.975, "epss_percentile": 0.999},
    "CVE-2018-1000006": {"epss": 0.42, "epss_percentile": 0.91},
}
_STUB_KEV: Dict[str, Dict[str, str]] = {
    "CVE-2021-44228": {
        "kev_date_added": "2021-12-10",
        "kev_due_date": "2021-12-24",
    },
}


def _validate(event: Dict[str, Any]) -> List[str]:
    """Validate input and return a normalized, de-duplicated CVE id list."""
    if not isinstance(event, dict):
        raise ValueError("event must be a dict")

    raw: List[Any]
    if "cve_ids" in event:
        raw = event["cve_ids"]
        if not isinstance(raw, list):
            raise ValueError("'cve_ids' must be a list of strings")
    elif "cve_id" in event:
        raw = [event["cve_id"]]
    else:
        raise ValueError("provide 'cve_id' (string) or 'cve_ids' (list)")

    if not raw:
        raise ValueError("no CVE identifiers supplied")
    if len(raw) > _MAX_BATCH:
        raise ValueError(f"batch too large; max {_MAX_BATCH} CVEs per call")

    seen: List[str] = []
    for item in raw:
        if not isinstance(item, str) or not item.strip():
            raise ValueError("every CVE id must be a non-empty string")
        norm = item.strip().upper()
        if not _CVE_RE.match(norm):
            raise ValueError(f"invalid CVE id format: {item!r}")
        if norm not in seen:
            seen.append(norm)
    return seen


def _enrich_stub(cve_ids: List[str]) -> Dict[str, Dict[str, Any]]:
    results: Dict[str, Dict[str, Any]] = {}
    for cid in cve_ids:
        epss = _STUB_EPSS.get(cid, {})
        kev = _STUB_KEV.get(cid)
        results[cid] = {
            "epss": epss.get("epss"),
            "epss_percentile": epss.get("epss_percentile"),
            "in_kev": kev is not None,
            "kev_date_added": (kev or {}).get("kev_date_added"),
            "kev_due_date": (kev or {}).get("kev_due_date"),
        }
    return results


def _enrich_live(cve_ids: List[str]) -> Dict[str, Dict[str, Any]]:
    """Query the public EPSS API and CISA KEV feed.

    Only reached when EPSS_KEV_LIVE=1. Network client imported lazily.
    """
    import json
    import urllib.request

    # Bound the read so a hostile/oversized upstream cannot force unbounded memory
    # buffering (mirrors the sibling *_LIVE tools).
    _MAX_LIVE_BODY_BYTES = 4 * 1024 * 1024

    def _get_json(url: str) -> Dict[str, Any]:
        req = urllib.request.Request(
            url, headers={"User-Agent": "sentinel-harness"}
        )
        with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310
            raw = resp.read(_MAX_LIVE_BODY_BYTES + 1)
        if len(raw) > _MAX_LIVE_BODY_BYTES:
            raise RuntimeError(
                f"backend reply exceeds {_MAX_LIVE_BODY_BYTES} bytes; refusing to parse"
            )
        return json.loads(raw.decode("utf-8"))

    # EPSS supports comma-separated batch queries.
    epss_url = (
        "https://api.first.org/data/v1/epss?cve=" + ",".join(cve_ids)
    )
    epss_data = _get_json(epss_url)
    epss_map: Dict[str, Dict[str, Any]] = {}
    for row in epss_data.get("data", []):
        cid = row.get("cve")
        if cid:
            epss_map[cid] = {
                "epss": float(row["epss"]) if row.get("epss") else None,
                "epss_percentile": (
                    float(row["percentile"]) if row.get("percentile") else None
                ),
            }

    kev_data = _get_json(
        "https://www.cisa.gov/sites/default/files/feeds/"
        "known_exploited_vulnerabilities.json"
    )
    kev_map: Dict[str, Dict[str, str]] = {}
    for row in kev_data.get("vulnerabilities", []):
        cid = row.get("cveID")
        if cid:
            kev_map[cid] = {
                "kev_date_added": row.get("dateAdded"),
                "kev_due_date": row.get("dueDate"),
            }

    results: Dict[str, Dict[str, Any]] = {}
    for cid in cve_ids:
        epss = epss_map.get(cid, {})
        kev = kev_map.get(cid)
        results[cid] = {
            "epss": epss.get("epss"),
            "epss_percentile": epss.get("epss_percentile"),
            "in_kev": kev is not None,
            "kev_date_added": (kev or {}).get("kev_date_added"),
            "kev_due_date": (kev or {}).get("kev_due_date"),
        }
    return results


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Enrich one or more CVEs with EPSS score and CISA KEV status.

    Offline (stub) by default; live enrichment only when EPSS_KEV_LIVE=1.
    Egress is controlled by environment configuration; no secrets required.
    """
    try:
        cve_ids = _validate(event)
    except ValueError as exc:
        return {"ok": False, "error": "validation_error", "message": str(exc)}

    live = os.environ.get("EPSS_KEV_LIVE") == "1"
    try:
        results = _enrich_live(cve_ids) if live else _enrich_stub(cve_ids)
    except Exception as exc:  # never swallow upstream failures
        return {"ok": False, "error": "upstream_error", "message": str(exc)}

    return {
        "ok": True,
        "source": "live" if live else "stub",
        "results": results,
    }


if __name__ == "__main__":
    import json

    print(
        json.dumps(
            handler({"cve_ids": ["CVE-2021-44228", "CVE-2018-1000006"]}, None),
            indent=2,
        )
    )
