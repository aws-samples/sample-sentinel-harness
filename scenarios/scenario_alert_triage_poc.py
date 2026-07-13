"""
Scenario (M5) — end-to-end alert-triage POC across ALL mock data planes
=======================================================================
Layer 3 (cyber-skills) · the "does the cross-linked data story actually triage?"
proof for the M5 mock data layer.

.. warning::
   **This runs entirely on CLEARLY-LABELED MOCK DATA for POC / testing only.**
   Every host id, IP, domain, alert, and IOC below is fictional (RFC 5737
   documentation IPs, ``example.com`` / ``example.test`` domains, generic host
   ids). It is *not* a real SIEM, *not* real threat intelligence, and *not* a
   real ticketing system. See ``mockdata/README.md`` and each tool's README.

WHY this scenario exists
------------------------
M5 builds a self-contained, internally-consistent fictional SecOps enterprise so
an alert-triage POC can run END TO END on realistic, cross-linked data BEFORE any
real customer SIEM / asset / ticketing plane is wired. This scenario is that
proof: it triages a mock alert exactly as a real analyst would, walking all four
data planes and correlating them into a verdict — with ZERO AWS and ZERO network
by default.

The triage walk (the "Log4Shell story")
----------------------------------------
1. ``siem_query`` for high-severity events -> pick the Log4Shell exploitation
   alert (``alert-1001``, technique ``T1190``) on ``web-01``.
2. ``enrich_ioc`` on that alert's ``src_ip`` (the C2 indicator ``203.0.113.66``)
   -> ``verdict: malicious``, ``related_hosts`` includes ``web-01``.
3. ``asset_lookup`` ``web-01`` -> confirms it exposes the vulnerable https
   service carrying ``CVE-2021-44228`` (Log4Shell) — the blast radius.
4. :func:`correlate` fuses the three planes into a deterministic TP verdict:
   ``{alert_id, verdict: "true_positive", confidence, blast_radius,
   recommended_action}``.
5. ``create_ticket`` records the confirmed incident. In the real alert-triage
   harness this write is **human-in-the-loop (HITL) gated**; here the offline
   mock records the ticket the analyst WOULD approve, side-effect-free.

Because all four data-plane tools read the SAME ``mockdata`` world, the host an
alert names is the host ``asset_lookup`` knows and the IP it carries is the
indicator ``enrich_ioc`` scores — that consistency is exactly what this POC
proves.

What is real vs. stubbed
------------------------
- The DEFAULT run is PURE (no AWS, no network, no LLM): it exercises the four
  deterministic mock tools directly (loaded by unique importlib path, mirroring
  how the harness tests load them) and the deterministic :func:`correlate` core.
  It proves the data-plane correlation end to end and records a scrubbed verdict.
- ``--live`` prints a pointer to the real alert-triage harness
  (``harnesses/alert-triage/harness.yaml``, allowedTools @gateway/{siem_query,
  asset_lookup, enrich_ioc, create_ticket} + code_interpreter) where an actual
  agent would drive the same walk with a HITL gate on the ticket write. It does
  NOT stand up AWS — that wiring is deployment work outside this POC.

Egress & secrets posture
------------------------
- Egress is CONTROLLED. The default path has zero network I/O — it reads the
  embedded mock world only. No tool's ``*_LIVE`` opt-in is set here.
- No secrets, no hardcoded account ids/ARNs. The evidence writer scrubs any
  12-digit account id out of ARNs before writing, mirroring the other scenarios.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# The data-plane tools do ``import mockdata`` — make the repo root importable so
# they resolve against the single-source-of-truth world package.
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)


def _load_tool(name: str) -> Any:
    """Load a data-plane tool handler by its UNIQUE importlib path.

    WHY unique names: every tool ships a module literally named ``handler``; a
    bare import would collide in ``sys.modules`` when several are loaded in one
    process. We register each under ``<name>_handler`` so the four planes coexist
    — exactly how the tools' own tests (tests/test_siem_query.py, etc.) load them.
    We never swallow a broken module: an exec error propagates loudly.
    """
    path = os.path.join(REPO_ROOT, "tools", name, "handler.py")
    unique = f"{name}_handler__alert_triage_poc"
    spec = importlib.util.spec_from_file_location(unique, path)
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        raise ImportError(f"cannot load tool {name!r} from {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[unique] = mod
    spec.loader.exec_module(mod)
    return mod


# Load the four data planes by unique path (offline, deterministic).
siem_query = _load_tool("siem_query")
enrich_ioc = _load_tool("enrich_ioc")
asset_lookup = _load_tool("asset_lookup")
create_ticket = _load_tool("create_ticket")

RESULT: Dict[str, Any] = {"scenario": "alert_triage_poc", "steps": []}

# Account-id scrubber — identical pattern to the other scenarios. Masks the
# 12-digit account id inside any ARN to <ACCOUNT_ID> before evidence is written.
_ACCT_RE = re.compile(r"(arn:aws[^:]*:[^:]*:[^:]*:)\d{12}(:)")


def _scrub(obj: Any) -> Any:
    if isinstance(obj, str):
        return _ACCT_RE.sub(r"\1<ACCOUNT_ID>\2", obj)
    if isinstance(obj, dict):
        return {k: _scrub(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_scrub(v) for v in obj]
    return obj


def rec(step: str, ok: bool, data: Any) -> None:
    data = _scrub(json.loads(json.dumps(data, default=str)))
    RESULT["steps"].append({"step": step, "ok": ok, "data": data})
    print(f"[{'OK' if ok else '..'}] {step}: "
          f"{json.dumps(data, ensure_ascii=False, default=str)[:240]}", flush=True)


# --------------------------------------------------------------------------
# The unit-testable core: fuse the three read planes into one triage verdict.
#
# This is a DETERMINISTIC correlation — no LLM, no randomness, no clock. It
# encodes the analyst's judgement as an explicit, testable policy:
#
#   true_positive  <=>  the alert is a real (non-false-positive) exploitation
#                       signal AND its source indicator is malicious AND the
#                       targeted host actually exposes a known-vulnerable service.
#
# Any one of those missing downgrades the verdict, so a benign/false-positive
# event (or a clean IP, or a fully-patched host) is never marked true_positive.
# --------------------------------------------------------------------------
def correlate(
    event: Dict[str, Any],
    ioc_result: Optional[Dict[str, Any]],
    asset_surface: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """Fuse a SIEM event + its IOC enrichment + the target asset surface.

    Parameters
    ----------
    event:
        A normalized ``siem_query`` event (must carry ``alert_id``, ``host``,
        ``severity``, ``src_ip``, ``technique``, ``false_positive``).
    ioc_result:
        The per-indicator reputation record ``enrich_ioc`` returned for the
        event's ``src_ip`` (or ``None`` if there was no indicator to enrich).
    asset_surface:
        The ``asset_lookup`` ``surface`` for the event's host (or ``None``).

    Returns
    -------
    A verdict dict::

        {
            "alert_id": "alert-1001",
            "verdict": "true_positive" | "inconclusive" | "false_positive",
            "confidence": "high" | "medium" | "low",
            "blast_radius": {
                "host": "web-01",
                "vulnerable": True,
                "cves": ["CVE-2021-44228"],
                "reachable_hosts": ["app-01"],   # trust-edge pivots
            },
            "recommended_action": "contain_host_and_open_incident" | ...,
            "signals": {ioc_malicious, asset_vulnerable, not_false_positive},
        }

    Determinism: pure function of its inputs. No I/O, no time, no randomness.
    """
    if not isinstance(event, dict) or "alert_id" not in event:
        raise ValueError("correlate() requires a normalized SIEM event with alert_id")

    alert_id = event["alert_id"]
    host = event.get("host")

    # --- Signal 1: is this a real signal, or a known false positive? ---
    not_false_positive = not bool(event.get("false_positive", False))
    # An "info"/false-positive-shaped severity is itself weak evidence; we treat
    # the explicit false_positive flag as authoritative and let severity feed
    # confidence below.
    severity = event.get("severity", "")

    # --- Signal 2: is the source indicator malicious? ---
    ioc_malicious = bool(ioc_result) and ioc_result.get("verdict") == "malicious"

    # --- Signal 3: does the targeted host expose a known-vulnerable service? ---
    asset_vulnerable = False
    cves: List[str] = []
    reachable_hosts: List[str] = []
    if asset_surface:
        for h in asset_surface.get("hosts", []):
            if h.get("id") != host:
                continue
            for svc in h.get("services", []):
                if svc.get("known_vuln"):
                    asset_vulnerable = True
                    cve = svc.get("cve_id")
                    if cve and cve not in cves:
                        cves.append(cve)
        # Trust-edge pivots OUT of the compromised host = downstream blast radius.
        reachable_hosts = sorted(
            {e["dst"] for e in asset_surface.get("trust_edges", [])
             if e.get("src") == host and e.get("dst")}
        )

    # --- The verdict policy (explicit + testable). ---
    if not_false_positive and ioc_malicious and asset_vulnerable:
        verdict = "true_positive"
        # High only when the alert itself is high/critical severity; otherwise a
        # true-but-low-severity match stays "medium" confidence.
        confidence = "high" if severity in ("high", "critical") else "medium"
        recommended_action = "contain_host_and_open_incident"
    elif not not_false_positive:
        # An explicitly-flagged false positive is dismissed regardless of the
        # other planes (e.g. allowlisted-CDN traffic that happens to name web-01).
        verdict = "false_positive"
        confidence = "high"
        recommended_action = "dismiss"
    else:
        # A real signal but the corroborating planes don't both fire — do not
        # over-claim. This needs a human look, not an auto-incident.
        verdict = "inconclusive"
        confidence = "low"
        recommended_action = "escalate_for_manual_review"

    return {
        "alert_id": alert_id,
        "verdict": verdict,
        "confidence": confidence,
        "blast_radius": {
            "host": host,
            "vulnerable": asset_vulnerable,
            "cves": cves,
            "reachable_hosts": reachable_hosts,
        },
        "recommended_action": recommended_action,
        "signals": {
            "ioc_malicious": ioc_malicious,
            "asset_vulnerable": asset_vulnerable,
            "not_false_positive": not_false_positive,
        },
    }


def _pick_log4shell_alert(events: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """From high-severity events, pick the Log4Shell exploitation attempt.

    WHY explicit: the SIEM returns several high/critical events; the triage entry
    point is the *exploitation* signal — technique ``T1190`` (Exploit
    Public-Facing Application) on ``web-01``. We match on that rather than take
    ``events[0]`` so the choice is meaningful, not positional.
    """
    for e in events:
        if e.get("technique") == "T1190" and e.get("host") == "web-01":
            return e
    return None


def run_pure() -> Dict[str, Any]:
    """Drive the full triage walk over the mock world (no AWS, no network).

    Exercises the four data-plane tools + :func:`correlate` and records a
    scrubbed verdict. This is the DEFAULT run and the M5 acceptance proof.
    """
    # --- Step 1: SIEM — pull high-severity events, pick the Log4Shell one. ---
    siem_res = siem_query.handler({"severity": "high"}, None)
    ok = bool(siem_res.get("ok"))
    rec("siem_query", ok, {"count": siem_res.get("count"),
                           "alert_ids": [e["alert_id"] for e in siem_res.get("events", [])]})
    # High severity alone would not surface the *critical* Log4Shell event, so we
    # also pull critical and merge — the SIEM bands are distinct in the world.
    crit_res = siem_query.handler({"severity": "critical"}, None)
    events = list(siem_res.get("events", [])) + list(crit_res.get("events", []))
    alert = _pick_log4shell_alert(events)
    siem_hit = alert is not None
    rec("pick_alert", siem_hit,
        {"alert_id": alert["alert_id"] if alert else None,
         "rule_name": alert.get("rule_name") if alert else None,
         "host": alert.get("host") if alert else None,
         "src_ip": alert.get("src_ip") if alert else None} if True else {})

    if not siem_hit:
        # Honest failure — the world changed out from under the POC.
        RESULT["verdict"] = _failed_verdict("Log4Shell alert not found in mock SIEM")
        rec("verdict", False, RESULT["verdict"])
        return RESULT

    # --- Step 2: enrich the alert's source IOC (the C2 IP). ---
    src_ip = alert.get("src_ip")
    ioc_res = enrich_ioc.handler({"indicator": src_ip}, None)
    ioc_record = (ioc_res.get("results") or {}).get(src_ip) if ioc_res.get("ok") else None
    ioc_malicious = bool(ioc_record) and ioc_record.get("verdict") == "malicious"
    rec("enrich_ioc", ioc_malicious,
        {"indicator": src_ip, "verdict": (ioc_record or {}).get("verdict"),
         "threat_category": (ioc_record or {}).get("threat_category"),
         "related_hosts": (ioc_record or {}).get("related_hosts")})

    # --- Step 3: look up the targeted asset (blast radius). ---
    asset_res = asset_lookup.handler({"query": alert["host"]}, None)
    surface = asset_res.get("surface") if asset_res.get("ok") else None
    asset_vulnerable = False
    if surface:
        asset_vulnerable = any(
            svc.get("known_vuln")
            for h in surface.get("hosts", [])
            if h.get("id") == alert["host"]
            for svc in h.get("services", [])
        )
    rec("asset_lookup", asset_vulnerable,
        {"host": alert["host"], "vulnerable": asset_vulnerable})

    # --- Step 4: correlate the three planes into a deterministic verdict. ---
    verdict = correlate(alert, ioc_record, surface)
    correlated_tp = verdict["verdict"] == "true_positive"
    rec("correlate", correlated_tp, verdict)

    # --- Step 5: record the ticket the analyst WOULD approve (HITL-gated live). ---
    ticket_created = False
    ticket_id = None
    if correlated_tp:
        ticket_res = create_ticket.handler(
            {
                "title": f"{alert.get('rule_name')} against {alert.get('host')}",
                "severity": alert.get("severity", "critical"),
                "description": (
                    f"Correlated true-positive: {alert.get('rule_name')} on "
                    f"{alert.get('host')} from C2 indicator {src_ip} "
                    f"(CVEs {verdict['blast_radius']['cves']}). "
                    "MOCK POC ticket — in the live alert-triage harness this "
                    "write is human-in-the-loop gated."
                ),
                "assignee": "secops",
                "related_alert_id": alert["alert_id"],
                "related_host": alert["host"],
            },
            None,
        )
        ticket_created = bool(ticket_res.get("ok"))
        ticket_id = (ticket_res.get("ticket") or {}).get("ticket_id")
    rec("create_ticket", ticket_created, {"ticket_id": ticket_id})

    closed = all([siem_hit, ioc_malicious, asset_vulnerable, correlated_tp, ticket_created])
    RESULT["verdict"] = {
        "siem_hit": siem_hit,
        "ioc_malicious": ioc_malicious,
        "asset_vulnerable": asset_vulnerable,
        "correlated_true_positive": correlated_tp,
        "ticket_created": ticket_created,
        "closed": closed,
        "note": (
            "MOCK POC: triaged the Log4Shell alert (" + str(alert["alert_id"]) +
            ") end to end across all four mock data planes — SIEM -> IOC "
            "enrichment -> asset blast-radius -> deterministic correlation -> "
            "HITL-gated ticket. All data is clearly-labeled fiction (RFC 5737 "
            "IPs, example.com/.test). This proves the cross-linked data story "
            "triages before any real SIEM/asset/ticketing plane is wired. "
            "Run with --live for a pointer to the real alert-triage harness."
        ),
    }
    rec("verdict", closed, RESULT["verdict"])
    return RESULT


def _failed_verdict(reason: str) -> Dict[str, Any]:
    """A closed=false verdict with all booleans false and an honest note."""
    return {
        "siem_hit": False,
        "ioc_malicious": False,
        "asset_vulnerable": False,
        "correlated_true_positive": False,
        "ticket_created": False,
        "closed": False,
        "note": reason,
    }


def live_note() -> str:
    """Return the pointer to the real alert-triage harness (no AWS stood up)."""
    return (
        "LIVE mode is not exercised by this POC. The real alert-triage harness "
        "lives at harnesses/alert-triage/harness.yaml — it declares allowedTools "
        "@gateway/{siem_query,asset_lookup,enrich_ioc,create_ticket} + "
        "code_interpreter and drives this same triage walk with an agent, with a "
        "human-in-the-loop gate in front of the create_ticket write. Deploy that "
        "harness + gateway to run it against a live (or still-mock) data plane; "
        "this scenario proves the correlation logic offline first."
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--live", action="store_true",
        help="print a pointer to the real alert-triage harness (stands up no AWS)")
    args = parser.parse_args()

    if args.live:
        note = live_note()
        RESULT["live_note"] = note
        print(note)

    run_pure()

    out = os.path.join(REPO_ROOT, "evidence", "alert_triage_poc_result.json")
    json.dump(_scrub(RESULT), open(out, "w"), indent=2, ensure_ascii=False, default=str)
    print("\nsaved evidence/alert_triage_poc_result.json  ·  verdict:",
          json.dumps(RESULT.get("verdict"), ensure_ascii=False))
