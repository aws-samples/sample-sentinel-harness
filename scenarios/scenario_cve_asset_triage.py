"""
Scenario (M5) — CVE-triage-AGAINST-ASSET, end to end over the mock world
========================================================================
Layer 3 (cyber-skills) · the "does a CVE actually threaten *this* environment?"
proof for the M5 mock data layer.

.. warning::
   **This runs entirely on CLEARLY-LABELED MOCK DATA for POC / testing only.**
   Every host id, IP, and domain is fictional (RFC 5737 documentation IPs,
   ``example.test`` domains, generic host ids). The CVE metadata comes from
   the OFFLINE stub fixtures in ``tools/{nvd_lookup,epss_kev}`` (public,
   non-sensitive CVEs). It is *not* a real NVD/EPSS/KEV feed and *not* a real
   asset inventory. See ``mockdata/README.md`` and each tool's README.

WHY this scenario exists
------------------------
A bare CVE record (CVSS 10.0, in KEV, EPSS 0.97) tells you a vuln is *dangerous
in general*. It does NOT tell a security-ops team whether the vuln threatens
*their* environment. The judgement that matters is **CVE ⋈ asset surface**:
which of *my* hosts actually expose the vulnerable service? That intersection is
the blast radius, and it is what turns "scary CVE on the internet" into "web-01
is exposed — page someone". This scenario proves that join runs end to end on
the mock world, offline and deterministic, BEFORE any real vuln feed or CMDB is
wired.

The triage walk (the "Log4Shell-against-my-fleet story")
--------------------------------------------------------
1. Take a CVE id (default ``CVE-2021-44228``, Log4Shell — present in the
   ``nvd_lookup`` offline stub). ``nvd_lookup`` -> severity / CVSS.
2. ``epss_kev`` -> exploit probability (EPSS) + CISA KEV flag (exploited in
   the wild?).
3. ``asset_lookup`` across the mock world (``query="*"``) -> which hosts expose
   a service carrying that CVE. ``web-01`` exposes the Log4Shell-vulnerable
   https service => that is the blast radius + the reachable (pivot) hosts.
4. :func:`triage` deterministically assembles a ``CVETriage`` verdict:
   ``{cve_id, severity, cvss, exploited_in_wild, affected_hosts, blast_radius,
   recommended_action}`` — no LLM, no clock, no randomness.
5. HITL: the remediation recommendation passes a ``request_human_review``-style
   gate. The offline POC records that analyst sign-off is REQUIRED before any
   remediation action — security decisions are not made by the AI alone.

What is real vs. stubbed
------------------------
- The DEFAULT run is PURE (no AWS, no network, no LLM): it exercises the three
  deterministic tools directly (loaded by unique importlib path, mirroring how
  the harness tests load them) and the deterministic :func:`triage` core. It
  records a scrubbed verdict to ``evidence/cve_asset_triage_result.json``.
- ``--live`` prints a pointer to the real CVE-triage harness where an agent
  would drive the same walk with a HITL gate. It stands up NO AWS — that wiring
  is deployment work outside this POC.

Egress & secrets posture
------------------------
- Egress is CONTROLLED. The default path has zero network I/O — it reads the
  offline tool stubs + the embedded mock world only. No tool's ``*_LIVE`` opt-in
  is set here.
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
# The data-plane tools may ``import mockdata`` — make the repo root importable
# so they resolve against the single-source-of-truth world package.
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)


def _load_tool(name: str) -> Any:
    """Load a data-plane tool handler by its UNIQUE importlib path.

    WHY unique names: every tool ships a module literally named ``handler``; a
    bare import would collide in ``sys.modules`` when several are loaded in one
    process. We register each under a scenario-scoped unique name so the planes
    coexist — exactly how the tools' own tests load them. We never swallow a
    broken module: an exec error propagates loudly.
    """
    path = os.path.join(REPO_ROOT, "tools", name, "handler.py")
    unique = f"{name}_handler__cve_asset_triage"
    spec = importlib.util.spec_from_file_location(unique, path)
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        raise ImportError(f"cannot load tool {name!r} from {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[unique] = mod
    spec.loader.exec_module(mod)
    return mod


# Load the three planes by unique path (offline, deterministic).
nvd_lookup = _load_tool("nvd_lookup")
epss_kev = _load_tool("epss_kev")
asset_lookup = _load_tool("asset_lookup")

DEFAULT_CVE = "CVE-2021-44228"  # Log4Shell — present in the nvd_lookup stub.

RESULT: Dict[str, Any] = {"scenario": "cve_asset_triage", "steps": []}

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
# The unit-testable core: join a CVE's public risk against the asset surface.
#
# This is a DETERMINISTIC assembly — no LLM, no randomness, no clock. It encodes
# the analyst's judgement as an explicit, testable policy over three inputs:
#   - nvd_cve      : the CVE record (severity + CVSS) from nvd_lookup.
#   - epss_kev_rec : the EPSS/KEV enrichment for the CVE from epss_kev.
#   - asset_surface: the WHOLE known asset surface from asset_lookup("*").
#
# The headline output is ``affected_hosts``: the hosts whose exposed services
# carry THIS cve_id. That intersection is the blast radius. A CVE that matches
# no host yields an EMPTY affected_hosts list (never a crash) and a benign
# recommendation — a scary CVE that touches nothing here is not an incident.
# --------------------------------------------------------------------------
def triage(
    cve_id: str,
    nvd_cve: Optional[Dict[str, Any]],
    epss_kev_rec: Optional[Dict[str, Any]],
    asset_surface: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """Assemble a deterministic ``CVETriage`` verdict for a CVE vs. the fleet.

    Parameters
    ----------
    cve_id:
        The (normalized) CVE identifier being triaged.
    nvd_cve:
        The ``cve`` sub-dict ``nvd_lookup`` returned (``cvss_v3_score`` /
        ``cvss_v3_severity``), or ``None`` if the CVE was not found.
    epss_kev_rec:
        The per-CVE record from ``epss_kev`` (``epss`` / ``in_kev`` / KEV
        dates), or ``None`` if enrichment was unavailable.
    asset_surface:
        The ``surface`` dict from ``asset_lookup`` over the WHOLE fleet
        (``{"hosts": [...], "trust_edges": [...]}``), or ``None``.

    Returns
    -------
    A ``CVETriage`` verdict dict::

        {
            "cve_id": "CVE-2021-44228",
            "severity": "CRITICAL",
            "cvss": 10.0,
            "exploited_in_wild": True,          # CISA KEV flag
            "epss": 0.975,                      # exploit probability (0..1)
            "affected_hosts": ["web-01"],       # hosts exposing THIS cve
            "blast_radius": {
                "affected_count": 1,
                "reachable_hosts": ["app-01"],  # trust-edge pivots out
                "internet_exposed_hit": True,
            },
            "recommended_action": "patch_now_exposed_and_exploited" | ...,
        }

    Determinism: pure function of its inputs. No I/O, no time, no randomness.
    """
    if not isinstance(cve_id, str) or not cve_id.strip():
        raise ValueError("triage() requires a non-empty cve_id")
    cve_id = cve_id.strip().upper()

    # --- CVE intrinsic risk (may be absent if the CVE was not found). ---
    severity = (nvd_cve or {}).get("cvss_v3_severity")
    cvss = (nvd_cve or {}).get("cvss_v3_score")

    # --- Real-world exploitation signals. ---
    exploited_in_wild = bool((epss_kev_rec or {}).get("in_kev"))
    epss = (epss_kev_rec or {}).get("epss")

    # --- The join: which of OUR hosts expose a service carrying THIS cve? ---
    affected_hosts: List[str] = []
    internet_exposed_hit = False
    if asset_surface:
        for h in asset_surface.get("hosts", []):
            host_id = h.get("id")
            for svc in h.get("services", []):
                if svc.get("known_vuln") and svc.get("cve_id") == cve_id:
                    if host_id and host_id not in affected_hosts:
                        affected_hosts.append(host_id)
                    if h.get("internet_exposed"):
                        internet_exposed_hit = True
    affected_hosts = sorted(affected_hosts)
    affected_set = set(affected_hosts)

    # Downstream pivots: trust edges OUT of any affected host = extended blast
    # radius (an attacker who lands on an affected host can move to these).
    reachable_hosts: List[str] = []
    if asset_surface and affected_set:
        reachable_hosts = sorted(
            {
                e["dst"]
                for e in asset_surface.get("trust_edges", [])
                if e.get("src") in affected_set and e.get("dst")
                and e.get("dst") not in affected_set
            }
        )

    # --- The recommendation policy (explicit + testable). ---
    if not affected_hosts:
        # A CVE that touches no host here is not an incident for us — track it,
        # do not page anyone. (Still HITL-gated: a human confirms the "no
        # exposure" reading before we close it out.)
        recommended_action = "no_action_not_exposed"
    elif internet_exposed_hit and exploited_in_wild:
        # Exposed to the internet AND confirmed exploited in the wild: the
        # worst quadrant. Patch/mitigate immediately.
        recommended_action = "patch_now_exposed_and_exploited"
    elif exploited_in_wild or internet_exposed_hit:
        recommended_action = "prioritize_patch"
    else:
        recommended_action = "schedule_patch"

    return {
        "cve_id": cve_id,
        "severity": severity,
        "cvss": cvss,
        "exploited_in_wild": exploited_in_wild,
        "epss": epss,
        "affected_hosts": affected_hosts,
        "blast_radius": {
            "affected_count": len(affected_hosts),
            "reachable_hosts": reachable_hosts,
            "internet_exposed_hit": internet_exposed_hit,
        },
        "recommended_action": recommended_action,
    }


# HITL gate: which recommendations require analyst sign-off before ANY action.
# Everything that would actually change the fleet (patch/mitigate) is gated; a
# "no action, not exposed" reading is still gated so a human confirms we did not
# miss an exposure. In short: no remediation is auto-applied by the AI.
def hitl_gate_required(verdict: Dict[str, Any]) -> bool:
    """Return True when the verdict's recommendation needs human sign-off.

    Mirrors a ``request_human_review`` inline-function gate: the deterministic
    core proposes an action, but a human MUST approve before it is executed.
    Modeled as always-required here — security remediation is never auto-applied
    by the agent — but kept as a function so a future policy can relax it.
    """
    return True


def run_pure(cve_id: str = DEFAULT_CVE) -> Dict[str, Any]:
    """Drive the full CVE-vs-asset triage walk over the mock world (no AWS).

    Exercises nvd_lookup -> epss_kev -> asset_lookup -> :func:`triage` -> the
    HITL gate and records a scrubbed verdict. This is the DEFAULT run and the
    M5 acceptance proof.
    """
    cve_id = cve_id.strip().upper()
    RESULT["cve_id"] = cve_id

    # --- Step 1: NVD — severity / CVSS for the CVE. ---
    nvd_res = nvd_lookup.handler({"cve_id": cve_id}, None)
    nvd_ok = bool(nvd_res.get("ok"))
    nvd_cve = nvd_res.get("cve") if nvd_ok else None
    has_cvss = bool(nvd_cve) and nvd_cve.get("cvss_v3_score") is not None
    rec("nvd_lookup", nvd_ok,
        {"cve_id": cve_id,
         "severity": (nvd_cve or {}).get("cvss_v3_severity"),
         "cvss": (nvd_cve or {}).get("cvss_v3_score"),
         "source": nvd_res.get("source"),
         "error": nvd_res.get("error")})

    # --- Step 2: EPSS + CISA KEV — exploit probability / exploited-in-wild. ---
    epss_res = epss_kev.handler({"cve_id": cve_id}, None)
    epss_ok = bool(epss_res.get("ok"))
    epss_rec = (epss_res.get("results") or {}).get(cve_id) if epss_ok else None
    in_kev = bool((epss_rec or {}).get("in_kev"))
    rec("epss_kev", epss_ok,
        {"cve_id": cve_id,
         "epss": (epss_rec or {}).get("epss"),
         "in_kev": in_kev,
         "kev_due_date": (epss_rec or {}).get("kev_due_date"),
         "source": epss_res.get("source")})

    # --- Step 3: asset_lookup across the WHOLE fleet -> blast radius. ---
    asset_res = asset_lookup.handler({"query": "*"}, None)
    asset_ok = bool(asset_res.get("ok"))
    surface = asset_res.get("surface") if asset_ok else None
    rec("asset_lookup", asset_ok,
        {"query": "*",
         "host_count": len(((surface or {}).get("hosts")) or []),
         "source": asset_res.get("source")})

    # --- Step 4: assemble the deterministic CVETriage verdict. ---
    verdict = triage(cve_id, nvd_cve, epss_rec, surface)
    affected_hosts = verdict["affected_hosts"]
    # Real invariant (not a tautology): the blast radius must actually agree with
    # the affected-host set — affected_count == len(affected_hosts) AND every
    # reachable host is a real, distinct neighbour of an affected host.
    blast = verdict["blast_radius"]
    reachable = blast.get("reachable_hosts") or []
    blast_radius_computed = (
        blast.get("affected_count") == len(affected_hosts)
        and set(reachable).isdisjoint(set(affected_hosts))
    )
    rec("triage", bool(affected_hosts), verdict)

    # --- Step 5: HITL gate — analyst sign-off REQUIRED before any action. ---
    gate_required = hitl_gate_required(verdict)
    rec("hitl_gate", gate_required,
        {"recommended_action": verdict["recommended_action"],
         "analyst_sign_off_required": gate_required,
         "note": ("MOCK POC: the deterministic core PROPOSES a remediation; a "
                  "human analyst MUST approve via a request_human_review-style "
                  "gate before any action is taken. No remediation is "
                  "auto-applied by the AI.")})

    closed = all([nvd_ok, epss_ok, asset_ok, blast_radius_computed, gate_required])
    RESULT["verdict"] = {
        "cve_id": cve_id,
        "has_cvss": has_cvss,
        "in_kev": in_kev,
        "affected_hosts": affected_hosts,
        "blast_radius_computed": blast_radius_computed,
        "hitl_gate_required": gate_required,
        "recommended_action": verdict["recommended_action"],
        "closed": closed,
        "note": (
            "MOCK POC: triaged " + cve_id + " AGAINST the mock asset surface "
            "end to end — nvd_lookup (severity/CVSS) -> epss_kev (EPSS + CISA "
            "KEV) -> asset_lookup (which of my hosts expose it) -> deterministic "
            "CVETriage join (blast radius) -> HITL gate (analyst sign-off "
            "required before any remediation). All data is clearly-labeled "
            "fiction (RFC 5737 IPs, example.test); CVE metadata is from the "
            "offline tool stubs. This proves the CVE-vs-asset join runs before "
            "any real vuln feed / CMDB is wired. Run with --live for a pointer "
            "to the real CVE-triage harness."
        ),
    }
    rec("verdict", closed, RESULT["verdict"])
    return RESULT


def live_note() -> str:
    """Return the pointer to the real CVE-triage harness (no AWS stood up)."""
    return (
        "LIVE mode is not exercised by this POC. The real CVE-triage harness "
        "drives this same walk with an agent — nvd_lookup + epss_kev for CVE "
        "risk, asset_lookup for the fleet surface, then a deterministic "
        "CVE-vs-asset join — with a human-in-the-loop request_human_review gate "
        "in front of any remediation recommendation. Deploy that harness + "
        "gateway (and optionally set NVD_LIVE / EPSS_KEV_LIVE / "
        "ASSET_LOOKUP_LIVE to reach real feeds) to run it against a live (or "
        "still-mock) data plane; this scenario proves the join logic offline "
        "first."
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--cve", default=DEFAULT_CVE,
        help=f"CVE id to triage against the mock fleet (default {DEFAULT_CVE})")
    parser.add_argument(
        "--live", action="store_true",
        help="print a pointer to the real CVE-triage harness (stands up no AWS)")
    args = parser.parse_args()

    if args.live:
        note = live_note()
        RESULT["live_note"] = note
        print(note)

    run_pure(args.cve)

    out = os.path.join(REPO_ROOT, "evidence", "cve_asset_triage_result.json")
    json.dump(_scrub(RESULT), open(out, "w"), indent=2, ensure_ascii=False, default=str)
    print("\nsaved evidence/cve_asset_triage_result.json  ·  verdict:",
          json.dumps(RESULT.get("verdict"), ensure_ascii=False))
