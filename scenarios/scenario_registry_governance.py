"""
Scenario — LIVE-REGISTRY GOVERNANCE loop (DRAFT-until-approved), offline by default
===================================================================================
Layer 3 (foundation) · the on-account realization of the offline dual-gate.

.. warning::
   **The DEFAULT run is 100% OFFLINE.** It injects a *fake* control client into
   :mod:`sentinel_harness.registry_live` and walks the governance lifecycle
   against it — ZERO AWS, ZERO network, deterministic. The ``--live`` path (see
   :func:`run_live`) drives the *real* ``bedrock-agentcore-control`` Registry API
   and is NEVER exercised by the test suite (CI must not call AWS).

WHY this scenario exists
------------------------
``sentinel_harness/registry.py`` encodes an OFFLINE dual-gate: a capability is
*live* only if it is BOTH approved in the declarative registry AND implemented in
code. The GA control-plane counterpart is a **Registry** created with
``approvalConfiguration.autoApproval=false``: a record you create lands in
``DRAFT`` and is **not live** until ``SubmitRegistryRecordForApproval`` + a human
approval flips it out of ``DRAFT``/``PENDING_APPROVAL``. That DRAFT-until-approved
lifecycle is the *on-account* realization of the offline "approved-only is live"
rule. This scenario proves that governance loop end to end — offline first, with a
documented opt-in to the real API.

The governance walk (offline default)
--------------------------------------
1. ``create_registry(auto_approval=False)`` -> a Registry ARN. autoApproval=false
   is the dual-gate: nothing this Registry holds is live without explicit approval.
2. ``create_skill_record`` (AGENT_SKILLS, inline SKILL.md) -> the record lands in
   ``DRAFT``.
3. ``list_records`` -> the record shows ``DRAFT`` (it exists but is NOT live).
4. ``submit_for_approval`` -> status transitions ``DRAFT`` -> ``PENDING_APPROVAL``.
5. ASSERT the record is NEVER live (``APPROVED``) before a human approves it: at no
   observed point in this walk does the record reach ``APPROVED``. Approval is the
   out-of-band human step the gate deliberately withholds.

What is real vs. stubbed
------------------------
- The DEFAULT run injects a stateful FAKE control client that mirrors the real
  service's autoApproval=false semantics (create -> DRAFT; submit ->
  PENDING_APPROVAL; approval is withheld). It records scrubbed evidence to
  ``evidence/registry_governance_result.json``.
- ``registry_live`` itself is LIVE-VERIFIED against the GA API (a real Registry +
  record were created and moved DRAFT -> PENDING_APPROVAL on a non-prod dev
  account). ``--live`` re-runs that against the real API with teardown; the test
  suite never sets it.

Egress & secrets posture
------------------------
- Egress is CONTROLLED. The default path has zero network I/O — the control client
  is a fake object; no boto3 call leaves the process.
- No secrets, no hardcoded account ids/ARNs. The fake mints ARNs against the
  ``000000000000`` placeholder account, and the evidence writer scrubs any
  12-digit account id out of ARNs before writing (mirroring the other scenarios).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from sentinel_harness import registry_live  # noqa: E402

# Placeholder account for the FAKE-minted ARNs (scrubbed again before write).
_PLACEHOLDER_ACCT = "000000000000"
_REGION = os.environ.get("SENTINEL_REGION", "us-east-1")

# Terminal "live" status: a record is live only once a human APPROVES it.
_APPROVED = "APPROVED"

RESULT: Dict[str, Any] = {"scenario": "registry_governance", "steps": []}

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
# The FAKE control client — a stateful stand-in for bedrock-agentcore-control
# that mirrors the REAL autoApproval=false governance semantics:
#
#   * create_registry(approvalConfiguration.autoApproval=false) -> registryArn
#   * create_registry_record(...) -> status DRAFT   (NOT live)
#   * list_registry_records(...)  -> the records with their current status
#   * submit_registry_record_for_approval(...) -> status PENDING_APPROVAL
#   * approval is WITHHELD: no method here ever flips a record to APPROVED, which
#     is exactly the point — human approval is the out-of-band gate.
#
# It is deliberately strict: an unexpected attribute access raises so a wrong code
# path is loud, never silently a no-op. This is the ONLY thing injected in the
# default run; boto3 is never touched.
# --------------------------------------------------------------------------
class FakeControlClient:
    """Deterministic, in-memory Registry control plane honoring autoApproval."""

    def __init__(self) -> None:
        self._registries: Dict[str, Dict[str, Any]] = {}
        self._records: Dict[str, Dict[str, Any]] = {}  # recordId -> record
        self._seq = 0

    def _next(self, kind: str) -> str:
        self._seq += 1
        return f"{kind}-{self._seq:04d}fake0000000000"  # opaque, deterministic

    # --- Registry ops ---
    def create_registry(self, **kwargs: Any) -> Dict[str, Any]:
        name = kwargs["name"]
        auto = bool(kwargs.get("approvalConfiguration", {}).get("autoApproval", False))
        reg_id = self._next("reg")
        arn = (f"arn:aws:bedrock-agentcore:{_REGION}:{_PLACEHOLDER_ACCT}:"
               f"registry/{reg_id}")
        self._registries[reg_id] = {
            "registryId": reg_id, "registryArn": arn, "name": name,
            "autoApproval": auto, "status": "ACTIVE",
        }
        # The service returns the id inside the ARN; expose both for the wrapper.
        return {"registryArn": arn, "registryId": reg_id}

    def get_registry(self, registryId: str) -> Dict[str, Any]:
        if registryId not in self._registries:
            raise self.exceptions.ResourceNotFoundException(registryId)
        return dict(self._registries[registryId])

    def delete_registry(self, registryId: str) -> Dict[str, Any]:
        self._registries.pop(registryId, None)
        return {}

    # --- Record ops ---
    def create_registry_record(self, **kwargs: Any) -> Dict[str, Any]:
        reg_id = kwargs["registryId"]
        auto = self._registries.get(reg_id, {}).get("autoApproval", False)
        rec_id = self._next("rec")
        arn = (f"arn:aws:bedrock-agentcore:{_REGION}:{_PLACEHOLDER_ACCT}:"
               f"registry/{reg_id}/record/{rec_id}")
        # autoApproval=false is the whole point: a new record is DRAFT, not live.
        status = _APPROVED if auto else "DRAFT"
        self._records[rec_id] = {
            "recordId": rec_id, "recordArn": arn, "name": kwargs["name"],
            "descriptorType": kwargs["descriptorType"], "status": status,
            "registryId": reg_id,
        }
        return {"recordArn": arn, "recordId": rec_id, "status": status}

    def list_registry_records(self, registryId: str) -> Dict[str, Any]:
        return {"registryRecords": [
            dict(r) for r in self._records.values()
            if r["registryId"] == registryId
        ]}

    def submit_registry_record_for_approval(
        self, registryId: str, recordId: str
    ) -> Dict[str, Any]:
        r = self._records.get(recordId)
        if r is None:
            raise self.exceptions.ResourceNotFoundException(recordId)
        # DRAFT -> PENDING_APPROVAL. It does NOT become APPROVED here: a human still
        # has to approve. That withheld step is the governance gate.
        r["status"] = "PENDING_APPROVAL"
        return {"recordId": recordId, "status": r["status"]}

    # --- exceptions namespace (delete_registry references it) ---
    class exceptions:  # noqa: N801 - mirrors boto3 client.exceptions shape
        class ResourceNotFoundException(Exception):
            pass

    def __getattr__(self, item: str) -> Any:  # pragma: no cover - defensive
        raise AssertionError(
            f"registry-governance offline run must not touch _control.{item}"
        )


def _record_status(records: List[Dict[str, Any]], record_id: str) -> Optional[str]:
    for r in records:
        if r.get("recordId") == record_id:
            return r.get("status")
    return None


def run_offline(fake: Optional[FakeControlClient] = None) -> Dict[str, Any]:
    """Drive the governance walk against an injected FAKE control client (no AWS).

    This is the DEFAULT run and the acceptance proof: create_registry(autoApproval
    =false) -> create_skill_record (DRAFT) -> list_records shows DRAFT ->
    submit_for_approval (PENDING_APPROVAL) -> assert never live-until-approved.
    """
    fake = fake or FakeControlClient()
    # Inject the fake into the module under test. registry_live does
    # ``from .core import _control`` so the name to patch lives in registry_live.
    original = registry_live._control
    registry_live._control = fake
    try:
        # --- Step 1: create the Registry with the governance-safe gate on. ---
        arn = registry_live.create_registry(
            "sentinel-governance-registry",
            description="Offline governance-loop proof (DRAFT-until-approved).",
            auto_approval=False,
        )
        registry_created = bool(arn) and arn.startswith("arn:aws:")
        # The wrapper returns the ARN; the fake also exposed registryId on create,
        # which we recover from the ARN tail for the subsequent record ops.
        registry_id = arn.split("registry/", 1)[1]
        rec("create_registry", registry_created,
            {"registryArn": arn, "auto_approval": False,
             "note": "autoApproval=false => a record is DRAFT (not live) until approved."})

        # --- Step 2: create a skill record -> lands in DRAFT. ---
        created = registry_live.create_skill_record(
            registry_id, "soc-triage",
            skill_md="# soc-triage\nInline SKILL.md for the SOC triage capability.\n",
            description="SOC triage agent-skills record (inline SKILL.md).",
        )
        record_created_draft = created.get("status") == "DRAFT"
        rec("create_skill_record", record_created_draft,
            {"recordArn": created.get("recordArn"), "status": created.get("status")})

        # --- Step 3: list_records shows the record as DRAFT (exists, NOT live). ---
        records = registry_live.list_records(registry_id)
        record_id = next((r["recordId"] for r in records
                          if r.get("name") == "soc-triage"), None)
        draft_listed = _record_status(records, record_id) == "DRAFT"
        rec("list_records_shows_draft", draft_listed,
            {"count": len(records), "record_id": record_id,
             "status": _record_status(records, record_id)})

        # --- Step 4: submit_for_approval -> DRAFT transitions to PENDING_APPROVAL. ---
        submit = registry_live.submit_for_approval(registry_id, record_id)
        submit_moved_to_pending_approval = submit.get("status") == "PENDING_APPROVAL"
        rec("submit_for_approval", submit_moved_to_pending_approval,
            {"record_id": record_id, "status": submit.get("status"),
             "transition": "DRAFT -> PENDING_APPROVAL"})

        # --- Step 5: assert the record is NEVER live (APPROVED) until a human approves. ---
        after = registry_live.list_records(registry_id)
        final_status = _record_status(after, record_id)
        # Across the whole walk the record only ever held DRAFT then PENDING_APPROVAL;
        # it never reached APPROVED because approval is the withheld human gate.
        not_live_until_approved = final_status != _APPROVED and final_status in (
            "DRAFT", "PENDING_APPROVAL",
        )
        rec("not_live_until_approved", not_live_until_approved,
            {"final_status": final_status,
             "live_status_would_be": _APPROVED,
             "note": ("The record is PENDING_APPROVAL, NOT live. Only an explicit "
                      "human approval (out of band) flips it to APPROVED/live.")})

        closed = all([
            registry_created,
            record_created_draft,
            draft_listed,
            submit_moved_to_pending_approval,
            not_live_until_approved,
        ])
        flags = {
            "registry_created": registry_created,
            "record_created_draft": record_created_draft,
            "submit_moved_to_pending_approval": submit_moved_to_pending_approval,
            "not_live_until_approved": not_live_until_approved,
            "closed": closed,
        }
        RESULT["flags"] = flags
        RESULT["verdict"] = {
            **flags,
            "final_status": final_status,
            "note": (
                "OFFLINE governance proof: a live Registry created with "
                "autoApproval=false is the on-account dual-gate — a record is "
                "created in DRAFT, listed as DRAFT (exists but NOT live), and "
                "submit_for_approval moves it DRAFT -> PENDING_APPROVAL. It is "
                "NEVER live (APPROVED) until an explicit human approval flips it, "
                "mirroring the offline registry's 'approved-only is live' rule. "
                "The control client is a fake here (zero AWS); registry_live is "
                "live-verified against the GA bedrock-agentcore-control API. Run "
                "with --live to drive the real API (never done in tests)."
            ),
        }
        rec("verdict", closed, RESULT["verdict"])
        return RESULT
    finally:
        registry_live._control = original


def live_note() -> str:
    """Return what the --live path does (real API), without running it."""
    return (
        "LIVE mode drives the REAL bedrock-agentcore-control Registry API: "
        "create_registry(autoApproval=false) -> create_skill_record (DRAFT) -> "
        "list_records -> submit_for_approval (PENDING_APPROVAL) -> delete_registry "
        "(teardown). registry_live is already live-verified (a real Registry + "
        "record were created and moved DRAFT -> PENDING_APPROVAL on a non-prod dev "
        "account). This requires AWS credentials + SENTINEL_EXECUTION_ROLE_ARN and "
        "is NEVER run by the test suite. The offline default proves the same "
        "governance loop deterministically first."
    )


def run_live() -> Dict[str, Any]:  # pragma: no cover - opt-in, real AWS, never in CI
    """Drive the governance walk against the REAL Registry API, then tear down.

    Guarded: only reached via ``--live`` on an explicit human invocation with AWS
    credentials. The test suite never calls this. Every failure surfaces as a
    ``RegistryLiveError`` from ``registry_live`` (never swallowed)."""
    RESULT["live_note"] = live_note()
    registry_id = None
    try:
        arn = registry_live.create_registry(
            "sentinel-governance-registry",
            description="Live governance-loop proof (DRAFT-until-approved).",
            auto_approval=False,
        )
        rec("live_create_registry", bool(arn), {"registryArn": arn})
        registry = registry_live.get_registry(arn.split("registry/", 1)[1])
        registry_id = registry.get("registryId") or arn.split("registry/", 1)[1]

        created = registry_live.create_skill_record(
            registry_id, "soc-triage",
            skill_md="# soc-triage\nInline SKILL.md.\n",
        )
        rec("live_create_skill_record", created.get("status") in ("DRAFT", "CREATING"),
            {"status": created.get("status")})

        records = registry_live.list_records(registry_id)
        record_id = next((r["recordId"] for r in records
                          if r.get("name") == "soc-triage"), None)
        submit = registry_live.submit_for_approval(registry_id, record_id)
        rec("live_submit_for_approval",
            submit.get("status") == "PENDING_APPROVAL", submit)
        return RESULT
    finally:
        if registry_id:
            registry_live.delete_registry(registry_id)
            rec("live_teardown", True, {"deleted_registry": registry_id})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--live", action="store_true",
        help="drive the REAL bedrock-agentcore-control Registry API (needs AWS "
             "creds; NEVER run in tests). Default is the offline fake-client walk.")
    args = parser.parse_args()

    if args.live:
        print(live_note())
        run_live()
    else:
        run_offline()

    out = os.path.join(REPO_ROOT, "evidence", "registry_governance_result.json")
    json.dump(_scrub(RESULT), open(out, "w"), indent=2, ensure_ascii=False, default=str)
    print("\nsaved evidence/registry_governance_result.json  ·  verdict:",
          json.dumps(RESULT.get("verdict") or RESULT.get("flags"), ensure_ascii=False))
