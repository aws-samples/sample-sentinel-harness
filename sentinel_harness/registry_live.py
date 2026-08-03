"""
sentinel-harness · LIVE AgentCore Registry client (control plane)
=================================================================
A thin, deterministic wrapper over the **real** ``bedrock-agentcore-control``
Registry API — the GA control-plane counterpart of the offline dual-gate in
``registry.py``. Where ``registry.py`` reconciles a declarative allowlist against
a code factory map (pure, offline governance), THIS module actually provisions a
Registry and its records on AWS and mirrors the same governance semantics:

    autoApproval=false  ⇒  a new record lands in ``DRAFT`` and is **not live**
    until ``SubmitRegistryRecordForApproval`` + a human approval flips it.

That DRAFT-until-approved lifecycle is the on-account realization of the
"a capability is live only after review" rule the offline registry encodes.

Verified against the live service model (2026-07, us-east-1): the operations
``CreateRegistry`` / ``GetRegistry`` / ``DeleteRegistry`` / ``CreateRegistryRecord``
/ ``SubmitRegistryRecordForApproval`` / ``ListRegistryRecords`` are REAL (a Registry
and a record were created on a non-prod dev account). Descriptor types:
``MCP`` / ``A2A`` / ``CUSTOM`` / ``AGENT_SKILLS`` — the first three map to our
tools / specialists, the last to ``skills/<name>/SKILL.md`` (inline content, so
no reachable URL is required).

Nothing here is customer- or company-specific. Region comes from ``SENTINEL_REGION``
(default us-east-1); the client is the shared ``core._control`` so credentials and
retries match the rest of the library.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from .core import _control
from .logutil import get_logger

# Descriptor types the live Registry accepts (verified against the service model).
DESCRIPTOR_TYPES = ("MCP", "A2A", "CUSTOM", "AGENT_SKILLS")

# The statuses a NOT-YET-LIVE record may legitimately report right after creation
# (INV-REGISTRY-1). `CREATING` is the transient state before the service settles the
# record into `DRAFT`; both mean "exists, not callable".
#
# Anything else — `ACTIVE`, `APPROVED`, `LIVE`, an empty string, a missing field — means
# either the record went live without the human step this module promises, or we cannot
# tell. Both must be refused: `approvalConfiguration` is set on the REGISTRY, and
# `create_registry_record` cannot see it, so a `registry_id` pointing at an
# auto-approving registry, an API version that ignores the field, or a partition with
# different behaviour would all produce a live record while this module reported success.
NOT_YET_LIVE_STATUSES = frozenset({"DRAFT", "CREATING"})

# clientToken shape (verified against the bedrock-agentcore-control model): pattern
# `[a-zA-Z0-9](-*[a-zA-Z0-9]){0,256}` (alphanumerics + hyphens ONLY, no trailing
# hyphen), min length 33, max length 256. Resource NAMES allow a wider charset
# (underscore/dot/slash), so a token that embeds a raw name verbatim can violate the
# token pattern — and botocore does NOT check string patterns client-side, so it
# fails only on the live call. We derive a deterministic-per-name token unless one
# is supplied, sanitized to the token charset and bounded on BOTH ends.
_MIN_CLIENT_TOKEN = 33
_MAX_CLIENT_TOKEN = 256


class RegistryLiveError(RuntimeError):
    """Raised when a live Registry operation cannot be completed."""


def _client_token(seed: str) -> str:
    """Build a deterministic, pattern-valid idempotency token from a seed.

    A caller-stable token makes ``create_*`` idempotent across retries. The seed
    often embeds a resource name, which may contain underscore/dot/slash — all
    ILLEGAL in a clientToken — so we sanitize to ``[A-Za-z0-9-]`` (collapsing runs
    of illegal chars to a single hyphen), pad to the 33-char minimum, and cap at the
    256-char maximum. The result always matches the ClientToken pattern and length."""
    base = f"sentinel-{seed}-idempotency"
    # Collapse any run of non-[A-Za-z0-9] to a single hyphen; strip leading/trailing
    # hyphens (the pattern forbids a trailing hyphen and requires an alnum start).
    base = re.sub(r"[^A-Za-z0-9]+", "-", base).strip("-") or "sentinel"
    if len(base) < _MIN_CLIENT_TOKEN:
        base = base + "-" + "0" * (_MIN_CLIENT_TOKEN - len(base) - 1)
    if len(base) > _MAX_CLIENT_TOKEN:
        base = base[:_MAX_CLIENT_TOKEN].rstrip("-")
    return base


def create_registry(
    name: str,
    *,
    description: str = "",
    auto_approval: bool = False,
    authorizer_type: str = "AWS_IAM",
    client_token: Optional[str] = None,
) -> str:
    """Create a governance Registry and return its ARN.

    ``auto_approval=False`` (the default, and the governance-safe choice) means a
    record created later is ``DRAFT`` until explicitly approved — mirroring the
    offline registry's "approved-only is live" gate.
    """
    if not name:
        raise RegistryLiveError("registry name is required")
    if authorizer_type not in ("AWS_IAM", "CUSTOM_JWT"):
        raise RegistryLiveError(
            f"authorizer_type must be AWS_IAM or CUSTOM_JWT, got {authorizer_type!r}"
        )
    if auto_approval:
        # INV-REGISTRY-2: creating an UNGOVERNED registry is allowed but never silent.
        # Every record in it goes live with no human step, which is the opposite of the
        # DRAFT-until-approved gate this module exists to provide. The parameter stays
        # (an adopter may genuinely want it for a throwaway dev registry), but an
        # operator reading the logs must be able to see that the gate was waived —
        # the degradation-leaves-a-trace rule applied to a deliberate choice.
        get_logger(__name__).warning(
            "create_registry(%r, auto_approval=True): every record in this registry "
            "will go LIVE with NO human approval step. The DRAFT-until-approved gate "
            "is waived for this registry.", name,
        )
    # INV-REGISTRY-3: the idempotency token must distinguish a GOVERNED request from an
    # ungoverned one. `clientToken` is `idempotencyToken: true` in the service model —
    # "If this token matches a previous request, the service ignores the request, but
    # doesn't return an error." The old seed was `f"registry-{name}"`, a pure function of
    # the NAME: it ignored `auto_approval` entirely, and `_client_token` collapses the
    # legal name characters `_ . / -` all to `-` (8 legal names -> 2 tokens). So a
    # governed `create_registry(name, auto_approval=False)` issued after an ungoverned
    # `create_registry(name, auto_approval=True)` sent a byte-identical token and, on
    # replay, returned the AUTO-APPROVING registry's ARN with no error — SecOps believes
    # it owns a DRAFT-gated registry and holds the ungoverned one. Folding the approval
    # posture into the seed means the two can never share a token.
    posture = "autoapprove" if auto_approval else "governed"
    args: Dict[str, Any] = {
        "name": name,
        "authorizerType": authorizer_type,
        "approvalConfiguration": {"autoApproval": auto_approval},
        "clientToken": client_token or _client_token(f"registry-{posture}-{name}"),
    }
    if description:
        args["description"] = description
    try:
        resp = _control.create_registry(**args)
    except Exception as exc:  # surface, never swallow
        raise RegistryLiveError(f"create_registry({name!r}) failed: {exc}") from exc
    arn = resp.get("registryArn")
    if not arn:
        raise RegistryLiveError(f"create_registry returned no registryArn: {resp!r}")
    # INV-REGISTRY-3: VERIFY the posture, do not trust the request. The token guard above
    # closes the collision this module can cause, but it cannot cover a caller-supplied
    # `client_token`, a name-conflict resolved by the service BEFORE idempotency, or any
    # other path by which the ARN we hold names a registry whose approvalConfiguration is
    # not what we asked for. The only trustworthy check is to read it back — same
    # "verify, don't assert" shape as the INV-REGISTRY-1 fix one layer down.
    _assert_approval_posture(arn, auto_approval)
    return arn


def _assert_approval_posture(arn: str, expected_auto_approval: bool) -> None:
    """Read the registry back and refuse if its autoApproval is not what we requested.

    A best-effort guard: if ``GetRegistry`` does not surface ``approvalConfiguration``
    we do NOT fail (the field is optional in some API versions, and a false refusal of a
    correctly-created registry would be its own outage). But when the field IS present
    and disagrees, that is the exact confused-registry this defends against, and it is
    refused — INV-BOUNDARY-5's rule that "we could not tell" must not silently pass
    applies only where we genuinely could tell.
    """
    registry_id = arn.rsplit("/", 1)[-1] if "/" in arn else arn
    try:
        info = get_registry(registry_id)
    except RegistryLiveError:
        # get_registry already wraps+surfaces; a read-back failure should not mask the
        # create, so we let the ARN stand rather than inventing a failure. The token
        # guard above is still in force for the collision this module can cause.
        return
    cfg = info.get("approvalConfiguration")
    if not isinstance(cfg, dict) or "autoApproval" not in cfg:
        return  # the field is not being reported; nothing to verify against
    actual = cfg["autoApproval"]
    if bool(actual) != bool(expected_auto_approval):
        raise RegistryLiveError(
            f"create_registry({registry_id!r}) requested autoApproval="
            f"{expected_auto_approval!r} but the registry actually has "
            f"autoApproval={actual!r}. The ARN returned names a registry with a "
            f"DIFFERENT governance posture than requested — most likely an idempotency "
            f"replay of an earlier create with the opposite posture, or a name-conflict "
            f"resolved to an existing registry. Refusing rather than reporting a "
            f"governed registry that is not one."
        )


def get_registry(registry_id: str) -> Dict[str, Any]:
    """Return the live Registry record (status/name/arn/...)."""
    try:
        resp = _control.get_registry(registryId=registry_id)
    except Exception as exc:
        raise RegistryLiveError(f"get_registry({registry_id!r}) failed: {exc}") from exc
    return {k: v for k, v in resp.items() if k != "ResponseMetadata"}


def delete_registry(registry_id: str) -> None:
    """Delete a Registry (teardown). Idempotent-friendly: a missing id is not fatal."""
    try:
        _control.delete_registry(registryId=registry_id)
    except _control.exceptions.ResourceNotFoundException:  # type: ignore[attr-defined]
        return
    except Exception as exc:
        raise RegistryLiveError(f"delete_registry({registry_id!r}) failed: {exc}") from exc


def _skill_descriptor(inline_md: str) -> Dict[str, Any]:
    return {"agentSkills": {"skillMd": {"inlineContent": inline_md}}}


def _custom_descriptor(inline_content: str) -> Dict[str, Any]:
    return {"custom": {"inlineContent": inline_content}}


def create_skill_record(
    registry_id: str,
    name: str,
    skill_md: str,
    *,
    description: str = "",
    client_token: Optional[str] = None,
) -> Dict[str, str]:
    """Register a skill (AGENT_SKILLS, inline SKILL.md) — lands in DRAFT.

    Returns ``{"recordArn": ..., "status": ...}``. Because the Registry is created
    with ``autoApproval=False``, ``status`` is ``DRAFT`` (or ``CREATING`` then
    ``DRAFT``): the record exists but is NOT live until approved.
    """
    return _create_record(
        registry_id, name, "AGENT_SKILLS", _skill_descriptor(skill_md),
        description=description, client_token=client_token,
    )


def create_custom_record(
    registry_id: str,
    name: str,
    inline_content: str,
    *,
    description: str = "",
    client_token: Optional[str] = None,
) -> Dict[str, str]:
    """Register a CUSTOM record (e.g. a tool's declarative spec) — lands in DRAFT."""
    return _create_record(
        registry_id, name, "CUSTOM", _custom_descriptor(inline_content),
        description=description, client_token=client_token,
    )


def _create_record(
    registry_id: str,
    name: str,
    descriptor_type: str,
    descriptors: Dict[str, Any],
    *,
    description: str = "",
    client_token: Optional[str] = None,
) -> Dict[str, str]:
    if descriptor_type not in DESCRIPTOR_TYPES:
        raise RegistryLiveError(
            f"descriptor_type must be one of {DESCRIPTOR_TYPES}, got {descriptor_type!r}"
        )
    args: Dict[str, Any] = {
        "registryId": registry_id,
        "name": name,
        "descriptorType": descriptor_type,
        "descriptors": descriptors,
        "clientToken": client_token or _client_token(f"record-{name}"),
    }
    if description:
        args["description"] = description
    try:
        resp = _control.create_registry_record(**args)
    except Exception as exc:
        raise RegistryLiveError(
            f"create_registry_record({name!r}) failed: {exc}"
        ) from exc
    status = resp.get("status")
    # INV-REGISTRY-1: VERIFY the DRAFT claim, do not merely assert it.
    #
    # This module's headline guarantee is "autoApproval=false => a new record lands in
    # DRAFT and is NOT live until approved". It used to SEND that configuration and
    # return whatever status came back — so a backend reporting ACTIVE / APPROVED /
    # LIVE / "" / nothing was passed through as success. Reproduced across all five.
    #
    # The gap is structural, not hypothetical: `approvalConfiguration` is set on the
    # REGISTRY, and this call cannot see it. A `registry_id` naming an auto-approving
    # registry, an API version that ignores the field, or a partition with different
    # behaviour each produce a live record while the governance report says DRAFT.
    #
    # A Registry record is what makes a tool or agent discoverable and callable, so an
    # unapproved-but-live record is an ungoverned capability. Refusing is right: the
    # caller asked for a governed record and did not get one, and INV-BOUNDARY-5's rule
    # applies — "we could not tell" must never render as the safe answer.
    if status not in NOT_YET_LIVE_STATUSES:
        raise RegistryLiveError(
            f"create_registry_record({name!r}) returned status {status!r}, not one of "
            f"{sorted(NOT_YET_LIVE_STATUSES)}. The record may be LIVE without the human "
            f"approval this module guarantees — check the registry's "
            f"approvalConfiguration (autoApproval must be false) before trusting it. "
            f"Refusing rather than reporting a governed record that is not one."
        )
    return {"recordArn": resp.get("recordArn", ""), "status": status}


def list_records(registry_id: str) -> List[Dict[str, Any]]:
    """List EVERY record in the Registry (name/type/status/arn), across all pages.

    INV-REGISTRY-4: this used to read only the first page — one
    ``list_registry_records`` call, returning ``resp.get("registryRecords", [])`` and
    ignoring ``nextToken``. The docstring said "every record" and the caller is a
    GOVERNANCE listing, so an approved (live) record beyond the first page was simply
    absent from the audit view, which read as complete. A truncated governance listing
    is a silent blind spot in exactly the direction that matters: a live capability you
    cannot see. The service models both ``nextToken`` and ``maxResults`` on this op, so
    pagination is the contract, not an optimization.
    """
    records: List[Dict[str, Any]] = []
    next_token: Optional[str] = None
    seen_tokens: set[str] = set()
    while True:
        kwargs: Dict[str, Any] = {"registryId": registry_id}
        if next_token:
            kwargs["nextToken"] = next_token
        try:
            resp = _control.list_registry_records(**kwargs)
        except Exception as exc:
            raise RegistryLiveError(
                f"list_registry_records({registry_id!r}) failed: {exc}"
            ) from exc
        records.extend(resp.get("registryRecords", []))
        next_token = resp.get("nextToken")
        if not next_token:
            return records
        # A backend that echoes the same token would loop forever; refuse rather than
        # hang, since a governance listing that never returns is its own failure.
        if next_token in seen_tokens:
            raise RegistryLiveError(
                f"list_registry_records({registry_id!r}) returned a repeated nextToken "
                f"{next_token!r}; refusing to loop. The listing may be incomplete."
            )
        seen_tokens.add(next_token)


def submit_for_approval(registry_id: str, record_id: str) -> Dict[str, Any]:
    """Submit a DRAFT record for approval — the governance gate.

    With ``autoApproval=False`` this is the step a human/automation runs to move a
    record out of DRAFT toward live; it is the on-account analogue of flipping a
    tool to ``approved`` in the offline registry.
    """
    try:
        resp = _control.submit_registry_record_for_approval(
            registryId=registry_id, recordId=record_id
        )
    except Exception as exc:
        raise RegistryLiveError(
            f"submit_registry_record_for_approval({record_id!r}) failed: {exc}"
        ) from exc
    return {k: v for k, v in resp.items() if k != "ResponseMetadata"}
