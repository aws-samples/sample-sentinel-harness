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

from typing import Any, Dict, List, Optional

from .core import _control

# Descriptor types the live Registry accepts (verified against the service model).
DESCRIPTOR_TYPES = ("MCP", "A2A", "CUSTOM", "AGENT_SKILLS")

# clientToken has a min length of 33 (same class of constraint as a harness
# session id). We derive a deterministic-per-name token unless one is supplied.
_MIN_CLIENT_TOKEN = 33


class RegistryLiveError(RuntimeError):
    """Raised when a live Registry operation cannot be completed."""


def _client_token(seed: str) -> str:
    """Build a >=33-char idempotency token from a seed (deterministic per seed).

    A caller-stable token makes ``create_*`` idempotent across retries; we pad a
    namespaced seed so it always clears the API's 33-char minimum.
    """
    base = f"sentinel-{seed}-idempotency"
    if len(base) < _MIN_CLIENT_TOKEN:
        base = base + "-" + "0" * (_MIN_CLIENT_TOKEN - len(base))
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
    args: Dict[str, Any] = {
        "name": name,
        "authorizerType": authorizer_type,
        "approvalConfiguration": {"autoApproval": auto_approval},
        "clientToken": client_token or _client_token(f"registry-{name}"),
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
    return arn


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
    return {"recordArn": resp.get("recordArn", ""), "status": resp.get("status", "")}


def list_records(registry_id: str) -> List[Dict[str, Any]]:
    """List every record in the Registry (name/type/status/arn)."""
    try:
        resp = _control.list_registry_records(registryId=registry_id)
    except Exception as exc:
        raise RegistryLiveError(
            f"list_registry_records({registry_id!r}) failed: {exc}"
        ) from exc
    return resp.get("registryRecords", [])


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
