"""
sentinel-harness · Agent Factory (config-driven provision-at-scale)
====================================================================
The single-file loader turns ONE ``harness.yaml`` into ONE live harness. Real
deployments run a *fleet*: many harnesses across test → staging → prod, born
from one manifest, provisioned repeatably, and torn down cleanly. That is the
blueprint's Layer-3 "Agent Factory + provision-at-scale" item — this module.

What the factory adds on top of ``loader.load_harness_config`` + ``core.create_harness``
---------------------------------------------------------------------------------------
- **Dry-run first.** ``provision_fleet(manifest, dry_run=True)`` resolves and
  validates EVERY config (yaml read, ${ENV} expansion, name-rule check, tag
  synthesis) WITHOUT a single AWS call. Provisioning at scale is fire-and-forget
  and server-side validation is silent (image-editing gotcha), so we fail loudly
  here, locally, before anything ships.
- **Idempotency.** A harness whose name already exists is left alone (``exists``),
  never recreated. One ``list_harnesses`` call is shared across the whole fleet so
  re-running the manifest is cheap and safe.
- **Environment tagging + cross-env tag-guard.** Every harness is stamped with an
  env label (``SENTINEL_ENV`` or the manifest ``env``) under the ``sentinel:env``
  tag. If a harness of the same name already lives under a DIFFERENT env tag, the
  factory REFUSES to touch it — a ``prod`` fleet run must never clobber a ``staging``
  harness that happens to share a name. This is the blueprint's tag-guard that
  "prevents cross-env update".
- **Teardown.** ``teardown_fleet`` deletes a whole fleet by manifest (resolving the
  exact names) or by a name prefix, reusing ``core.delete_harness``.

Manifest shape
--------------
A manifest is a dict (or a path to a yaml file holding that dict)::

    env: staging                       # optional; SENTINEL_ENV overrides nothing,
                                       # it is the fallback when this key is absent
    name_prefix: sentinel_             # optional; teardown-by-prefix convenience
    tags:                              # optional; fleet-wide tags merged into each harness
      team: secops
    harnesses:                         # required; each entry is one harness
      - config: harnesses/alert-triage/harness.yaml   # path -> loader.load_harness_config
      - config: harnesses/detection-eng/harness.yaml
        tags: { tier: critical }       # optional per-harness tags (override fleet tags)
      - name: adhoc_probe              # OR an inline kwargs dict (no yaml)
        system_prompt: "You are a probe."
        model: { bedrockModelConfig: { modelId: global.anthropic.claude-haiku-4-5 } }

Each ``harnesses`` entry is either ``{config: <path>}`` (delegated to the loader,
so ${ENV} expansion / inline-gate injection / prompt-file resolution all apply) or
an inline dict of ``core.create_harness`` kwargs (must carry ``name`` +
``system_prompt``). ``tags`` at entry level merge over fleet-level ``tags``.

No AWS calls happen during resolution/validation — only ``provision_fleet`` (when
not ``dry_run``) and ``teardown_fleet`` reach the control plane, and only through
``core`` (never a raw boto3 client here). Exceptions are never swallowed.

Nothing in this file is customer- or company-specific.
"""
from __future__ import annotations

import os
import re
from typing import Any

from . import core, loader

# The env tag key is namespaced so it never collides with a user's own tags.
ENV_TAG_KEY = "sentinel:env"

# Same naming rule core.create_harness enforces server-side ([a-zA-Z][a-zA-Z0-9_]{0,39}).
# We check it during dry-run so a bad name fails locally, not after a round trip.
# \Z (not $) so a trailing newline is rejected: '$' matches before a final \n,
# which would let 'name\n' pass local validation and fail only server-side.
_NAME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]{0,39}\Z")


class FactoryError(RuntimeError):
    """Raised when a manifest is malformed or a fleet operation is unsafe.

    A dedicated type so callers can distinguish a manifest/guard problem (fix the
    config) from a boto/control-plane error (retry / check AWS) — we never collapse
    the two by swallowing one into the other."""


# --------------------------------------------------------------------------- env
def _fleet_env(manifest: dict) -> str:
    """The env label stamped onto every harness in this fleet.

    ``SENTINEL_ENV`` wins (12-factor: the deploy pipeline sets it per stage); the
    manifest ``env`` key is the in-repo default; ``"dev"`` is the safe fallback so a
    forgotten env never silently lands in prod."""
    return os.environ.get("SENTINEL_ENV") or manifest.get("env") or "dev"


# ----------------------------------------------------------------- manifest read
def _load_manifest(manifest_or_path: Any) -> dict:
    """Accept an already-built dict or a path to a yaml manifest. A path is read via
    the loader's yaml helper so we share one PyYAML dependency + error style."""
    if isinstance(manifest_or_path, dict):
        return manifest_or_path
    if isinstance(manifest_or_path, str):
        # Reuse loader._read_yaml so a missing/PyYAML-less/non-mapping file raises the
        # same clear errors the loader already documents — no divergent behavior.
        return loader._read_yaml(os.path.abspath(manifest_or_path))
    raise FactoryError(
        f"manifest must be a dict or a path string, got {type(manifest_or_path).__name__}"
    )


# ------------------------------------------------------------- config resolution
def _resolve_entry(entry: Any, fleet_tags: dict, env: str, index: int) -> dict:
    """Resolve ONE manifest ``harnesses`` entry into create_harness kwargs + tags.

    Offline only. A ``{config: <path>}`` entry is delegated to
    ``loader.load_harness_config`` (yaml, ${ENV} expansion, inline-gate injection);
    any other dict is treated as inline create_harness kwargs. Per-entry ``tags``
    merge OVER ``fleet_tags``; the env tag is always stamped last so it cannot be
    overridden by a manifest typo."""
    if not isinstance(entry, dict):
        raise FactoryError(
            f"harnesses[{index}] must be a mapping (a {{config: path}} or inline kwargs), "
            f"got {type(entry).__name__}"
        )

    entry_tags = entry.get("tags") or {}
    if not isinstance(entry_tags, dict):
        raise FactoryError(f"harnesses[{index}].tags must be a mapping, got {type(entry_tags).__name__}")

    if "config" in entry:
        config_path = entry["config"]
        if not isinstance(config_path, str):
            raise FactoryError(f"harnesses[{index}].config must be a path string")
        kwargs = loader.load_harness_config(config_path)
    else:
        # Inline kwargs: shallow-copy and strip the factory-only 'tags' key so the
        # rest passes straight to core.create_harness.
        kwargs = {k: v for k, v in entry.items() if k != "tags"}
        if not kwargs.get("name") or not kwargs.get("system_prompt"):
            raise FactoryError(
                f"harnesses[{index}] inline entry needs both 'name' and 'system_prompt' "
                f"(or use {{config: <harness.yaml>}})"
            )

    name = kwargs.get("name")
    if not isinstance(name, str) or not _NAME_RE.match(name):
        raise FactoryError(
            f"harnesses[{index}] resolves to invalid harnessName {name!r} — must match "
            r"[a-zA-Z][a-zA-Z0-9_]{0,39} (no hyphens)."
        )

    # Tag precedence (lowest -> highest): fleet tags, entry tags, then the env tag.
    tags = {**fleet_tags, **entry_tags, ENV_TAG_KEY: env}
    return {"name": name, "kwargs": kwargs, "tags": tags}


def _resolve_fleet(manifest: dict) -> tuple[list[dict], str]:
    """Validate the manifest and resolve every entry. Pure/offline — raises loudly on
    the first structural problem or duplicate name. Returns (resolved, env)."""
    if not isinstance(manifest, dict):
        raise FactoryError(f"manifest must be a mapping, got {type(manifest).__name__}")

    entries = manifest.get("harnesses")
    if not isinstance(entries, list) or not entries:
        raise FactoryError("manifest missing required non-empty 'harnesses' list")

    fleet_tags = manifest.get("tags") or {}
    if not isinstance(fleet_tags, dict):
        raise FactoryError(f"manifest 'tags' must be a mapping, got {type(fleet_tags).__name__}")

    env = _fleet_env(manifest)
    resolved = [_resolve_entry(e, fleet_tags, env, i) for i, e in enumerate(entries)]

    # Duplicate names within one manifest are a config bug — catch it before AWS.
    seen: set[str] = set()
    for r in resolved:
        if r["name"] in seen:
            raise FactoryError(f"duplicate harnessName {r['name']!r} in manifest")
        seen.add(r["name"])
    return resolved, env


# --------------------------------------------------------------- existing lookup
def _index_existing() -> dict[str, dict]:
    """Map name -> existing harness summary via ONE list_harnesses call, shared across
    the fleet (so provisioning N harnesses costs one list, not N)."""
    return {h["harnessName"]: h for h in core.list_harnesses()}


def _existing_env(summary: dict) -> str | None:
    """The env tag on an existing harness, or None if untagged. list_harnesses returns
    ``tags`` when present; treat a missing/empty tag map as 'no env claim'."""
    return (summary.get("tags") or {}).get(ENV_TAG_KEY)


# ------------------------------------------------------------------- public API
def provision_fleet(manifest: Any, *, dry_run: bool = False) -> list[dict]:
    """Provision a fleet of harnesses from one manifest. Idempotent + env-guarded.

    Returns one result dict per harness, in manifest order::

        {"name": str, "action": "created" | "exists" | "would_create", "harnessId"?: str}

    - ``dry_run=True`` resolves + validates every config and reports what WOULD happen
      with ZERO AWS calls (not even list_harnesses) — the local parity check that
      guards against silent server-side validation failures at scale.
    - Existing harnesses are skipped (``exists``); creation is idempotent.
    - **Tag-guard:** if a harness of the same name already exists under a DIFFERENT
      ``sentinel:env`` tag, this raises ``FactoryError`` rather than mutating a
      cross-env resource. (We never *update* here — provisioning is create-or-skip —
      but the guard also refuses to adopt a foreign-env harness as our own.)
    """
    resolved, env = _resolve_fleet(manifest)

    if dry_run:
        # No AWS at all — pure resolution/validation already happened above.
        return [{"name": r["name"], "action": "would_create"} for r in resolved]

    existing = _index_existing()
    results: list[dict] = []
    for r in resolved:
        name = r["name"]
        prior = existing.get(name)
        if prior is not None:
            prior_env = _existing_env(prior)
            # Tag-guard: an existing harness claimed by another env is off-limits.
            if prior_env is not None and prior_env != env:
                raise FactoryError(
                    f"cross-env tag-guard: harness {name!r} already exists under env "
                    f"{prior_env!r} but this fleet is env {env!r}; refusing to touch it. "
                    f"Use a distinct name per env, or run against the matching SENTINEL_ENV."
                )
            results.append({"name": name, "action": "exists", "harnessId": prior.get("harnessId")})
            continue

        harness = core.create_harness(**r["kwargs"], tags=r["tags"])
        results.append({"name": name, "action": "created", "harnessId": harness.get("harnessId")})
    return results


def teardown_fleet(manifest_or_prefix: Any) -> list[str]:
    """Delete a fleet. Two addressing modes:

    - **By prefix** (a plain string that is NOT a manifest path): delegates to
      ``core.cleanup(prefix)`` — deletes every harness whose name starts with it.
    - **By manifest** (a dict, or a path to a yaml manifest): resolves the exact
      harness names and deletes only those that currently exist. This is the precise
      inverse of ``provision_fleet`` — it will not touch a same-prefixed harness that
      is not in the manifest.

    Returns the list of deleted harness names. Deletion errors are not swallowed."""
    # A bare prefix string is anything that is not an on-disk manifest file.
    if isinstance(manifest_or_prefix, str) and not os.path.isfile(manifest_or_prefix):
        # Guard: an empty/whitespace prefix would delegate to core.cleanup("") which
        # matches EVERY harness (''.startswith('') is True) — a catastrophic
        # delete-everything. Refuse it explicitly.
        if not manifest_or_prefix.strip():
            raise FactoryError(
                "refusing an empty teardown prefix — it would match and delete "
                "EVERY harness; pass a non-empty prefix or a manifest"
            )
        return core.cleanup(manifest_or_prefix)

    manifest = _load_manifest(manifest_or_prefix)
    resolved, env = _resolve_fleet(manifest)
    existing = _index_existing()

    deleted: list[str] = []
    # Iterate the ORDERED resolved list (not a set) so deletion order + the
    # returned list are deterministic.
    for r in resolved:
        name = r["name"]
        prior = existing.get(name)
        if prior is None:
            continue
        # Tag-guard on teardown too (mirrors provision_fleet): never delete a
        # harness claimed by a DIFFERENT env — a staging teardown must not wipe a
        # prod harness that happens to share the name.
        prior_env = _existing_env(prior)
        if prior_env is not None and prior_env != env:
            raise FactoryError(
                f"cross-env tag-guard: refusing to delete harness {name!r} — it is "
                f"claimed by env {prior_env!r} but this teardown is env {env!r}. "
                f"Run against the matching SENTINEL_ENV."
            )
        core.delete_harness(prior["harnessId"])
        deleted.append(name)
    return deleted
