"""INV-HARNESS-1 — every tool a harness allows is resolvable, and the docs say where from.

`harnesses/*/harness.yaml` grants each agent an `allowedTools` list, and those names span **three
different namespaces**:

    code_interpreter                 an AgentCore built-in primitive
    @gateway/siem_query              an MCP tool served by the Gateway
    request_containment_approval     a HITL gate the adopter implements as a blocking @tool

Nothing checked any of them. A rename in `tools/` (this repo did one — `whitelist_optimizer` ->
`allowlist_optimizer`, INV-REGISTRY-5) or a deleted stub would leave a harness granting a name that
resolves to nothing, and the agent would come up with a smaller tool surface than its config
declares — silently, because the allowlist is a *grant*, not a lookup.

## The defect this found

`docs/HARNESSES.md` claimed:

> The Gateway tools these supervisors reference (`search_registry`, `siem_query`, `enrich_ioc`, …)
> have reference-stub handlers under `tools/`; point `SENTINEL_GATEWAY_ARN` at a Gateway that hosts
> them to run against live data.

Measured: **12 of the 14** gateway-namespaced references have a stub under `tools/`. The two that do
not are `search_registry` and `invoke_specialist` — and `search_registry` was the doc's own first
example. A reader following that sentence would look for a stub that is not there.

Those two are correctly stub-less: they are *platform* operations (Registry query, A2A dispatch),
not SecOps tools, so a local stub would be a misleading no-op. The defect was the documentation,
which has been corrected to state the split and the reason.

## What this module asserts

- every `@gateway/` reference either has a stub under `tools/` or is in the recorded
  platform-operation set — so a NEW unresolvable name fails, rather than joining a vague exemption
- that set is verified, not merely trusted: each member must be absent from `tools/` (an entry that
  gained a stub is a stale exemption) and must be reachable in the repo somewhere
- HITL gates match `exporter.is_hitl_gate`, the canonical predicate (INV-EXPORT-1), rather than a
  second substring rule
- the doc states the current split

ZERO network, ZERO AWS.
"""
from __future__ import annotations

import os

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HARNESSES_DIR = os.path.join(REPO_ROOT, "harnesses")
TOOLS_DIR = os.path.join(REPO_ROOT, "tools")
HARNESS_DOC = os.path.join(REPO_ROOT, "docs", "HARNESSES.md")

# The 12-factor placeholders several harnesses reference; the loader refuses without them.
_ENV = {
    "SENTINEL_GATEWAY_ARN": "arn:aws:bedrock-agentcore:us-east-1:000000000000:gateway/test",
    "SENTINEL_GATEWAY_URL": "https://gw.example.internal/mcp",
    "SENTINEL_MEMORY_ID": "mem-test-000",
    "SENTINEL_EXECUTION_ROLE_ARN": "arn:aws:iam::000000000000:role/test",
    "AWS_DEFAULT_REGION": "us-east-1",
    "AWS_ACCESS_KEY_ID": "testing",
    "AWS_SECRET_ACCESS_KEY": "testing",
}

# Gateway-namespaced names that deliberately have NO stub under `tools/`, with why.
#
# These are PLATFORM operations rather than SecOps tools, so a local stub would be a no-op that
# looks like a reference implementation — worse than its absence. Recorded here (not silently
# skipped) so the set can be checked and can shrink.
_PLATFORM_OPERATIONS = {
    "search_registry": "queries the AgentCore Registry (see sentinel_harness/registry_live.py)",
    "invoke_specialist": "dispatches to an A2A specialist container under specialists/",
}


@pytest.fixture(autouse=True)
def _twelve_factor_env(monkeypatch):
    for key, value in _ENV.items():
        monkeypatch.setenv(key, value)


def _harness_names() -> list:
    return sorted(
        name for name in os.listdir(HARNESSES_DIR)
        if os.path.isfile(os.path.join(HARNESSES_DIR, name, "harness.yaml"))
    )


def _allowed_tools(harness: str) -> list:
    """The harness's allowlist, via the loader.

    Read through `load_harness_config`, NOT raw YAML: the loader normalises `allowedTools` to
    `allowed_tools` and expands `${ENV}` placeholders. My first probe read the loader's output with
    the camelCase key and got `None` for all eight harnesses — a scan finding nothing looks exactly
    like a repo with nothing to find, which is why the positive control below is not optional.
    """
    from sentinel_harness.loader import load_harness_config

    config = load_harness_config(os.path.join(HARNESSES_DIR, harness, "harness.yaml"))
    return list(config.get("allowed_tools") or [])


def _tools_on_disk() -> set:
    return {
        name for name in os.listdir(TOOLS_DIR)
        if os.path.isfile(os.path.join(TOOLS_DIR, name, "handler.py"))
    }


def test_the_scan_finds_tool_references_at_all():
    """Positive control, and the reason it exists: my first version of `_allowed_tools` returned an
    empty list for every harness because it read the wrong key case. Every assertion below iterates
    those lists, so they would all have passed vacuously."""
    total = sum(len(_allowed_tools(h)) for h in _harness_names())
    assert total >= 15, (
        f"only found {total} tool references across {len(_harness_names())} harnesses. Either the "
        "allowlists were emptied or this scan reads the wrong key — both must fail loudly."
    )
    assert len(_tools_on_disk()) >= 15, "fewer than 15 tools on disk; the comparison is blind"


@pytest.mark.parametrize("harness", _harness_names())
def test_every_gateway_reference_resolves(harness):
    """A `@gateway/<name>` reference must have a stub under `tools/` or be a known platform op.

    The failure mode this prevents is quiet: `allowedTools` is a GRANT, so an unresolvable name does
    not raise — the agent simply comes up with a smaller tool surface than its config claims. After
    the `whitelist_optimizer` -> `allowlist_optimizer` rename, exactly this kind of dangling
    reference is what INV-REGISTRY-5 was written to catch on the registry side; this is the harness
    side of the same coupling.
    """
    on_disk = _tools_on_disk()
    unresolved = []
    for reference in _allowed_tools(harness):
        if not reference.startswith("@gateway/"):
            continue
        name = reference.split("/", 1)[1]
        if name in on_disk or name in _PLATFORM_OPERATIONS:
            continue
        unresolved.append(reference)
    assert not unresolved, (
        f"{harness} allows gateway tool(s) that resolve to nothing: {unresolved}.\n\n"
        f"Add a reference stub under tools/<name>/handler.py, or — if it is a platform operation "
        f"rather than a SecOps tool — record it in _PLATFORM_OPERATIONS with the reason. An "
        f"unresolvable name does not raise: the agent just gets fewer tools than its config says."
    )


def test_the_platform_operation_exemptions_are_still_accurate():
    """Guard the exemption in both directions.

    An entry that has GAINED a stub is a stale exemption — the "lint-exempt directory = never
    cleaned" rule applied to an allowlist. An entry nothing in the repo mentions is either a typo or
    a reference to something that no longer exists.
    """
    on_disk = _tools_on_disk()
    now_stubbed = sorted(name for name in _PLATFORM_OPERATIONS if name in on_disk)
    assert not now_stubbed, (
        f"_PLATFORM_OPERATIONS claims {now_stubbed} have no stub under tools/, but they do. Remove "
        "them from the exemption so the resolution check covers them properly."
    )

    # Each must be reachable somewhere, or the exemption excuses a dangling name.
    unreferenced = []
    for name in _PLATFORM_OPERATIONS:
        found = False
        for root, dirs, files in os.walk(REPO_ROOT):
            dirs[:] = [d for d in dirs
                       if d not in {".git", ".venv", "build", "dist", "node_modules",
                                    "__pycache__", ".pytest_cache", "cdk.out", "site"}]
            for filename in files:
                if not filename.endswith((".py", ".md", ".yaml", ".yml")):
                    continue
                path = os.path.join(root, filename)
                if os.path.samefile(path, os.path.abspath(__file__)):
                    continue  # this file names them to exempt them; that is not a reference
                try:
                    with open(path, encoding="utf-8", errors="ignore") as fh:
                        if name in fh.read():
                            found = True
                            break
                except OSError:  # pragma: no cover
                    continue
            if found:
                break
        if not found:
            unreferenced.append(name)
    assert not unreferenced, (
        f"_PLATFORM_OPERATIONS names {unreferenced}, which appear nowhere else in the repo. Either "
        "the reference was removed (drop the exemption) or the name is a typo."
    )


@pytest.mark.parametrize("harness", _harness_names())
def test_every_hitl_gate_reference_uses_the_canonical_shape(harness):
    """HITL gates are recognised by `exporter.is_hitl_gate`, not by a second local rule.

    INV-EXPORT-1 records why: the gate predicate was an inline expression, a test re-derived it as
    `"approval" in name`, and two definitions of a SAFETY rule agree until one is edited. A gate a
    checker misses is a gate the exported code does not warn about.
    """
    from sentinel_harness.exporter import is_hitl_gate

    for reference in _allowed_tools(harness):
        if reference.startswith("@gateway/") or "_approval" not in reference:
            continue
        assert is_hitl_gate(reference), (
            f"{harness} allows {reference!r}, which contains '_approval' but is not recognised by "
            f"`exporter.is_hitl_gate`. Either it is misnamed (the contract is "
            f"`request_<action>_approval`) or the canonical predicate needs updating — and if the "
            f"predicate misses it, the exported code will not warn that it is a blocking gate."
        )


def test_the_documentation_states_the_current_split():
    """The doc claimed all these tools have stubs; two do not, and one of those was its own example.

    A reader following that sentence goes looking for `tools/search_registry/` and finds nothing.
    Checked against measurement so the sentence cannot drift back.
    """
    with open(HARNESS_DOC, encoding="utf-8") as fh:
        text = fh.read()

    on_disk = _tools_on_disk()
    stubbed = set()
    for harness in _harness_names():
        for reference in _allowed_tools(harness):
            if reference.startswith("@gateway/"):
                name = reference.split("/", 1)[1]
                if name in on_disk:
                    stubbed.add(name)
    total = len(stubbed) + len(_PLATFORM_OPERATIONS)

    assert f"{len(stubbed)} of the {total}" in text, (
        f"docs/HARNESSES.md does not state the current split ({len(stubbed)} of {total} gateway "
        f"references have stubs). Without it the doc implies ALL of them do — the claim that sent "
        f"a reader looking for tools/search_registry/."
    )
    for name in _PLATFORM_OPERATIONS:
        assert name in text, (
            f"docs/HARNESSES.md does not mention {name!r}, so a reader cannot tell why it has no "
            "stub."
        )
