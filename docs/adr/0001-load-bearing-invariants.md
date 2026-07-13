# ADR 0001 — Load-bearing invariants an extender must not "fix"

- **Status:** Accepted
- **Date:** 2026-07-11
- **Applies to:** M0–M7 codebase

## Context

`sentinel-harness` is a public reference implementation of production SecOps
agents built as *configuration* on Amazon Bedrock AgentCore. Several design
choices read like limitations to a newcomer — a Bedrock-only harness, a
"boring" deterministic delegation tool, a simulated detonation that does
nothing, governance that refuses to auto-approve. Each is a **deliberate
invariant** that upholds a security, governance, or honesty property. This ADR
captures them in one place so an extender does not "helpfully" undo one.

The six invariants below are grouped as one ADR because they share a single
theme: **the harness stays a governed, deterministic, honest control surface —
the LLM narrates, it does not get to widen its own blast radius.**

## Decision

We commit to the following invariants. Changing any of them is an architecture
change requiring a new ADR, not a routine PR.

### 1. Bedrock-model-only harness; non-Bedrock lives only in a specialist Runtime container

The supervisor **Harness** primitive is config-only and **Bedrock-model-only**
by constraint. Any non-Bedrock model (a cheaper/narrower LLM via `LiteLLMModel`)
lives **only** inside a specialist **AgentCore Runtime** container reached over
A2A — see [`specialists/threat-hunt/README.md`](../../specialists/threat-hunt/README.md)
("Why a specialist" table: Harness = Bedrock-only; Specialist = any, via
`LiteLLMModel`) and the sibling `specialists/cve-intel`. Do **not** try to bolt
a non-Bedrock provider onto the harness itself.

### 2. Delegation is a deterministic MCP tool — never let the LLM hand-write HTTP

Supervisor→specialist and harness-lifecycle delegation go through the
deterministic MCP tool [`tools/harness_ops/handler.py`](../../tools/harness_ops/handler.py):
"create/update/invoke/promote are **deterministic** control-plane actions …
There is NO LLM here and NO business logic beyond validation" (module docstring,
lines 1–18). The handler validates then delegates to `core` / `core._control`.
The LLM decides *whether* to delegate; it must never hand-write raw HTTP or
control-plane calls. Keep the deterministic seam.

### 3. Registry dual-gate — a tool is live only if approved AND code-mapped

The tool/skill registry
([`sentinel_harness/registry.py`](../../sentinel_harness/registry.py)) enforces a
**dual-gate**: a name is live only if it is `approved` **in the registry** AND
has a **code factory** in the code map (`resolve`, lines 151–165; `list_live`,
lines 168–172). A name present on only one side is a governance signal, not a
usable tool — `governance_check` surfaces `approved_missing_impl` (approved but
unshipped) and `impl_missing_registry` (shadow capability never governed). Do
**not** collapse this to a single list; the two gates catch different failures.

### 4. Detonation is an honest SIMULATED no-op

The sample-detonation scenario
([`scenarios/scenario_detonation.py`](../../scenarios/scenario_detonation.py))
keeps a real, tested **orchestration lifecycle** (acquire → sandbox-gate every
action → HITL approval → collect → report → destroy-after-use) while the
detonation itself is a **SIMULATED no-op**: there is NO real microVM /
Firecracker / container / malware / network (docstring lines 14–27). The sample
is by-reference; a disallowed action (e.g. `rm -rf /`) is **refused** by
`sentinel_harness.sandbox_hooks`, recorded, never executed. Do **not** make this
"actually detonate" — the honesty (and safety) is the point. This is a public,
defensive-only repo.

### 5. `autoApproval=false` governance is the default and the safe choice

Registry records are created with `autoApproval=false`
([`sentinel_harness/registry_live.py`](../../sentinel_harness/registry_live.py),
`auto_approval: bool = False`, lines 62–81): a new record lands in `DRAFT` and is
**not live**; promotion to `PENDING_APPROVAL` is an explicit human/automation
step (`submit_for_approval`, ~line 203). This mirrors the live-verified
governance walk in the README evidence table. Do **not** default it to `true` to
"reduce friction" — the friction is the control.

### 6. The execution role omits `InvokeAgentRuntimeCommand`

The least-privilege execution-role policy in
[`docs/SETUP.md`](../SETUP.md) (lines 59–94) **deliberately excludes**
`bedrock-agentcore:InvokeAgentRuntimeCommand`: it runs a shell command on the
microVM **as root, bypassing the LLM and `allowedTools`**. Critically,
`allowedTools` only scopes which tools the *LLM* may pick during `InvokeHarness`;
it **cannot** restrict `InvokeAgentRuntimeCommand`, which is a separate
data-plane API. SETUP.md calls this "the single most important least-privilege
decision for a SecOps repo." Do **not** add it to the role by default; grant it
only for a scenario that truly needs deterministic shell prep, understanding the
risk.

## Consequences

**Positive.**

- The harness stays a **governed, deterministic control surface**: the LLM
  narrates and chooses; it never widens its own blast radius (no hand-written
  HTTP, no root shell, no un-approved tools).
- Every capability that is live is **both** approved and implemented, so the
  registry cannot drift into shadow capability or approved-but-vaporware.
- The repo can stay **public and defensive-only** with an honest fidelity story —
  detonation never touches real malware, and the docs never overclaim.
- Non-Bedrock experimentation is still possible, cleanly isolated in a specialist
  container behind A2A, without weakening the supervisor's constraints.

**Negative / costs (accepted).**

- Extenders wanting a non-Bedrock supervisor, autonomous approval, or a "real"
  detonation must build a specialist/Runtime path or write a new ADR — there is
  friction by design.
- The dual-gate and `autoApproval=false` add steps before a tool goes live.
- Omitting `InvokeAgentRuntimeCommand` means deterministic shell prep is not
  available out of the box; a scenario that needs it must opt in explicitly and
  own the risk.

These costs are the price of the security and honesty properties above and are
accepted deliberately.
