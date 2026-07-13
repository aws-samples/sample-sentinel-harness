# Contributor Cookbook

Four **worked, end-to-end recipes** for extending `sentinel-harness` at each of its
four plug-in points — a **tool**, a **skill**, a **harness**, and an A2A
**specialist**. Every recipe is real: it names the exact files to add, mirrors a
shipped example, ends in a **passing offline test**, and drops a scrubbed
**evidence JSON** so the change is proven, not just asserted.

These replace the four terse pointers that used to live in the README
["Extending"](../README.md#-extending) section. Read the example each recipe is
modelled on before you start — the point of the codebase is that a new capability
is a *config + handler + test* change, never a rebuild.

> **Ground rules (from [`CONTRIBUTING.md`](../CONTRIBUTING.md)).** Public repo:
> generic SecOps content only — **zero** org names, **zero** real 12-digit account
> ids (use `000000000000`), **zero** secrets, English only, RFC 5737 documentation
> IPs (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) in examples. Everything
> is env-parameterized (`SENTINEL_EXECUTION_ROLE_ARN` / `SENTINEL_REGION` /
> `AWS_PROFILE`). Deterministic tools stay LLM-free. `make lint` + `make test` is
> the CI gate.

### The one test command

Every recipe below runs its test with the **hermetic** invocation the CI gate uses
(no local venv to manage; `uv` builds the environment on the fly):

```bash
export SENTINEL_EXECUTION_ROLE_ARN="arn:aws:iam::000000000000:role/test"  # offline placeholder
uv run --no-project --python 3.13 --with pytest --with boto3 --with pyyaml --with . \
    python -m pytest tests/<your_test>.py -q
```

`make test` runs the whole offline suite the same way (see
[`docs/TESTING.md`](TESTING.md) for the authoritative count). Nothing here
touches AWS or the network.

### A running example

To keep the four recipes coherent they add **one** new capability across all four
extension points: a `geo_lookup` geo-IP enrichment. Recipe 1 builds the tool,
Recipe 2 a SOP skill that uses it, Recipe 3 a harness that wires it, Recipe 4 an
A2A specialist that serves it. Swap the name for your own capability.

---

## Recipe 1 — Add a tool

**Model it on:** [`tools/siem_query/`](../tools/siem_query/) (backend-pluggable, has a
`*_LIVE` seam) and [`tools/sigma_yara_lint/`](../tools/sigma_yara_lint/) (deterministic,
LLM-free, no seam). **Governed by** the [dual-gate](GOVERNANCE.md) in
[`registry/tools.yaml`](../registry/tools.yaml) + the code factory map.

### The handler contract

A tool is a single `handler(event, context) -> dict`. The response shape is fixed
across every tool in the repo so callers (and the harness) never special-case one:

```python
# success
{"ok": True, "source": "stub", ...}      # source == "stub" offline, "live" via the *_LIVE seam
# failure
{"ok": False, "error": "validation_error", "message": "..."}   # bad input (a client error)
{"ok": False, "error": "upstream_error",  "message": "..."}    # a live backend failed
{"ok": False, "error": "not_found",       "message": "..."}    # (optional) a valid-but-absent key
```

Rules that keep the family consistent:

- **Validate loudly.** A malformed/empty/typo'd input is a `validation_error`, never
  a silently-empty result. An unknown *value* for a valid selector returns an empty
  result set (distinguishable from a malformed query).
- **No silent fallback.** If a live backend fails, return `upstream_error` — never
  quietly drop back to the mock. "Opted into live and got nothing" must never look
  like "no results".
- **Deterministic offline.** No clock, no randomness — same input, same output.
- **Egress & secrets controlled.** Any backend URL/token is read from the
  environment only, never hardcoded, logged, or echoed into a response.

### Steps

1. **Create the handler** `tools/geo_lookup/handler.py`. Start from the module
   docstring convention in `tools/siem_query/handler.py` (SecOps purpose · input
   contract · output contract · egress & secrets posture) then implement:
   - `_validate(event)` — raise `ValueError` for a non-dict, empty, unknown-key, or
     over-long input; return the normalized selector.
   - `_select(...)` — read the shared world via `mockdata.load_world()` (a fresh deep
     copy each call, so the tool can never mutate the source), filter, and normalize
     to a stable field shape.
   - `handler(event, context)` — catch `ValueError` → `validation_error`; catch every
     other `Exception` from the live path → `upstream_error`; else return
     `{"ok": True, "source": ..., ...}`.

2. **Add the `*_LIVE` seam** (only if the tool is backend-pluggable — like
   `siem_query`/`asset_lookup`/`enrich_ioc`/`ops_query`; a deterministic linter like
   `sigma_yara_lint` needs none). Copy the `_fetch_live` pattern verbatim:
   - Gate on `os.environ.get("GEO_LOOKUP_LIVE") == "1"`.
   - Read `GEO_LOOKUP_URL` (required — missing → `RuntimeError`) and optional
     `GEO_LOOKUP_TOKEN` (bearer, env-only).
   - Use **stdlib `urllib.request`** (no third-party deps), a bounded timeout, and a
     bounded read (reject an over-large reply rather than truncate).
   - Map every failure — missing URL, DNS/refused/timeout (`URLError`), non-2xx
     (`HTTPError`), malformed JSON — to a `RuntimeError`, which the handler surfaces
     as `upstream_error`. Normalize the live reply into the **same** field shape the
     stub emits so a caller cannot tell them apart beyond the `source` marker.

3. **Register it — both gates.** A tool is *live* only when it appears in **both**
   sides ([`GOVERNANCE.md`](GOVERNANCE.md)):
   - **Declarative side** — add an entry to [`registry/tools.yaml`](../registry/tools.yaml):
     ```yaml
       - name: geo_lookup
         owner: threat-intel          # a team alias/label — never a personal name
         status: approved             # approved | pending | deprecated
         description: >-
           Geo-IP / ASN enrichment for an IP indicator: given an IP (RFC 5737 in the
           mock world), returns a deterministic offline view (country / ASN / org /
           network). Offline stub by default; GEO_LOOKUP_LIVE opts into a real geo
           backend later (env URL+bearer; failures -> upstream_error, no fallback).
     ```
   - **Code side** — add `geo_lookup` to the factory map the registry is loaded with
     (a name → zero-arg callable returning the harness tool-config). See how
     `tests/test_registry.py::test_load_registry_with_shipped_yaml_dual_gate` wires
     the factory map to `load_registry(factory_map, TOOLS_YAML)`; a name approved in
     the YAML but missing a code factory is flagged as `approved_missing_impl` drift.

4. **Write a `tools/geo_lookup/README.md`** — mirror `tools/siem_query/README.md`:
   the MOCK-DATA warning banner, the signature, the selector/return table, and the
   `*_LIVE` env vars.

### Tests to write

Two files, both offline (mirror the `sys.modules`-hygiene pattern — load the handler
by explicit path under a **unique** module name, since every tool ships a module
literally named `handler`):

- **`tests/test_geo_lookup.py`** — the offline contract (model on
  `tests/test_siem_query.py`): success shape (`ok`, `source == "stub"`, normalized
  fields), each `validation_error` branch, deterministic repeat, and that the default
  path makes **zero** network calls.
- **`tests/test_geo_lookup_live.py`** — the live client against an **in-process mock
  `http.server`** on `127.0.0.1:0` (model on `tests/test_siem_query_live.py`): proves
  the request shape (POST, JSON body, optional bearer header), response parsing
  (`source == "live"`), and that HTTP 500 / malformed JSON / connection-refused each
  become `upstream_error` with no crash and no fallback. **Zero external network** —
  every request stays on loopback.

Also extend the governance assertion in `tests/test_registry.py` (add `geo_lookup`
to the factory-map set and the expected `list_live()` — a shared change; see below).

**Run:**

```bash
uv run --no-project --python 3.13 --with pytest --with boto3 --with pyyaml --with . \
    python -m pytest tests/test_geo_lookup.py tests/test_geo_lookup_live.py tests/test_registry.py -q
```

### Evidence to drop

Exercise the tool from a small scenario (`scenarios/scenario_geo_lookup.py`, model on
`scenarios/scenario_cve_asset_triage.py`) that runs the offline path, the governance
check, and — behind `--live` — the `*_LIVE` seam, then writes a **scrubbed** result
(`_scrub` replaces any 12-digit account id in an ARN with `<ACCOUNT_ID>`) to
`evidence/geo_lookup_result.json`:

```json
{
  "scenario": "geo_lookup",
  "steps": [
    {"step": "offline_query", "ok": true,
     "data": {"query": "203.0.113.66", "source": "stub", "country": "ZZ", "asn": 64500}},
    {"step": "governance_check", "ok": true,
     "data": {"live": true, "approved_missing_impl": [], "impl_missing_registry": []}}
  ],
  "verdict": {"tool": "geo_lookup", "dual_gate_live": true, "source": "stub", "closed": true}
}
```

---

## Recipe 2 — Add a skill

**Model it on:** [`skills/soc-triage/SKILL.md`](../skills/soc-triage/SKILL.md).
**Gated by:** [`tests/test_cyber_skills.py`](../tests/test_cyber_skills.py) — the
anti-hallucination gate.

A skill is a single AgentSkills.io `SKILL.md`: YAML frontmatter + a procedural
Markdown body. It carries **no code** — it is the reusable SOP an analyst follows,
and it may reference **only tools that actually exist** in `tools/` (the platform
cannot run a hallucinated tool).

### Steps

1. **Create** `skills/geo-triage/SKILL.md` with frontmatter — the `name` **must
   match the directory** and the `description` must be a real "use this when…"
   trigger blurb (≥ 80 chars; the test enforces both):
   ```markdown
   ---
   name: geo-triage
   description: Geo/ASN-context triage for an IP indicator on an alert. Use when a SIEM
     alert names a src_ip and the analyst must place it geographically and by owning
     network before dispositioning — corroborating geo_lookup against enrich_ioc and
     asset_lookup, and human-gating any block/containment recommendation.
   ---
   ```

2. **Write the body** — a genuine SOP, not a stub. The test floor is **1500 chars**
   with `##` sections and explicit `Step N` structure. Follow the shape of
   `soc-triage`: Operating Principles → numbered Steps → a structured JSON output
   block → Guardrails. Keep dispositions deterministic and human-gate every action.

3. **Reference only real tools.** The test extracts every backticked identifier
   ending in a tool suffix (`_query`, `_lookup`, `_ioc`, `_ticket`, `_kev`,
   `_optimizer`, `_match`, `_lint`, `_search`, `_ops`, `_evaluation`) plus every
   `tool:<name>` citation, and asserts each exists under `tools/` (or is the approved
   `ops_query` sibling). So `` `geo_lookup` ``, `` `enrich_ioc` ``, `` `asset_lookup` ``,
   `tool:siem_query` are fine; a `` `geo_reputation` `` you never built fails the
   build. Reference at least one real tool (a useless SOP names none).

4. **Attach it** to a harness at create time via
   `core.create_harness(..., skills=["geo-triage", ...])`, or list it in a
   `harness.yaml`.

### Test that gates it

Add `"geo-triage"` to the explicit `NEW_SKILLS` list in
`tests/test_cyber_skills.py` (kept explicit, not globbed, so a rename fails loudly) —
a shared change; see below. That parametrizes five checks over your skill: file
exists, frontmatter name/description well-formed, body non-trivial, references only
real tools, references at least one.

**Run:**

```bash
uv run --no-project --python 3.13 --with pytest --with pyyaml --with . \
    python -m pytest tests/test_cyber_skills.py -q
```

### Evidence to drop

The passing `test_cyber_skills.py` run *is* the proof the skill is well-formed and
hallucination-free. For a captured artifact, have your triage scenario record which
skill drove the disposition and drop `evidence/geo_triage_result.json`:

```json
{
  "scenario": "geo_triage",
  "skill": "geo-triage",
  "steps": [
    {"step": "siem_query",   "ok": true, "data": {"alert_id": "alert-1001", "src_ip": "203.0.113.66"}},
    {"step": "geo_lookup",   "ok": true, "data": {"country": "ZZ", "asn": 64500, "source": "stub"}},
    {"step": "enrich_ioc",   "ok": true, "data": {"verdict": "malicious", "related_hosts": ["web-01"]}}
  ],
  "verdict": {"disposition": "TRUE_POSITIVE", "requires_human_approval": true,
              "tools_referenced": ["siem_query", "geo_lookup", "enrich_ioc"], "closed": true}
}
```

---

## Recipe 3 — Add a harness

**Model it on:** [`harnesses/alert-triage/`](../harnesses/alert-triage/)
(`harness.yaml` + `system_prompt.md`). **Loaded by:**
[`sentinel_harness/loader.py`](../sentinel_harness/loader.py) ·
`load_harness_config`. **Docs:** [`docs/HARNESSES.md`](HARNESSES.md).

A harness is pure declaration — the whole thesis. You write a `harness.yaml` + a
`system_prompt.md`; the loader turns them into `core.create_harness(**kwargs)` and
AWS runs the agent loop.

### `harness.yaml` fields

```yaml
harnessName: sentinel_geo_enrichment      # MUST match [a-zA-Z][a-zA-Z0-9_]{0,39} — NO hyphens

model:
  bedrockModelConfig:
    # MUST carry a full version suffix or invoke silently fails. Overridable via env.
    modelId: global.anthropic.claude-haiku-4-5-20251001-v1:0
    maxTokens: 4096
    temperature: 0.1

systemPrompt: system_prompt.md            # a path — the loader reads it, relative to the yaml dir

tools:
  - type: agentcore_code_interpreter
    name: code_interpreter
  - type: agentcore_gateway
    name: gateway
    config:
      agentCoreGateway:
        gatewayArn: ${SENTINEL_GATEWAY_ARN}   # ${ENV} expanded by the loader (12-factor)

allowedTools:                             # EXPLICIT allowlist — never ['*']
  - code_interpreter
  - "@gateway/siem_query"                 # @gateway/<tool> grammar for gateway-scoped tools
  - "@gateway/geo_lookup"
  - "@gateway/enrich_ioc"
  - request_containment_approval          # an inline HITL gate (see below)

memory:
  managedMemoryConfiguration:
    strategies: [SEMANTIC, SUMMARIZATION]
    eventExpiryDuration: 90

maxIterations: 12
timeoutSeconds: 180
```

### Steps

1. **Create** `harnesses/geo-enrichment/harness.yaml` with the fields above. Note:
   - `harnessName` has **no hyphens** (the directory may; the name field may not).
   - `modelId` is **version-pinned** — an unversioned id makes `invoke` silently fail.
   - `${SENTINEL_GATEWAY_ARN}` and any other `${ENV_VAR}` are expanded by the loader
     from the environment; a missing var is a clear error (`${arn:...}` literals are
     left untouched).
2. **Write** `harnesses/geo-enrichment/system_prompt.md` — model on
   `harnesses/alert-triage/system_prompt.md`: role, a numbered "How you work",
   deterministic-math-through-code-interpreter, and an explicit HITL constraint.
3. **Wire inline HITL gates.** Any `allowedTools` entry that names a known inline
   gate — `request_publish_approval`, `request_containment_approval`, or
   `request_human_review` (see `loader._INLINE_GATES`) — is auto-injected as an
   `inline_function` tool definition at load time via `core.tool_inline(...)`. So
   listing `request_containment_approval` is enough: the agent can only *request*
   containment, never execute it unattended. Do not expose a raw destructive action
   directly.
4. **Load / create it:**
   ```bash
   sentinel create harnesses/geo-enrichment/harness.yaml   # via the CLI, or…
   ```
   ```python
   from sentinel_harness import loader
   kwargs = loader.load_harness_config("harnesses/geo-enrichment/harness.yaml")  # pure, offline
   # loader.create_from_config(path) additionally reaches the control plane to create it
   ```
   `core.new_session(...)` produces the ≥ 33-char session ids the runtime requires.

### Test to write

Add `"geo-enrichment"` to the `SHIPPED` list in
[`tests/test_loader.py`](../tests/test_loader.py) — a shared change; see below. The
loader tests run each shipped `harness.yaml` through `load_harness_config` and assert
the kwargs are shaped for `core.create_harness` (name regex, gateway-tool grammar,
`system_prompt` resolved to text, inline gate injected) — **zero AWS**;
`create_from_config` is exercised only against a monkeypatched fake client.

**Run:**

```bash
uv run --no-project --python 3.13 --with pytest --with boto3 --with pyyaml --with . \
    python -m pytest tests/test_loader.py -q
```

### Evidence to drop

A scenario that loads the harness and runs an enrichment pass drops
`evidence/geo_enrichment_result.json`:

```json
{
  "scenario": "geo_enrichment",
  "harness": "sentinel_geo_enrichment",
  "steps": [
    {"step": "load_harness_config", "ok": true,
     "data": {"name": "sentinel_geo_enrichment", "allowed_tools": 5,
              "inline_gate_injected": "request_containment_approval",
              "model_id": "global.anthropic.claude-haiku-4-5-20251001-v1:0"}},
    {"step": "system_prompt_resolved", "ok": true, "data": {"chars": 1420}}
  ],
  "verdict": {"loadable": true, "hitl_gated": true, "model_version_pinned": true, "closed": true}
}
```

---

## Recipe 4 — Add a specialist

**Model it on:** [`specialists/cve-intel/`](../specialists/cve-intel/) — the
source-of-truth reference. **Reuses:**
[`specialists/_a2a_contract.py`](../specialists/_a2a_contract.py) (the shared
in-process A2A harness). **Blueprint:** [`docs/BLUEPRINT.md`](BLUEPRINT.md) §4.2.

A specialist is a narrow, single-capability agent that a supervisor delegates to
over **A2A** (agent-to-agent). Unlike the Bedrock-only supervisor harness, a
specialist runs in its **own** Runtime microVM, so it may use `LiteLLMModel` to reach
a cheaper/narrower or non-Bedrock model.

### Steps

1. **`specialists/geo-intel/agent_a2a.py`** — model on `cve-intel/agent_a2a.py`:
   - `SPECIALIST_NAME` / `SPECIALIST_VERSION` / `SPECIALIST_DESCRIPTION` — skill-based
     names, never person/org.
   - `DEFAULT_MODEL_ID = os.environ.get("SENTINEL_SPECIALIST_MODEL",
     "bedrock/global.anthropic.claude-haiku-4-5-20251001-v1:0")` — provider-prefixed
     for LiteLLM and **version-pinned** (an unversioned id silently fails to invoke).
   - `agent_card(...)` — the self-describing name/description/capabilities the
     supervisor discovers through the Registry and A2A card.
   - `build_agent(...)` / `build_app(...)` / `serve(...)` — **guard the heavy imports**
     (`strands` / `strands-agents[a2a,litellm]` / `bedrock-agentcore`) lazily inside
     the factories so the module is always importable and the card is verifiable
     offline. Host/port from `SENTINEL_A2A_HOST` (`0.0.0.0`) / `SENTINEL_A2A_PORT`
     (`9000`).
2. **`specialists/geo-intel/local_a2a.py`** — the in-process A2A front end. Reuse the
   shared harness `specialists/_a2a_contract.py` (`LocalA2AServer` / `LocalA2AClient` /
   `verdict_from_response` / the JSON-RPC error codes) rather than re-implementing the
   `message/send` server/client. Inject a deterministic offline model callable
   `(message_text: str) -> dict` built around your pure reasoner for the contract
   test; `strands_model_callable` is the production seam (documented, not tested).
3. **`specialists/geo-intel/Dockerfile`** — copy the `cve-intel` pattern exactly:
   - **Two-stage** (`builder` installs pinned deps into `/opt/venv`; `runtime` copies
     only the ready venv + app code — no pip/build tools ship).
   - `FROM --platform=linux/arm64 python:3.13-slim` — **version-pinned base** (not
     `:latest`); arm64 because AgentCore Runtime runs arm64 microVMs.
   - **Non-root**: `useradd --uid 10001 specialist` then `USER specialist`.
   - `EXPOSE 9000`; a `HEALTHCHECK` that hits `/ping` with a stdlib python one-liner
     (curl isn't in slim); `CMD ["python", "-m", "agent_a2a"]`.
4. **`specialists/geo-intel/requirements.txt`** — every dep **pinned** (`==`/`~=`):
   `bedrock-agentcore`, `strands-agents[a2a,litellm]`, `fastapi`, `uvicorn[standard]`,
   etc. The container test asserts nothing is unpinned.
5. **`specialists/geo-intel/compose.yaml`** — valid YAML, drives the model id from an
   env var, exposes the A2A port, and carries **no** hardcoded secret / real 12-digit
   account id. `README.md` to document it.

### Tests to write

Two offline files (both load the module by explicit path under a **unique** name so
the bare `agent_a2a` / `local_a2a` names can't cross-poison sibling specialists via
`sys.modules`):

- **`tests/test_geo_intel_container.py`** — the packaging contract (model on
  `tests/test_cve_intel_container.py`), **zero docker**: Dockerfile parses, is
  multi-stage, pins its base (no `:latest`), declares a non-root `USER`, an `EXPOSE`,
  and a `CMD`; every requirement is pinned; `compose.yaml` is valid YAML with an
  env-driven model id and **no** secret / real account id.
- **`tests/test_geo_intel_a2a.py`** — the A2A contract (model on
  `tests/test_cve_intel_a2a.py`), **in-process + mocked model + a socket-connect
  guard** (any outbound `connect` raises `AssertionError`): the agent-card is served
  and well-formed; a `message/send` round-trips through the mocked model to a
  structured response envelope and is deterministic; an unknown method / malformed
  message yields a clean JSON-RPC **error** (never a crash). Proves a zero-network
  round-trip.

**Run:**

```bash
uv run --no-project --python 3.13 --with pytest --with pyyaml --with . \
    python -m pytest tests/test_geo_intel_container.py tests/test_geo_intel_a2a.py -q
```

An actual `docker build` (arm64, pinned deps, non-root) is a **verify** step, not
part of the unit test — the unit test must pass on a machine with no docker daemon.

### Evidence to drop

A scenario driving the in-process A2A round-trip (mocked model, socket guard) drops
`evidence/geo_intel_a2a_result.json`:

```json
{
  "scenario": "geo_intel_a2a",
  "specialist": "geo-intel",
  "steps": [
    {"step": "agent_card", "ok": true,
     "data": {"name": "geo-intel", "protocol": "JSONRPC", "skills": 1}},
    {"step": "message_send_round_trip", "ok": true,
     "data": {"indicator": "203.0.113.66", "grounded": true, "network_calls": 0}}
  ],
  "verdict": {"a2a_contract_ok": true, "zero_network": true,
              "model_version_pinned": true, "closed": true}
}
```

---

## Shared changes (not owned by this file)

These recipes reference edits to files another author owns. Make them as separate,
single-purpose changes:

- **`README.md`** — replace the four "Extending" pointer bullets (New tool / New
  skill / New harness; the specialist row) with a link to this cookbook.
- **`tests/test_registry.py`** — add `geo_lookup` to the dual-gate factory-map set
  and the expected `list_live()` (Recipe 1).
- **`tests/test_cyber_skills.py`** — add `"geo-triage"` to `NEW_SKILLS` (Recipe 2).
- **`tests/test_loader.py`** — add `"geo-enrichment"` to `SHIPPED` (Recipe 3).

## See also

- [`docs/GOVERNANCE.md`](GOVERNANCE.md) — the Registry dual-gate, HITL gates, sandbox hooks.
- [`docs/HARNESSES.md`](HARNESSES.md) — the declarative `harness.yaml` configs and how the loader consumes them.
- [`docs/TESTING.md`](TESTING.md) — the offline test suite: layout, determinism, how to run.
- [`docs/BLUEPRINT.md`](BLUEPRINT.md) — layer→primitive mapping and the borrowed AWS-sample patterns.
