# Testing Guide

*How the sentinel-harness test suite is designed, why it is the way it is, and how
to run and extend it. This document is a companion to the per-capability status
matrix in the [root README](../README.md) and the honesty audit in
[`docs/FIDELITY-REPORT.md`](FIDELITY-REPORT.md).*

**Verified at HEAD:** `1698 passed, 5 skipped` across **77** test files
(76 under `tests/`, 1 under `tests/smoke/`), in ~41s on a laptop, with **zero AWS
calls and zero external network I/O** on the default path.

---

## 1. Philosophy

The suite is built on one hard rule and three consequences.

**Hard rule: the default `pytest` run makes ZERO AWS calls and ZERO external
network I/O.** No credentials, no profile, no region lookup, no live account, no
Docker daemon, no LLM token. A defect must fail *here*, in CI, deterministically —
not silently at deploy time and not only when someone happens to have AWS creds.

Three consequences follow:

1. **Every AWS seam is either monkeypatched or replaced by an in-process fake.**
   `sentinel_harness.core` constructs its two boto3 clients
   (`bedrock-agentcore-control` for lifecycle, `bedrock-agentcore` for invocation)
   at import time. Client *construction* is offline — no network, no credential
   resolution — so import is safe once dummy env is present. Any test that would
   otherwise reach a control-plane or data-plane operation monkeypatches
   `core._control` / `core._data` (or the module-local `_control` in
   `registry_live.py`) with a fake that records the request kwargs the call *would*
   have sent. Tests then assert on those captured kwargs, which is exactly the
   contract the GA API enforces server-side.

2. **The `*_LIVE` tool clients are proven against in-process mock servers, never a
   real backend.** The reference tools under `tools/` are offline-by-default: they
   return deterministic fixtures unless a `*_LIVE=1` env var opts into a real
   `urllib.request` call. Those live code paths are still tested — but against an
   in-process `http.server` bound to `127.0.0.1:0` (an ephemeral loopback port)
   spun up on a background thread and torn down in teardown. This proves the live
   client's request *shape* (POST, JSON body, optional bearer header), its response
   *parsing* (JSON → normalized event/record shape, `source="live"`), and its
   *error handling* (HTTP 500, malformed JSON, connection-refused →
   `upstream_error`, never a silent fixture fallback) — all on the loopback
   interface, with zero packets leaving the host.

3. **Nothing labelled `real`/`live` is secretly mocked, and nothing offline
   pretends to be live.** The live on-account probes (Section 5) are strictly
   opt-in and *skip* when the opt-in is absent; the offline evidence checks are
   labelled as reading *live-captured* evidence, not as re-proving the AWS
   round-trip. This is the same honesty posture as the FIDELITY-REPORT: the suite
   never fakes liveness.

There is **no `conftest.py`** in the repo. Hermeticity is achieved per-file, on
purpose: each test module sets dummy env with `os.environ.setdefault(...)` before
importing `sentinel_harness`, and loads standalone script-tree modules (`tools/`,
`specialists/`) by explicit path under a **unique** module name (Section 6). This
keeps every file independently runnable and free of hidden shared fixtures.

---

## 2. How to run

### The canonical offline invocation

The hermetic entry point (no `/tmp` venv, reproducible via `uv`) is what `make
test` runs and what you should use locally:

```bash
SENTINEL_EXECUTION_ROLE_ARN=arn:aws:iam::000000000000:role/test \
AWS_DEFAULT_REGION=us-east-1 \
uv run --no-project --python 3.13 \
  --with pytest --with boto3 --with pyyaml --with . \
  python -m pytest tests/ -q
```

Expected result: `1698 passed, 5 skipped`.

The two env vars keep boto3 client construction and import hermetic — a placeholder
execution-role ARN (all-zeros account) and a fixed region so nothing tries to
resolve a real profile/credentials/region. Most test files also `setdefault` these
themselves, so a bare `pytest` still runs; setting them explicitly just guarantees
it.

### Via Make

```bash
make test     # the exact command above (hermetic, no AWS)
make lint     # uv run ruff check .
make smoke    # tests/smoke acceptance suite (offline; SENTINEL_SMOKE_LIVE=1 for live)
```

`make test`, `lint`, `synth`, `seed-registry`, `create-harnesses`, `smoke`, `demo`,
and `clean` are all **offline**. Only `deploy`, `deploy-endpoints`, `reset`, and
`destroy` touch AWS, each behind a human-confirmation prompt.

### A single file or test

```bash
# one file
uv run --no-project --python 3.13 --with pytest --with boto3 --with pyyaml --with . \
  python -m pytest tests/test_core_invoke_resume.py -q

# one test, with skip reasons shown
... python -m pytest tests/test_registry_live.py -q -rs

# just the smoke acceptance suite
... python -m pytest tests/smoke/ -q
```

If you already have a venv with the package installed editable (`pip install -e .`)
plus `pytest`/`boto3`/`pyyaml`, plain `pytest -q tests` works too — that is what CI
does (Section 7).

---

## 3. Test taxonomy

The 77 files fall into seven groups. Counts below are file counts; the total suite
is 1698 tests.

### a. Core / library unit tests

The `sentinel_harness.core` builders and the surrounding library, checked against a
monkeypatched control-plane client so the request kwargs are asserted without ever
leaving the process:

- **core lifecycle & invoke/resume** — `test_config_validation.py`,
  `test_core_endpoint.py`, `test_core_invoke_resume.py`, `test_core_update.py`.
  Envelope shapes (`systemPrompt` → `[{"text": ...}]`, `runtimeSessionId` ≥ 33
  chars, tool-config envelopes, model/memory builders, field forwarding), the HITL
  two-message `toolUse` + `toolResult` resume contract, endpoint promotion, update
  semantics.
- **loader** — `test_loader.py`: `harness.yaml` → `create_harness(**kwargs)`.
- **registry (governance)** — `test_registry.py`, `test_registry_governance.py`,
  `test_registry_minyaml.py`: the dual-gate tool/skill registry.
- **registry (live wrapper)** — `test_registry_live.py`: `registry_live.py`
  request shape + `RegistryLiveError` contract, against an in-process **fake**
  control client (DRAFT → PENDING_APPROVAL governance).
- **gateway** — `test_gateway.py`, `test_gateway_jwt.py`: Gateway builder + the
  CUSTOM_JWT authorizer human/machine shapes.
- **factory** — `test_factory.py`, `test_harness_ops.py`: Agent Factory fleet
  provisioning, dry-run, cross-env tag guard.
- **sandbox** — `test_sandbox_hooks.py`: the PreToolUse command-allowlist +
  path-containment hook.
- **exporter** — `test_exporter.py`: harness → standalone code export.
- **feedback** — `test_feedback.py`: the feedback/whitelist loop primitives
  (also `test_whitelist_optimizer.py`).
- **simulation** — `test_simulation.py`: the Play Mode driver (gating, checkpoint
  round-trip).
- **CLI** — `test_cli.py`: `sentinel` alias→model, tool/memory spec→builder,
  command dispatch.

### b. Tool-handler tests + their `*_live` mock-server twins

Each reference tool has an offline handler test and (for the networked tools) a
`*_live` twin that exercises the real `urllib` client against an in-process mock
`http.server` on `127.0.0.1`:

- **offline handlers** — `test_tool_handlers.py` (the nvd/epss_kev/attack/web_search
  reference stubs), `test_asset_lookup.py`, `test_enrich_ioc.py`,
  `test_ops_query.py`, `test_siem_query.py`, `test_create_ticket.py`,
  `test_sigma_match.py`, `test_sigma_yara_lint.py`, `test_run_evaluation.py`.
- **`*_live` (mock-server) twins** — `test_asset_lookup_live.py`,
  `test_attack_lookup_live.py`, `test_enrich_ioc_live.py`, `test_epss_kev_live.py`,
  `test_nvd_lookup_live.py`, `test_ops_query_live.py`, `test_siem_query_live.py`,
  `test_web_search_live.py`. Each opts into its tool's `*_LIVE` flag
  (`ASSET_LOOKUP_LIVE`, `ATTACK_LIVE`, `ENRICH_IOC_LIVE`, `EPSS_KEV_LIVE`,
  `NVD_LIVE`, `OPS_QUERY_LIVE`, `SIEM_QUERY_LIVE`, `WEB_SEARCH_LIVE`) and points the
  client at the loopback mock. `test_registry_live.py` is the ninth live-path test
  but uses a monkeypatched fake control client rather than an HTTP mock.

### c. Scenario tests

The narrated end-to-end scenarios under `scenarios/` (16 `scenario_*.py`), run
offline against fakes and asserted on their evidence-shaped output:
`test_agent_factory_scenario.py`, `test_alert_triage_poc.py`,
`test_bas_replay_scenario.py`, `test_cve_asset_triage.py`,
`test_detection_gen_scenario.py`, `test_detonation_scenario.py`,
`test_feedback_loop_scenario.py`, `test_self_improve_scenario.py`,
`test_live_a2a_runtime_scenario.py` (offline by default; the live path is
`SENTINEL_A2A_LIVE=1`/`--live` and is never taken in CI), plus the M2 milestone
suite (`test_m2_demo.py`, `test_m2_e2e_offline.py`, `test_m2_edge.py`,
`test_m2_harnesses.py`, `test_m2_integration.py`, `test_m2_regression.py`) and the
BAS/detonation drivers (`test_bas_runner.py`, `test_bas_cases.py`,
`test_detonation.py`, `test_detonation_runner.py`, `test_detonation_lifecycle.py`).

### d. Container-contract tests

Prove each A2A specialist's *packaging* is buildable-and-runnable-shaped **without
invoking a Docker daemon** (Dockerfile pins its base, declares non-root `USER`,
`EXPOSE`, `CMD`/`ENTRYPOINT`; `requirements.txt` fully pinned and at parity across
specialists; no baked secret/account id; any Bedrock model-id default carries a
full version suffix): `test_specialist_containers.py` (parametrized over cve-intel,
attack-mapper, threat-hunt), `test_cve_intel_container.py`,
`test_specialist_a2a_contract.py`, `test_cve_intel_a2a.py`,
`test_specialist.py`, `test_attack_mapper.py`, `test_threat_hunt.py`.

### e. CDK synth tests (ts-node)

Not part of the Python suite. The `iac-cdk` project ships six self-contained
`test/*.test.ts` stack-synth scripts (`gateway`, `guardrail`, `identity`,
`network`, `registry`, `runtime`) run via `npx ts-node` — each exits non-zero on
the first failed assertion; no jest is wired in. The Python side cross-checks synth
in `tests/smoke/` (all **9** stacks synthesize) when `iac-cdk/node_modules` is
present, and skips cleanly otherwise.

### f. Doc / Make / deploy guard tests

Keep the docs and delivery story honest and in-sync with the repo:
`test_quickstart_doc.py` (the offline test count quoted in `docs/QUICKSTART.md`
must equal the real suite size — currently `1698` — and the canonical `make`
targets must match the Makefile), `test_makefile.py`, `test_deploy_scripts.py`,
`test_eval_assets.py`, `test_platform_demo.py`, `test_coverage_smoke.py`,
`test_intake_adapter.py`, `test_config_validation.py`, `test_cyber_skills.py`,
`test_litellm_gateway.py`, `test_mockworld.py`, `test_egress_control.py`,
`test_meta_harnesses.py`, `test_ops_harness.py`.

### g. Secret / account scan

Enforced two ways. In CI, the dedicated `secret-and-name scan` job greps the whole
tree for customer/company names, hardcoded 12-digit AWS account ids in an
ARN/ECR/IAM context, and `AKIA`/`ASIA` access-key ids — and fails the build on any
hit (the workflow is written to be self-non-matching). In the Python suite, the
doc-guard and evidence tests independently assert that no real account id or
customer name can slip into a committed file: `test_quickstart_doc.py` forbids any
12-digit run other than `000000000000`, the `tests/smoke/` `*_evidence_is_account_scrubbed`
checks enforce the scrub on every evidence JSON, and the live-scenario tests build
fake 12-digit ids **at runtime** (never as a source literal) so even the test
fixtures stay scan-clean.

### Test area → file(s)

| Area | File(s) |
|---|---|
| core builders / config invariants | `test_config_validation.py`, `test_core_endpoint.py`, `test_core_update.py` |
| invoke / HITL resume | `test_core_invoke_resume.py` |
| loader (`harness.yaml` → kwargs) | `test_loader.py` |
| registry governance (dual-gate) | `test_registry.py`, `test_registry_governance.py`, `test_registry_minyaml.py` |
| registry live wrapper (fake control client) | `test_registry_live.py` |
| gateway + JWT authorizer | `test_gateway.py`, `test_gateway_jwt.py` |
| agent factory / harness ops | `test_factory.py`, `test_harness_ops.py` |
| sandbox PreToolUse hook | `test_sandbox_hooks.py` |
| exporter | `test_exporter.py` |
| feedback / whitelist loop | `test_feedback.py`, `test_whitelist_optimizer.py` |
| Play Mode simulation | `test_simulation.py` |
| CLI | `test_cli.py` |
| offline tool handlers | `test_tool_handlers.py`, `test_asset_lookup.py`, `test_enrich_ioc.py`, `test_ops_query.py`, `test_siem_query.py`, `test_create_ticket.py`, `test_sigma_match.py`, `test_sigma_yara_lint.py`, `test_run_evaluation.py` |
| `*_live` tool clients (127.0.0.1 mock server) | `test_asset_lookup_live.py`, `test_attack_lookup_live.py`, `test_enrich_ioc_live.py`, `test_epss_kev_live.py`, `test_nvd_lookup_live.py`, `test_ops_query_live.py`, `test_siem_query_live.py`, `test_web_search_live.py` |
| scenarios (offline) | `test_agent_factory_scenario.py`, `test_alert_triage_poc.py`, `test_bas_replay_scenario.py`, `test_cve_asset_triage.py`, `test_detection_gen_scenario.py`, `test_detonation_scenario.py`, `test_feedback_loop_scenario.py`, `test_self_improve_scenario.py`, `test_live_a2a_runtime_scenario.py` |
| M2 milestone suite | `test_m2_demo.py`, `test_m2_e2e_offline.py`, `test_m2_edge.py`, `test_m2_harnesses.py`, `test_m2_integration.py`, `test_m2_regression.py` |
| BAS / detonation drivers | `test_bas_runner.py`, `test_bas_cases.py`, `test_detonation.py`, `test_detonation_runner.py`, `test_detonation_lifecycle.py` |
| specialist containers + A2A contract | `test_specialist_containers.py`, `test_cve_intel_container.py`, `test_specialist_a2a_contract.py`, `test_cve_intel_a2a.py`, `test_specialist.py`, `test_attack_mapper.py`, `test_threat_hunt.py` |
| doc / make / deploy guards | `test_quickstart_doc.py`, `test_makefile.py`, `test_deploy_scripts.py`, `test_eval_assets.py`, `test_platform_demo.py`, `test_coverage_smoke.py`, `test_intake_adapter.py`, `test_cyber_skills.py`, `test_litellm_gateway.py`, `test_mockworld.py`, `test_egress_control.py`, `test_meta_harnesses.py`, `test_ops_harness.py` |
| M4 acceptance smoke (offline + opt-in live) | `tests/smoke/test_m4_acceptance.py` |
| CDK stack synth (ts-node, separate job) | `iac-cdk/test/*.test.ts` |

---

## 4. The 5 skips

On the default offline run you will see exactly **5 skipped** tests. All five are
intentional and gated on an *absent optional dependency* or an *un-opted-in live
path* — none is a masked failure:

| Skip | Location | Reason |
|---|---|---|
| `strands` absent | `test_attack_mapper.py:206` | `pytest.importorskip("strands")` / `("litellm")` — the real Strands-Agents + LiteLLM stack is optional; the specialist's logic is tested with stubbed deps, and the *real* model path skips when the stack is not installed. |
| `strands` absent | `test_litellm_gateway.py:173` | same — the LiteLLM gateway's real `LiteLLMModel` path is `importorskip`'d; the stubbed-model path always runs. |
| `strands` absent | `test_specialist.py:198` | same — real specialist wiring is `importorskip`'d so CI stays green when the agent stack is absent. |
| `strands` absent | `test_threat_hunt.py:286` | same. |
| live re-verify not opted in | `tests/smoke/test_m4_acceptance.py:397` | `skipif` unless `SENTINEL_SMOKE_LIVE=1` **and** AWS creds resolve — the opt-in, read-only STS probe. |

Install the optional stack (`strands-agents`, `litellm`) and the four `strands`
skips convert to runs; opt into `SENTINEL_SMOKE_LIVE=1` with creds and the fifth
runs its read-only STS probe. Absent both, the suite is fully green at
`1698 passed, 5 skipped`.

---

## 5. Live / on-account validation

The suite is offline by default, but the platform *has* been validated against real
AWS on a **non-production dev/test account**, and those proofs are captured (with
the account id scrubbed to `000000000000` / `<ACCOUNT_ID>`) as **23 evidence JSON
artifacts** under `evidence/`. Two opt-in switches let you re-run the live checks
yourself:

- **`SENTINEL_SMOKE_LIVE=1`** — turns on the live re-verification in
  `tests/smoke/`. It is a minimal, **non-destructive, read-only** STS
  `get_caller_identity` probe confirming creds resolve in `us-east-1`; it creates
  and mutates nothing. Runs only when the flag is set *and* credentials resolve;
  otherwise it skips. Heavier live round-trips (Gateway create/delete,
  `apply_guardrail` masking) live in the M4 scenarios, not duplicated here.

  ```bash
  SENTINEL_SMOKE_LIVE=1 AWS_PROFILE=<your-profile> \
  AWS_REGION=us-east-1 AWS_DEFAULT_REGION=us-east-1 \
  pytest tests/smoke/ -rs
  ```

- **`SENTINEL_A2A_LIVE=1`** (or `--live`) — documented in
  `scenario_live_a2a_runtime.py` / `test_live_a2a_runtime_scenario.py` for the real
  AgentCore Runtime A2A path. It is **never** taken in CI; the test explicitly pops
  the env var so the default run stays offline.

**The `evidence/*.json` capture convention.** Each `*_result.json` is written by
the matching `scenarios/scenario_*.py`; each `*.log` is the raw run log. They are
captured results from real GA-API runs on a non-prod dev account, with **every
account id scrubbed** to the `000000000000` / `<ACCOUNT_ID>` placeholder. The
`tests/smoke/` `*_evidence_is_account_scrubbed` checks enforce the scrub on every
commit, so a real 12-digit id can never reach this public repo. What was validated
live (and is now frozen as evidence) includes: a Gateway `create → READY → delete`
on the GA API; a Guardrail `GUARDRAIL_INTERVENED` masking a fake AWS key; Cognito
CUSTOM_JWT OIDC/JWKS RS256; a private-VPC default-deny egress posture (no
IGW/NAT/`0.0.0.0/0`); AgentCore Registry create + records + DRAFT →
PENDING_APPROVAL governance; and a real `CreateAgentRuntime` → arm64 microVM →
live A2A `message/send` → real Bedrock Haiku CVE triage, then torn down.

**Honest remaining limits (stated, not hidden).** A full CDK `cdk deploy` of the
Registry/runtime raw-`CfnResource` stacks fails until those CloudFormation types are
GA *and* the `bedrock-agentcore-control` SDK client is bundled into the Lambda
asset; wiring the `*_LIVE` tool seams to a real SIEM/asset/IOC/ticketing backend
needs a customer account; detonation is an honestly-labelled **simulated** no-op (no
real malware/VM/network); and on the primary dev account `CreateAgentRuntime` is
blocked by an org SCP (it was validated on a separate test account). See the README
status matrix (🟢/🟡/🟠) and `docs/FIDELITY-REPORT.md` for the authoritative
per-capability ledger. These labels are never upgraded to hide a gap.

---

## 6. Determinism rules for contributors

If you add or change a test, keep the suite offline and deterministic. The
non-negotiables:

1. **No AWS, ever, on the default path.** Never let a test reach a real
   control-plane or data-plane operation. Monkeypatch `core._control` /
   `core._data` (or a module's own `_control`, as in `registry_live.py`) with a
   fake that records request kwargs, and assert on those. If you need a networked
   client path, stand up an in-process `http.server` on `127.0.0.1:0` and tear it
   down in teardown — never call a real host.

2. **Unique-name importlib loading for script-tree modules.** `tools/` and
   `specialists/` ship files literally named `handler` / `agent_a2a`. Load them by
   explicit path under a **unique** module name
   (`importlib.util.spec_from_file_location("siem_query_handler_live_dedicated",
   path)`), and never register the bare `handler` / `agent_a2a` name in
   `sys.modules`. This prevents sibling modules from poisoning each other's
   namespace when the whole suite imports in one process.

3. **No clock, no randomness, no wall-time.** Do not assert on `datetime.now()`,
   `time.time()`, `uuid` values, or unseeded `random`. If a code path needs an id
   or timestamp, inject it or assert only on its *shape* (e.g. `runtimeSessionId`
   length ≥ 33), not its value. Any 12-digit id used in a fixture must be built at
   runtime (never a source literal) so the secret/account scan stays clean — and
   only `000000000000` may appear as a literal placeholder.

4. **Set dummy env before importing the package.** Use `os.environ.setdefault(...)`
   for `SENTINEL_REGION`, `AWS_DEFAULT_REGION`, `SENTINEL_EXECUTION_ROLE_ARN`
   (all-zeros account), and dummy `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` so
   import cannot try to resolve a real region/profile/credentials. There is no
   `conftest.py` — each file is responsible for its own hermetic setup.

5. **Gate optional deps with `importorskip`, gate live paths with `skipif`.** If a
   test genuinely needs `strands`/`litellm` or a live AWS round-trip, guard it so it
   *skips cleanly* rather than errors when the dep or opt-in is absent — matching
   the 5 documented skips above. Never let an optional dependency turn a green run
   red.

6. **Keep the doc-count guard true.** The offline test count is asserted in
   `test_quickstart_doc.py` (`EXPECTED_TEST_COUNT`). If you change the suite size,
   update `docs/QUICKSTART.md` in the same change so the guard stays green.

Following these rules is what keeps every `pytest` run reproducible on any machine
— with no AWS account, no network, and no Docker — while still proving the exact
request shapes and error contracts the real GA API enforces.
