# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

_Nothing yet._

## [0.3.0] — 2026-07-12

Quality, live-proof, and observability release. Milestones **M8–M12** land (CI/security
gates, on-platform depth, north-star safety), **all `[EXTERNAL]` live proofs** are
captured on a non-production dev/test account, a unified logging + multi-signal
observability layer ships, an adversarial repo audit's findings are cleared, and the
supply-chain / API-docs / CI toolchain is hardened. Test suite: **1742 offline passing
(+6 skipped) across 89 files, coverage 91%**; **30 evidence artifacts**.

### Added
- **Live `[EXTERNAL]` proofs** (real AWS, non-prod, scrubbed) — CUSTOM_JWT gateway
  enforcement end-to-end (`live_custom_jwt_gateway_result.json`), managed Evaluate
  on-demand judge (`live_managed_evaluator_result.json`) **and** continuous online
  evaluation over CloudWatch Transaction Search `aws/spans`
  (`live_online_evaluation_result.json`), A2A specialist on AgentCore Runtime
  (`live_a2a_runtime_result.json`), the M12 end-to-end closed loop with `closed:true`
  (`closed_loop_result.json`), and cross-session Memory SEMANTIC recall + multi-tenant
  isolation (`live_memory_recall_result.json`, `live_memory_isolation_result.json`).
- **Gateway request/response hardening** — `lambda_interceptor()` + `policy_engine_config()`
  builders and `create_gateway(interceptor_configurations=…, policy_engine_configuration=…)`,
  schema-drift-tested against the real `CreateGateway` model.
- **Unified logging** — `sentinel_harness.logutil` (`get_logger` / `configure_logging`,
  `SENTINEL_LOG_LEVEL` / `SENTINEL_LOG_JSON`, stderr default, Lambda-safe, idempotent).
- **Multi-signal observability** — generalized `observability` emitters
  (`emit_invoke_latency` / `emit_tool_calls` / `emit_error` / `emit_hitl_gate` /
  `emit_eval_score`, `METRIC_FIELDS`) and `core.invoke_and_meter()` that emits the
  token/latency/tool-call/error signals in one call (closing the previously-dead token
  metric). New `docs/OBSERVABILITY.md`.
- **API reference site** — pdoc → GitHub Pages (`.github/workflows/docs.yml`), live at
  <https://neosun100.github.io/sentinel-harness/>, with a `docs-drift` test guarding
  public-export docstrings.
- **Supply-chain in `release.yml`** — CycloneDX SBOM + SLSA build-provenance attestation
  + PyPI OIDC Trusted Publishing. New `docs/RELEASING.md`.
- **`adversarial-reviewer` specialist** and expanded eval datasets (hard negatives,
  ambiguous severity, safety traps); provenance ledger (`provenance.py`).
- **Client-facing explainer deck** — a dark, animated-SVG HTML presentation (show +
  presenter views) on Cloudflare Pages: <https://sentinel-harness-deck.pages.dev/>.
- **Adopter docs** — `INTEGRATIONS`, `COOKBOOK`, `TROUBLESHOOTING`, `COMPARISON`,
  `GLOSSARY`, `THREAT-MODEL`, `SECRETS`, ADR trail, `.devcontainer/`.

### Changed
- Three library-internal `print()` sites (harness/gateway cleanup, Play Mode) migrated
  to the structured logger (stderr, level-gated) — scenario stdout is unchanged.
- All GitHub Actions pinned to Node-24 SHAs (`actions/checkout` v7, `setup-python` v6.3)
  across every workflow; cleared the Node-20 deprecation warnings.
- `pyproject.toml` gains a `[project.optional-dependencies] test` extra
  (`pip install -e '.[test]'`); README quickstart uses it.
- Docs reconciled to real counts (1742 tests / 89 files / 30 evidence / 9 CDK stacks);
  the fully-autonomous-loop claim softened to "end-to-end, runner-orchestrated".

### Fixed
- **SSRF (correctness/security)** — `enrich_ioc` defined an SSRF guard but never called
  it (dead code); wired it in and removed its errant loopback block. Ported the guard to
  `ops_query` / `asset_lookup` / `web_search` (previously none). Replaced a false-green
  metadata test with a `urlopen`-spy that fails unless the guard fires first.
- **`whitelist_optimizer` TP-safety bug** — the emitted Sigma `domain_suffix` clause used
  a bare suffix that suppressed a true positive (`evilexample.com`) the tool certified
  safe; now dot-anchored to match the guard, with a regression test.
- **`make test`** now includes `--with hypothesis` (was drift vs `ci`; the quickstart
  command aborted on `ModuleNotFoundError`).

### Security
- Public-repo hygiene: removed the internal system name from all tracked files
  (public-safe phrasing); CI `secret-and-name` scan + `test_quickstart_doc` enforce no
  customer name / real 12-digit account id.

## [0.2.0] — 2026-07-09

Milestones M0–M7 all delivered. Sentinel-harness grows from a Layer-1 reference into
a full self-iterating SecOps agent factory with live-verified control planes: the
meta-agent builds and self-improves agents, Layer-2 attack validation runs on a real
Sigma matcher, the Layer-3 foundation IaC is deployed to a non-prod dev/test account,
and an A2A specialist executed end-to-end on AgentCore Runtime against a real model.

Everything below is grouped by milestone, then by Keep-a-Changelog category. All test
counts are offline and deterministic (zero AWS by default). Live claims are marked and
were validated on a **non-production dev/test account** (account id scrubbed to
`000000000000` in all committed evidence). The honest remaining limits are enumerated
under **Known limitations** — no 🟡 was promoted to 🟢 and no full `cdk deploy` or
live customer backend is claimed.

### M1 — meta-agent self-iteration (agent builds agents)

#### Added
- **Meta-agent self-iteration** (`harnesses/meta-agent/`, `harnesses/agent-ops/`,
  `intake/adapter.py`, `tools/harness_ops`): an agent that normalizes a natural-language spec
  (or notes / framework errors) into a harness definition, then authors, validates, and
  provisions the child harness. **Live-validated** — the agent-builds-agents loop ran
  end-to-end (`scenarios/scenario_agent_factory_loop.py`, evidence recorded with account id
  scrubbed).

### M2 — evaluation-driven self-improvement

#### Added
- **Self-improvement loop** (`harnesses/self-improving/`, `harnesses/llm-judge/`,
  `tools/run_evaluation`): score a harness against an eval set, generate an improved
  candidate, then **promote** it only when the score clears the bar — a closed score →
  improve → promote cycle. **Live-validated** (`scenarios/scenario_self_improve_loop.py`).

#### Tests
- Added regression, integration, offline-E2E, edge, and demo suites for the M2 loop
  (`test_m2_regression.py`, `test_m2_integration.py`, `test_m2_e2e_offline.py`,
  `test_m2_edge.py`, `test_m2_demo.py`, `test_m2_harnesses.py`).

### M3 — Layer 2 attack validation

#### Added
- **Real Sigma matcher** (`tools/sigma_match`): a functional detection-logic evaluator
  (not a stub) that matches Sigma rules against event records.
- **BAS detection-replay** (`scenarios/scenario_bas_replay.py`, `tools`/`tests` for BAS cases):
  replays breach-and-attack-simulation cases through the matcher to validate detections.
- **Honest skeletons** for the tiers that are not yet runnable end-to-end, kept explicitly
  labelled as skeletons rather than dressed up as live.

#### Tests
- Closed measured coverage gaps (74% → 98%) with dedicated `asset_lookup` tests and added
  coverage tooling (`test_sigma_match.py`, `test_bas_cases.py`, `test_bas_replay_scenario.py`).

### M4 — Layer 3 foundation IaC

#### Added
- **L3 foundation IaC** (`iac-cdk/`, `iac-terraform/`): identity, network/VPC, guardrail,
  observability, and harness stacks in both CDK and a Terraform mirror.
- **Egress control**: a private-VPC default-deny posture (no IGW / NAT / `0.0.0.0/0` route)
  plus a deploy runbook, platform demo, and smoke suite.
- **Live-deployed and validated** on a non-prod dev/test account:
  - Guardrail `GUARDRAIL_INTERVENED` masked a fake AWS key (`evidence/` proof).
  - Cognito `CUSTOM_JWT` OIDC/JWKS RS256 identity.
  - Private-VPC default-deny egress verified (`closed: true`).

#### Fixed
- Unified all live stacks to a single region (`us-east-1`) and root-fixed a Cognito domain
  global-collision failure.
- EC2 `SecurityGroup` rejects a non-ASCII `GroupDescription` — enforced ASCII-only in stack
  strings.

#### Changed
- Trued up every claim after an AgentCore authenticity audit; corrected a stale region
  reference.

### M5 — mock data planes, tools, skills, and ops automation

#### Added
- **Mock data layer + data-plane tools** (`tools/siem_query`, `tools/asset_lookup`,
  `tools/enrich_ioc`) with an alert-triage POC wired end-to-end on DIY mock data.
- **Ops-automation harness** (`harnesses/ops-automation/`, `harnesses/agent-ops/`,
  `tools/ops_query`, `tools/harness_ops`) for fleet/multi-account operations.
- **Cyber skills** (`skills/soc-triage`, `soc-ip-lookup`, `incident-ticketing`,
  `multi-account-ops`, `cve-asset-triage`) in AgentSkills.io format.
- **CVE-asset triage** scenario cross-linking CVE intel to asset inventory.
- **`*_LIVE` tool seams**: SIEM / asset / IOC / ops clients are backend-pluggable HTTP
  clients — real seams that connect to a customer backend when one is supplied (offline mock
  by default). See Known limitations for what is not yet wired.

#### Tests
- Added `test_mockworld.py`, `test_alert_triage_poc.py`, `test_cve_asset_triage.py`,
  `test_cyber_skills.py`, and `*_live.py` seam tests for each data-plane tool.

### M6 — feedback loop

#### Added
- **Feedback-loop automation** (`tools/whitelist_optimizer`, feedback scenario): analyst
  disposition auto-feeds detection strategy, closing the loop — HITL-gated so a human
  approves before strategy changes take effect.

#### Fixed
- Stopped tracking `.omc/` — OMC session memory had leaked a private-note filename into the
  repo.

#### Tests
- Added `test_feedback.py`, `test_feedback_loop_scenario.py`, `test_whitelist_optimizer.py`.

### M7 — delivery form

#### Added
- **One-command entry** via `Makefile`, a lock-in-free `sentinel export`, and a `QUICKSTART`
  so the harness can be adopted without bespoke setup.

#### Tests
- Added `test_makefile.py`, `test_exporter.py`, `test_quickstart_doc.py`.

### Registry control plane — live-verified

#### Added
- **AgentCore Registry control plane** (`sentinel_harness/registry.py`, `tools`/scenario,
  `iac-cdk/lib/registry-stack.ts` + `registry-cr.ts`): create + records +
  `DRAFT → PENDING_APPROVAL` governance flow. **Live-verified on-account** via
  `test_registry_live.py` / `registry_live.py`.
- A Lambda-backed custom-resource fallback (`registry-cr.ts`) so the Registry stack is
  deploy-ready ahead of the CFN type reaching GA (see Known limitations).

### AgentCore Runtime — live A2A end-to-end

#### Added
- **Live A2A specialist on AgentCore Runtime** (`specialists/cve-intel/`,
  `iac-cdk/lib/runtime-stack.ts`, `scenarios`/`test_live_a2a_runtime_scenario.py`):
  `CreateAgentRuntime` provisioned a real arm64 microVM (public net, A2A), a live
  `message/send` returned HTTP 200 driven by a real Bedrock Haiku model, which triaged
  Log4Shell (`CVETriage`, CVSS 10.0). Torn down afterward.
- Productionized the cve-intel A2A container with a real Docker build and a contract test
  (`test_cve_intel_container.py`, `test_cve_intel_a2a.py`).

### Adversarial completeness review

#### Fixed
- Resolved **25 findings** from an adversarial completeness re-audit, including:
  - a **sandbox newline-bypass** in the PreToolUse command allowlist,
  - a `--region` CLI flag that was a **no-op**,
  - missing **byte-caps** on unbounded reads,
  - model-id pinning (full version suffix required or invoke silently fails),
  - a tautological test assertion, and a doc overclaim.

### Nice-to-have polish (13 items)

#### Added
- **Runtime CDK stack** (`iac-cdk/lib/runtime-stack.ts`) added to the stack set.

#### Changed
- **Specialist A2A parity** across `cve-intel`, `attack-mapper`, and `threat-hunt`
  (shared `_a2a_contract.py`).
- **Terraform mirror alignment** with the CDK stacks (`terraform validate` clean).
- **CI `iac` job** added: `tsc` + `cdk synth` + stack tests, alongside the Python matrix.

### Changed (project-wide)
- Detection-gen scenario continues to define success on **substance** (independent verdict
  reached + flawed rule withheld from publish + no stray shell) via a robust prose parser,
  not on whether the model emitted a structured tool call — a known model-behavior quirk
  that `allowedTools` narrows but cannot force.

### Security
- CI gained an `iac` job on top of the existing secret / customer-name scan gate; all
  committed evidence uses `000000000000` for account ids and RFC-5737 documentation IPs.
- Fully anonymized — no organization-specific data, hardcoded account IDs, or secrets.

### Tests
- Offline suite grown **42 → 1475 passing** (+5 skipped when optional deps are absent),
  across **77 test files** (76 under `tests/` + 1 under `tests/smoke/`). Still deterministic and zero-AWS by default. CI runs the Python
  matrix (3.10 / 3.11 / 3.12) plus the secret/customer-name scan and the new `iac` job — all
  green at HEAD. (Python 3.13 is outside the supported matrix.)

### Inventory at 0.2.0
- 16 scenarios, 23 evidence JSON artifacts, 14 tools, 9 skills, 8 harnesses
  (including a research-supervisor harness), 3 specialists (cve-intel / attack-mapper / threat-hunt),
  9 CDK stacks (gateway / registry / memory / network / identity / guardrail / observability /
  harness / runtime) plus `iam.ts`, and a `terraform validate`-clean Terraform mirror.

### Known limitations
- A full `cdk deploy` of the Registry / runtime raw-`CfnResource` stacks **fails** until those
  CloudFormation types are GA **and** the `bedrock-agentcore-control` SDK client is bundled into
  the Lambda asset. The stacks synth today and ship a custom-resource fallback.
- Wiring the `*_LIVE` tool seams to a **real customer SIEM / asset / IOC / ticketing backend**
  requires a customer account — the seams are real but ship pointed at offline mock data.
- **Detonation is an honest SIMULATED no-op** (`longrunning/detonation/`) — no real malware,
  VM, or network is exercised.
- On the primary dev account, `CreateAgentRuntime` is blocked by an org SCP; the live A2A
  end-to-end run above was performed on a separate non-prod test account.

## [0.1.0] — 2026-07-03

First public release. A Layer-1 reference implementation of SecOps agents as
configuration on Amazon Bedrock AgentCore Harness.

### Added
- **Core library** (`sentinel_harness/core.py`): `create_harness` / `wait_ready` /
  `invoke` (streaming) / `delete_harness` / `cleanup`, plus builders for
  code-interpreter, remote-MCP, gateway, inline-function tools and managed/BYO memory.
  12-factor (env-parameterized: `SENTINEL_EXECUTION_ROLE_ARN` / `SENTINEL_REGION`).
- **CLI** (`sentinel`): `create` / `invoke` / `list` / `delete` / `cleanup` / `run-scenario`.
- **Three live-validated Layer-1 scenarios**: CVE triage (deterministic compute + HITL
  pause + managed memory), multi-harness parallel + supervisor (≈2.6× measured speedup),
  and detection-generation with an independent adversarial-reviewer harness + publish gate.
- **Reference tool templates** (`tools/`): a real deterministic `sigma_yara_lint`, plus
  offline-safe `nvd_lookup` / `epss_kev` / `attack_lookup` / `web_search` stubs.
- **Agent Skills** (`skills/`): `cve-triage-rubric`, `detection-writing-sop`,
  `ioc-vetting`, `attack-path-reasoning` (AgentSkills.io format).
- **Illustrative harness configs** (`harnesses/`) for the three Layer-1 supervisors.
- **Docs**: `README`, `ARCHITECTURE`, `BLUEPRINT`, `SETUP`, `HARNESSES`, and a
  self-audit `FIDELITY-REPORT`; SVG logo + architecture diagram under `assets/`.
- **CI** with an offline test matrix (Python 3.10–3.12) and a customer-name / secret scan gate.
- **42 offline config-validation tests** (no AWS calls).

### Security
- Execution-role sample policy deliberately **omits** `bedrock-agentcore:InvokeAgentRuntimeCommand`
  (it bypasses the LLM and `allowedTools`); documented as an explicit least-privilege decision.
- Egress control: no raw-download tool; `web_search` returns text only.
- Fully anonymized — no organization-specific data, hardcoded account IDs, or secrets.

### Known limitations
- Layers 2–3 are design specs with reference stubs, not runnable end-to-end (see the
  status matrix in the README).
- The human-in-the-loop scenarios demonstrate the *pause* half; the two-message resume
  is a roadmap item.
- Long-term (semantic) memory extraction is asynchronous (minutes-scale) — expected
  AgentCore behavior, documented in `SETUP.md` / `evidence/README.md`.

[Unreleased]: https://github.com/neosun100/sentinel-harness/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/neosun100/sentinel-harness/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/neosun100/sentinel-harness/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/neosun100/sentinel-harness/releases/tag/v0.1.0
