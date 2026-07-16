# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

**M13 — world-class depth + adversarial hardening.** Additive on top of M0–M12
(no live-validated code rewritten). Test suite **1742 → 2273 offline passing**.

### Added
- **Deployment benchmark** (`sentinel_harness/benchmark.py`) — deterministic
  cost/latency/ops model comparing AgentCore Harness vs raw-Bedrock-DIY vs
  self-hosted EKS, with a procurement-ready Markdown report + evidence.
- **All-domain evaluation** — golden datasets for `alert_triage` / `attack_path` /
  `feedback_loop` (eval now spans 5 domains), a deterministic offline
  assertion-grounding scorer with a hard safety gate (`eval_datasets.py`), and an
  all-domain baseline scenario.
- **Deep enterprise mock world** (`mockdata/enterprise.py`) — 45-host, five-tier
  topology the real attack-path reasoner traverses (3 planted crown-jewel chains).
- **Time-series campaign + cross-domain E2E pipeline** — a 28-alert Log4Shell
  intrusion timeline (`mockdata/campaign.py`) driven through triage → correlation →
  attack-path → feedback → autonomy under one trace (`scenario_e2e_pipeline.py`).
- **Autonomous self-improvement controller** (`sentinel_harness/autonomy.py`) — the
  reusable decision engine (score→revise→gate→promote) closing the north-star
  runner-orchestration gap; wired into the live self-improve scenario (offline-proven).
- **Code-emitted GenAI/OTEL spans** (`sentinel_harness/tracing.py`) — deterministic
  offline span lines + an opt-in real-OTEL path (`SENTINEL_OTEL`), feeding the
  managed online-eval `aws/spans` source.
- **Plug-and-play SIEM/ticketing connectors** (`sentinel_harness/connectors/`) —
  8 SIEM backends (Splunk, Elasticsearch, OpenSearch, QRadar, Microsoft Sentinel,
  Google Chronicle, Sumo Logic, Datadog) + 3 ticketing (ServiceNow, Jira, PagerDuty),
  pure translators wired into `siem_query` via `SIEM_QUERY_CONNECTOR`, plus an
  importable conformance kit that self-certifies any connector.
- **Compliance control mapping** (`docs/COMPLIANCE.md`) — 18 capability anchors →
  SOC 2 / ISO 27001:2022 / NIST CSF 2.0, with a test that fails if any anchor drifts.
- **Suricata detection-rule linting** — `sigma_yara_lint` now lints Suricata rules
  (header grammar, required `msg`/`sid`/`rev`, numeric sid, balanced options,
  multi-rule/comment/continuation handling) alongside Sigma and YARA.
- **Multi-language detection-rule translation** (`tools/detection_translate/`) — a
  deterministic Sigma→YARA/Suricata skeleton translator: faithful modifiers
  (`contains`/`startswith`/`endswith`) become content matches, lossy ones
  (`re`/`base64`/`cidr`/numeric comparisons) are surfaced in an `untranslatable`
  list rather than silently dropped. Registered + governance-approved.
- **Sigma rule-set governance** (`tools/detection_dedup/`) — a deterministic,
  LLM-free tool that reports PROVABLE `duplicate` / `subsumption` / `overlap`
  relationships across a Sigma library (same-logsource pairs, sound
  set-containment over `contains`/`startswith`/`endswith`/equals predicates) and
  surfaces every rule it cannot soundly analyze in `not_analyzed`. Conservative by
  design — it never claims a rule is redundant without a proven subset relation, so
  a "safe to delete" verdict never deletes real coverage. Registered +
  governance-approved.
- **ATT&CK coverage / gap analysis** (`tools/detection_coverage/`) — a
  deterministic, LLM-free tool that answers a detection team's most important
  question: which adversary techniques can we NOT detect? Given Sigma rules (with
  `attack.tXXXX` tags) and a target technique list, it reports `covered` /
  `uncovered` (the blind spots) / `untagged_rules` / `invalid_tags` +
  `coverage_ratio`. Conservative — a sub-technique tag covers its parent but a
  parent tag NEVER covers a specific sub-technique, so a false "covered" cannot
  hide a real blind spot. Registered + governance-approved.
- **One-shot rule-library health check** (`tools/detection_audit/`) — a
  deterministic, LLM-free AGGREGATOR that runs `sigma_yara_lint` (per rule) +
  `detection_dedup` + `detection_coverage` over one Sigma set and folds them into a
  single governance report with a transparent, saturating 0–100 `health_score` and
  a prioritized worst-first `findings` list. Adds no judgement beyond composing the
  three conservative tools; resilient to a junk entry (surfaced, not a crash).
  Registered + governance-approved. This completes the detection-engineering suite:
  **lint → translate → dedup → coverage → audit**.
- **ATT&CK Navigator layer export** (`tools/detection_navigator/`) — a
  deterministic, LLM-free renderer that turns `detection_coverage` output into a
  standard MITRE ATT&CK Navigator layer JSON (v4.5): covered techniques green
  (score 100), blind spots red (score 0), each annotated with the detecting rule(s).
  Drag-drop the layer into mitre-attack.github.io/attack-navigator for an
  executive-ready coverage heat-map. A thin faithful renderer — inherits
  `detection_coverage`'s conservative sub-technique semantics; no network calls.
  Registered + governance-approved.

### Fixed
- **Adversarial audit remediation:** seven hostile-finder/skeptic-verifier rounds
  cleared **89 confirmed defects** total (round-1: 20; round-2: 22; round-3: 17;
  round-4: 6; round-5: 7; round-6: 9; round-7: 8), each with a regression test.
  - Round-7 (gateway auth, mockdata/accounts, remaining scenarios, specialist
    agents, CDK IaC). 8 confirmed:
    - **gateway (HIGH)** — `lambda_interceptor` emitted `payloadFilter.exclude` as a
      list of bare strings, but the CreateGateway API wants `{"field": <jsonpath>}`
      selector structs — the redaction interceptor crashed against the real service
      while two false-green offline tests asserted the buggy shape. Now wrapped as
      `{"field": ...}`; the schema-drift guard test now descends into the element.
    - **egress scenario (HIGH, false-contained)** — the default-deny gate only
      recognized igw-/eigw-/NatGateway as internet targets, so a `0.0.0.0/0` route
      via a Transit Gateway (the standard AWS centralized-egress pattern), a NAT
      instance, VPC peering, or a carrier gateway was silently certified
      "contained". Now FAIL-CLOSED: any non-`local` default-route target is treated
      as internet-capable.
    - **cve-asset scenario (HIGH)** — the CVE↔asset join upper-cased the query id
      but compared case-sensitively against the asset-side `cve_id`, dropping a
      mixed/lower-case match and flipping the verdict to "not exposed". Now
      case-insensitive on both sides.
    - **adversarial-reviewer (HIGH)** — the undefined-selection logic-flaw check
      prefix-matched every condition identifier, so a typo (a prefix of a real
      selection, e.g. `sel` for `selection`) got APPROVE. Now an exact match is
      required unless the identifier is an actual `*` glob.
    - **cve-asset scenario (MED)** — the `blast_radius_computed` invariant was a
      tautology (it compared verdict fields to themselves). Now recomputed
      independently from the raw asset surface.
    - **adversarial-reviewer (MED)** — an empty `condition:` bypassed the
      `missing_condition` objection (the guard was `is None` but the value is `''`).
      Now guards on falsy.
    - **adversarial-reviewer (MED)** — the lone-wildcard (`broad_selection`) check
      missed the YAML list-item form `- '*'` (and the `- *` a dict artifact
      renders). Now matches both the scalar and list-item wildcard forms.
    - **mockdata/accounts (LOW)** — an inline comment misdescribed the per-account
      findings placement; corrected to match the fixture data.
  - Round-6 (gateway, exporter, observability, benchmark_models, scenarios,
    a2a-contract). 9 confirmed:
    - **whitelist_optimizer (HIGH, false-green)** — for a `domain_suffix` whitelist
      whose FP cohort includes the apex domain, the matcher CERTIFIED the apex as
      suppressed (`dv == sv`) but the emitted Sigma only had `|endswith:
      '.suffix'` (which cannot match the apex) — so `scenario_feedback_loop`
      reported `closed=True` while the deployed rule still fired on a real FP. The
      emitter now produces an OR of an exact-apex clause and a strict-subdomain
      clause, keeping matcher and artifact in lock-step.
    - **a2a-contract (HIGH×2, dead-on-arrival seam)** — the production
      `strands_model_callable` in `_a2a_contract.py` and `cve-intel/local_a2a.py`
      fed a Strands `AgentResult.message` (a Message DICT) straight to `json.loads`,
      which always raised `TypeError` → every live A2A call returned an internal
      error. Now the envelope text is extracted from the message's content parts.
    - **gateway (MED)** — target-name validation reused the stricter GATEWAY regex
      (48 chars, no trailing hyphen), falsely rejecting service-valid target names;
      a separate target validator now allows the API's `([0-9a-zA-Z][-]?){1,100}`.
    - **exporter (MED, injection)** — an `allowedTools` entry containing a newline
      broke out of its `#` comment line and injected code into the exported Strands
      module; entries are now collapsed to a single inert comment line.
    - **observability (MED)** — the `emit_*` helpers raised `TypeError` when a
      caller passed a dim colliding with the fixed dimension name
      (`kind`/`gate`/`dimension`/`input_tokens`); the leading params are now
      positional-only and the fixed dim is merged so the caller value wins, no crash.
    - **gateway (LOW)** — `wait_gateway_ready` treated `DELETING` as transient and
      polled to timeout; `DELETING`/`DELETE_UNSUCCESSFUL` are now terminal (fail fast).
    - **observability (LOW)** — a non-finite float DIMENSION value emitted the bare
      `NaN`/`Infinity` token (invalid JSON, silently dropped by a strict
      MetricFilter); dim values are now coerced to a strict-JSON-safe string.
    - **benchmark_models (LOW)** — `ModeModel`/`ModelPrice` numeric fields were
      unvalidated (unlike `Workload`); a negative/NaN override produced negative
      dollars / an out-of-range savings pct / an order-undefined sort. Both now
      validate non-finite/negative at construction + the billing enum.
  - Round-5 (the still-not-deep-audited modules: core invoke loop, loader,
    factory, cli, mockdata). 22 findings → 7 confirmed after independent skeptic
    verification:
    - **cli + core (HIGH)** — `sentinel cleanup ""` (or an unset `$PREFIX` in a
      script) matched EVERY harness (`"".startswith("")` is True) and
      cascade-deleted managed memory with no confirmation. Now refused at BOTH the
      CLI (clean exit-2 usage error) and `core.cleanup` (ValueError) layers, plus a
      `--dry-run` that previews matches.
    - **core (MED)** — parallel HITL gates were captured but not resumable: the
      singular `invoke_with_tool_result` answered only one of N, dropping the
      others (a silently-lost human security decision + a corrupted session). New
      `invoke_with_tool_results` answers every paused gate in the one required
      assistant+user message pair; the singular now delegates to it.
    - **factory (MED)** — teardown deleted an UNTAGGED same-name prior (e.g. a
      pre-tagging prod harness) because the env-guard only fired on tagged priors;
      provision treated such a name as a safe skip while teardown deleted it. Now
      refused (a harness the factory did not stamp is off-limits).
    - **loader (LOW×2)** — `harnessName` was accepted unvalidated (a non-string or
      hyphenated name loaded clean then failed/corrupted downstream); `allowedTools`
      elements were not per-item type-checked (a nested list/dict/None silently
      failed HITL-gate wiring). Both now validated.
    - **factory (LOW)** — the documented `name_prefix` manifest key was a silent
      no-op; now a real governance guard (every provisioned name must start with it).
    - **mockdata (LOW)** — `_HOST_IDS` / `_IOC_BY_VALUE` carried comments claiming a
      reference-integrity guard that did not exist; now a live import-time assertion
      (every alert must name a defined host; malicious src_ips must cross-link to a
      defined IOC).
  - Round-4 (the never-deep-audited M8–M13 core modules: autonomy, tracing,
    eval_datasets, connectors). 22 findings → 6 confirmed after independent
    skeptic verification (a high refute rate — out-of-contract crashes and
    already-caught paths were correctly rejected):
    - **eval_datasets safety gate (HIGH+LOW)** — the offline safety-trap gate
      mis-read a complying unsafe answer as a refusal because `_REFUSAL_MARKERS`
      held weak substrings (`instead` matches "instead of", plus `unsafe`/
      `unauthorized`/bare `reject` that merely NAME the risk); removed them (every
      golden refusal leads with a strong opener, so they added only bypass
      surface). Also fold typographic apostrophes/quotes to ASCII so a curly `’`
      no longer evades the compliance markers.
    - **tracing (MED)** — a non-finite float attribute (`inf`/`NaN`) was emitted as
      the bare `Infinity`/`NaN` tokens, which are not valid JSON and break strict
      `aws/spans` consumers; now folded to a stable string.
    - **autonomy (MED)** — the revise loop's early-stop used only `passed_bar and
      safety_ok`, omitting `regression_ok`; a bar-passing but regressing candidate
      was falsely refused (and, perversely, a worse starting candidate could
      promote while a better one stopped). Now gates on the full
      `promotable_pre_human` condition.
    - **connectors/ticketing (LOW)** — the PagerDuty connector silently dropped
      `assigned_team` and `related_alert_ids`; now carried as an `assignments`
      entry and a `dedup_key` (mirroring ServiceNow's `correlation_id` de-dupe).
  - Round-3 (the brand-new detection-engineering code — `detection_translate` +
    Suricata linting — audited hardest because it had only passed its author's
    tests). Two defect classes:
    - **Translator output-injection** — a Sigma value or title containing the
      target grammar's metacharacters (`"`, newline, `;`, `|`, `(`) broke out of
      the emitted YARA/Suricata literal. Now grammar-escaped: YARA `\xHH`/`\n`
      escaping, Suricata `content:` hex-encoding (`a|b` → `a|7C|b`) and msg
      escaping. A leading-digit Sigma title (`4625 brute force`) yielded an
      illegal YARA rule name → prefixed `r_`.
    - **Lossy-marked-faithful** — `condition: ... and not filter` (negation
      inverts exclude→include), the `|all` aggregator, and null/empty values were
      silently emitted as faithful; all now routed to the `untranslatable` ledger.
    - **Linter false-rejections** — the Suricata option parser split on a `;`
      inside a quoted `msg` (faking sid/rev) and counted parens inside a quoted
      value; the YARA checker counted braces inside hex-strings/regex literals and
      truncated bodies at the first `}`. All now quote-/span-aware (new
      `_split_suricata_options`, `_strip_suricata_quoted`, `_extract_rule_body`,
      hex/regex spans stripped in `_strip_yara_noise`), with a `translate → lint`
      round-trip property test sweeping a title × value hostile matrix.
  - Round-1: safety-gate bypasses (refusal-marker evasion, nested
    `dimensions`-key veto skip), a NaN/non-finite score crash, tracing
    `BaseException` stack corruption, SIEM DSL injection (SPL/AQL/KQL value
    escaping), string-boolean misclassification, an IPv6-CIDR `TypeError`, and
    conformance-kit blind spots.
  - Round-2 (never-deep-audited core modules): true-positive indicators no longer
    suppressed by the feedback whitelist; parallel `tool_use` blocks all captured
    from the invoke stream (+ `_raw` double-pop fix); `teardown_fleet` rejects an
    empty prefix and applies the env tag-guard; `loader` contains a `systemPrompt`
    path to the harness dir (no absolute/`..` escape) and rejects a scalar or
    `'*'`-wildcard `allowedTools`; `cleanup`/`list_harnesses` paginate all
    harnesses; a YARA brace miscount inside string/comment noise; the `_mini_yaml`
    fallback folds block scalars; a non-dict registry spec raises `RegistryError`;
    a DEPRECATED-but-still-coded tool is flagged as drift; token/metric emitters
    fail-safe on `inf`/`NaN`/non-dict usage; and the Datadog nested-`attributes`
    merge lets the top-level value win.

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
