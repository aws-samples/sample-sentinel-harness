# Troubleshooting — known footguns

A consolidated **symptom → cause → fix** for the traps a newcomer or extender
hits first. Each entry cites the exact file/symbol so you can go read the code.

If you hit something not listed here, check [`docs/FIDELITY-REPORT.md`](FIDELITY-REPORT.md)
(honest real-vs-built self-audit) and [`docs/SETUP.md`](SETUP.md) (least-privilege
execution role and live-run config) before filing an issue.

---

## 1. `invoke` silently returns empty / the model never runs — bare model id

**Symptom.** You point a harness at a model like `anthropic.claude-haiku-4-5`
or `global.anthropic.claude-haiku-4-5` (no version suffix). Create/`wait_ready`
succeed, but `invoke` comes back empty or the loop produces no model output —
no obvious error.

**Cause.** AgentCore resolves the model id verbatim. A model id **must carry a
full version suffix** or the invoke silently fails; a prefix-only id is not a
valid inference target.

**Fix.** Always use a fully-versioned cross-region inference id. The pinned
defaults in [`sentinel_harness/core.py`](../sentinel_harness/core.py) (`MODEL_SONNET`,
`MODEL_HAIKU`, `MODEL_OPUS`, lines 79–81) show the shape, e.g.
`global.anthropic.claude-haiku-4-5-20251001-v1:0` and
`us.anthropic.claude-opus-4-5-20251101-v1:0`. When you override via
`SENTINEL_MODEL_*` env vars or pass a literal to `bedrock_model(model_id)`
(`core.py:94`), keep the `-YYYYMMDD-v1:0` suffix. Do not pin a version you
cannot verify is available in your account/region.

---

## 2. `ValidationException` on `runtimeSessionId` — session id too short

**Symptom.** `invoke` / `invoke_with_tool_result` throw a `ValidationException`
about `runtimeSessionId`, or a resumed tool-result turn is rejected.

**Cause.** AgentCore requires `runtimeSessionId` to be **≥ 33 characters**. A
short id (a bare counter, a truncated UUID) fails validation.

**Fix.** Mint session ids with
[`new_session()`](../sentinel_harness/core.py) (`core.py:99`) — it returns a
hyphenated UUID composition (36+ chars) and documents the ≥ 33 rule inline.
Reuse the **same** session id across a tool-result resume: `invoke` and
`invoke_with_tool_result` both take `session_id` and pass it as `runtimeSessionId`
(`core.py:270`, `core.py:293`).

---

## 3. A bad `harness.yaml` field is accepted locally, then fails on-account

**Symptom.** A config typo (bad name, unexpanded `${ENV}`, a field the
control plane rejects) is not caught until you make a real `CreateHarness`
round trip and it fails server-side — with a terse message.

**Cause.** **Server-side harness-config validation is silent / late.** The
loader resolves the YAML but does not fully validate every field against the
control plane; some errors only surface on the create call.

**Fix.** Guard with a **factory dry-run first**. `provision_fleet(manifest, dry_run=True)`
in [`sentinel_harness/factory.py`](../sentinel_harness/factory.py) (`factory.py:191`)
resolves and validates every config locally — YAML read, `${ENV}` expansion,
name-rule check (`[a-zA-Z][a-zA-Z0-9_]{0,39}`, no hyphens), tag checks — and
reports what *would* happen without touching the control plane. Only a real
run (`dry_run=False`) or `teardown_fleet` reaches AWS. Load a single config with
`load_harness_config` / `create_from_config` in
[`sentinel_harness/loader.py`](../sentinel_harness/loader.py) (`loader.py:196`,
`loader.py:239`).

---

## 4. `cdk synth` is clean but `cdk deploy` fails — native Registry/Runtime CFN not GA

**Symptom.** `npx cdk synth` succeeds (CI is green), but a real `cdk deploy`
of the Registry or Runtime stack fails with an unknown-resource-type error.

**Cause.** The **native AgentCore Registry/Runtime CloudFormation types are not
GA**. The stacks default to a raw `CfnResource` of type
`AWS::BedrockAgentCore::Registry` (and the Runtime equivalent), which **synths
cleanly but fails on deploy** until the CFN type ships. The control-plane APIs
themselves *are* live-verified (see the evidence table in the README) — it is
only the declarative CFN path that is synth-only.

**Fix.** For live provisioning, drive the control plane via the SDK
([`sentinel_harness/registry_live.py`](../sentinel_harness/registry_live.py)),
not `cdk deploy` of the raw type. See the design notes at the top of
[`iac-cdk/lib/registry-stack.ts`](../iac-cdk/lib/registry-stack.ts) (lines 15–46,
66–76): PATH A (default, flag off) keeps the synth-only `CfnResource`
fallback with zero regression; PATH B is a custom-resource path
([`iac-cdk/lib/registry-cr.ts`](../iac-cdk/lib/registry-cr.ts)) that requires
the `bedrock-agentcore-control` SDK client bundled into the Lambda asset.

---

## 5. Explainer deck thumbnails are blank when opened locally

**Symptom.** You open the explainer deck's HTML from disk and the embedded
`iframe` slide thumbnails (the live-preview panels) render blank; the hosted
deck at <https://sentinel-harness-deck.pages.dev/> shows them fine.

**Cause.** The deck's iframe thumbnails only render over **`http(s)`, not
`file://`** — browsers block cross-document/iframe embedding under the
`file://` origin.

**Fix.** Use the hosted deck (see the README
["Explainer deck"](../README.md) section, lines 193–205), or serve the deck
directory over local HTTP (`python -m http.server`) rather than double-clicking
the file. The static `assets/deck/*.png` thumbnails in this repo render
anywhere; the iframe issue is only for the interactive deck.

---

## 6. GitHub Actions minutes get billed — repo went private

**Symptom.** CI (`.github/workflows/ci.yml`) starts consuming billed Actions
minutes.

**Cause.** **GitHub Actions is free only for public repositories.** If the
repo is flipped to private, every CI run (the 3-way Python matrix + the CDK
synth job + the secret/name scan) bills against the account's Actions quota.

**Fix.** Keep the repo **public** (it is public OSS by design). If you must
fork private, expect to pay for minutes, or disable/scope the workflows. The
secret-and-name scan job in [`ci.yml`](../.github/workflows/ci.yml) exists
precisely because the repo is public — it fails the build on any customer name
or hardcoded 12-digit account id.

---

## 7. `CreateAgentRuntime` is denied on the primary dev account — org SCP

**Symptom.** `CreateAgentRuntime` returns an AccessDenied / explicit-deny even
though your execution role looks correct.

**Cause.** On the **primary dev account, `CreateAgentRuntime` is blocked by an
org SCP**. This is an organization-level guardrail, not a role-policy gap — you
cannot fix it by editing the execution role.

**Fix.** Run Runtime live-validation on a **separate test account** without the
SCP (that is how the A2A-on-Runtime evidence in
[`evidence/live_a2a_runtime_result.json`](../evidence/live_a2a_runtime_result.json)
was captured). The README's "Honest note on what is not yet proven" states this
explicitly. Registry control-plane and Gateway lifecycle are unaffected and
were validated on-account.

---

## 8. A `*_LIVE` tool raises `upstream_error` — by design, never a silent fallback

**Symptom.** With a `*_LIVE` env set, a tool returns
`{"ok": false, "error": "upstream_error", ...}` instead of data.

**Cause.** This is **intended**. The four backend-pluggable tools —
`siem_query` (`SIEM_QUERY_LIVE`/`SIEM_QUERY_URL`/`SIEM_QUERY_TOKEN`),
`asset_lookup` (`ASSET_LOOKUP_*`), `enrich_ioc` (`ENRICH_IOC_*`), and
`ops_query` (`OPS_QUERY_*`) — default to an offline mock world. Setting
`*_LIVE=1` opts into a real stdlib `urllib` HTTP client. Any live-path failure
(missing URL, DNS/refused/timeout/TLS, non-2xx, oversized or malformed reply)
surfaces as `upstream_error`. It **never silently falls back** to the offline
fixtures and **never swallows the exception** — a masked backend outage would be
worse than an explicit error in a SecOps tool.

**Fix.** Read the failure posture at
[`tools/siem_query/handler.py`](../tools/siem_query/handler.py) (`_fetch_live`,
lines 250–316, and `handler` classification at `siem_query/handler.py:356–368`)
and [`tools/siem_query/README.md`](../tools/siem_query/README.md) (lines 89–96).
To go back to the mock world, **unset** the `*_LIVE` env — do not expect an
automatic fallback. If `*_LIVE=1` is set with no `*_URL`, that is a deliberate
`RuntimeError` → `upstream_error` telling you to unset the flag
(`siem_query/handler.py:276`). The same seam contract applies to
`asset_lookup`, `enrich_ioc`, and `ops_query`.
