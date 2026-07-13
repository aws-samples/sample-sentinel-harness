# M4 acceptance smoke suite (`tests/smoke/`)

A small, re-runnable freeze of the **M4** acceptance proofs. M4 (the L3
"defense-in-depth + real Amazon Bedrock AgentCore GA control-plane" milestone)
was validated once, live, on a real non-prod dev account in `us-east-1`. That
one-time proof rots: evidence files drift, the CDK app can stop synthesizing, the
JWT authorizer shape can regress, and the deterministic BAS blind-spot arithmetic
can silently change. This suite is the ROADMAP-M7 `tests/smoke` habit applied to
M4 — it re-asserts, on every `pytest` run, the M4 promises that are **provable
OFFLINE**, so a regression fails CI immediately.

## Honesty boundary — what is proven where

| Layer | What this suite does | Live? |
|---|---|---|
| Evidence verdicts | Reads the 4 M4 evidence JSONs and asserts the **recorded** verdict still says what the M4 audit found (guardrail `GUARDRAIL_INTERVENED` + masked tokens; live-deploy region `us-east-1`; gateway created+deleted+gone). The verdicts were captured **live at M4 time**; this suite does not re-run those AWS calls. | offline (reads live-captured evidence) |
| CDK synth | Runs the **local** `cdk synth --all` (offline, no deploy) and confirms all **8** stacks are produced. | offline |
| JWT authorizer | Builds `customJWTAuthorizer` in-process and asserts the human (`allowedAudience`) vs machine (`allowedClients`) shapes. | offline (pure Python) |
| BAS blind spots | Runs `sigma_match` + `bas_cases.replay` and asserts the deterministic blind-spot result. | offline (pure Python, no LLM) |
| Live re-verification | Optionally re-probes STS to confirm creds resolve in `us-east-1`. | **live, opt-in only** |

The suite never fakes liveness: the live check **skips** unless you opt in, and
the offline checks are labeled as reading live-captured evidence, not re-proving
the AWS round-trip.

## Running

### Offline (default) — fully green, ZERO AWS, ZERO network

```bash
pytest tests/smoke/
# or as part of the whole suite
pytest tests/
```

The default run makes **no AWS or network calls**. The CDK synth check shells out
to the local `iac-cdk/node_modules/.bin/cdk` (offline synth) and **skips** if
`node_modules` is absent. The optional `egress_control_result.json` check skips if
that file is not present.

### Live re-verification (opt-in)

```bash
SENTINEL_SMOKE_LIVE=1 \
AWS_PROFILE=<your-profile> AWS_REGION=us-east-1 AWS_DEFAULT_REGION=us-east-1 \
pytest tests/smoke/ -rs
```

The live check runs only when `SENTINEL_SMOKE_LIVE=1` **and** AWS credentials
resolve. It is a minimal, **non-destructive, read-only** STS probe (`get_caller_identity`)
confirming the M4-unified `us-east-1` region; it creates and mutates nothing.
Heavier live round-trips (gateway create/delete, `apply_guardrail` masking) live in
the M4 scenarios themselves and are not duplicated here.

## Acceptance-criteria map

| M4 acceptance criterion | Check(s) |
|---|---|
| Guardrail intervened live + masked both tokens | `test_guardrail_evidence_intervened_and_masked` |
| Live deploy unified to `us-east-1`; 3 free-tier controls retained; PrivateLink cost-gated off | `test_live_deploy_evidence_region_and_stacks` |
| Real GA gateway created **and** deleted (no leftover) | `test_gateway_lifecycle_evidence_created_and_deleted` |
| Optional egress-control evidence shape (if present) | `test_egress_control_evidence_if_present` |
| All 8 CDK stacks synthesize | `test_cdk_app_synthesizes_all_eight_stacks` |
| `cognito_jwt_authorizer` shapes (human/machine) + misconfig raises | `test_cognito_jwt_authorizer_*` |
| Deterministic BAS blind-spot result | `test_bas_replay_deterministic_blind_spots`, `test_bas_replay_is_deterministic`, `test_bas_replay_empty_ruleset_is_all_blind_spots` |
| Evidence files scrub the real account id | `test_*_evidence_is_account_scrubbed` |
| (opt-in) live creds resolve in `us-east-1` | `test_live_caller_identity_region` |

## Determinism / no-secrets posture

- No LLM, no tokens, no network on the default path.
- Evidence files are account-id-scrubbed (`<ACCOUNT_ID>` / `000000000000`
  placeholder only); the `_assert_no_real_account_id` checks enforce this so a
  real 12-digit id can never slip into a public commit.
