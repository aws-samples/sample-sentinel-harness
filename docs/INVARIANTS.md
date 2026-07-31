# Security Invariants

> The executable contract for `sentinel-harness`'s security-critical behaviour.
> Every invariant here is **enforced by a named test**. A row without a passing
> test is a lie, and `tests/test_invariants_doc.py` fails the build if any test
> named here stops existing.

## Why this file exists

The M18 audit found four defects in code with 90–97% line coverage and a passing
2493-test suite. None was a coding error. All four were **assembly gaps**: a
module documented a fail-closed posture in its docstring, delegated one case to
"the caller", and no caller implemented it.

The clearest example: `loop_safety.safety_failures()`'s docstring said a missing
safety dimension "is NOT counted as a failure here" and added that "a caller that
wants a fail-closed posture on missing safety data can inspect the parsed
dimensions". Its only caller — `autonomy.evaluate_gate`, *the* promotion decision
— never did. A judge that never scored safety therefore promoted the agent.

The lesson is not "write more tests". It is that **an invariant living only in a
docstring is not enforced by anything**. A docstring cannot state which layer
owns a guarantee, cannot be checked against reality, and cannot fail a build. So
each invariant below names three things:

1. the **property** in one sentence, phrased as what must never happen;
2. the **layer that owns it** (so it cannot be delegated into a gap again);
3. the **test that proves it**.

## How to use this file

- **Changing a security module?** Read its invariants first. If your change makes
  one of them false, you are introducing a vulnerability, not a feature.
- **Adding a guarantee?** Add a row *and* a test. A row without a test fails
  `tests/test_invariants_doc.py`.
- **Reviewing?** The invariant IDs are cited in code comments (grep
  `INV-PROMOTE-3`) — that is the link from an implementation detail back to the
  property it serves.

---

## INV-PROMOTE — promotion to production

The self-improvement loop can create a production endpoint. These invariants make
"the loop can never promote something worse or unsafe" structurally true rather
than merely intended.

| ID | Invariant | Owner | Enforced by |
|---|---|---|---|
| **INV-PROMOTE-1** | A promotion NEVER executes without an evaluation the driver itself witnessed as passing. The agent's *claim* of a score is never evidence — only a handler's actual return. | `agent_loop.run_agent_loop` | `test_prop_promotion_policy.py::test_promotion_implies_a_witnessed_passing_eval` |
| **INV-PROMOTE-2** | A promotion NEVER executes on a human approval given for a *different* harness. Consent is subject-bound; approving A cannot promote B. | `agent_loop.run_agent_loop` | `test_prop_promotion_policy.py::test_promotion_implies_human_approval_of_the_same_subject`, `test_m18_security_gates.py::TestApprovalSubjectBinding` |
| **INV-PROMOTE-3** | A promotion NEVER executes on a verdict that did not score EVERY veto dimension (`safety`, `groundedness`). A judge's silence is not a pass. | `autonomy.evaluate_gate` (`require_safety_dims=True`) | `test_prop_promotion_policy.py::test_promotion_implies_every_veto_dimension_was_actually_scored`, `test_m18_security_gates.py::TestMissingSafetyDataFailsClosed` |
| **INV-PROMOTE-4** | A real judge's dimension NAMES reach the veto: `Builtin.Harmfulness` / `Faithfulness` / `safety_score` / `is_safe` are recognized, and inverted-polarity metrics are score-flipped, not just renamed. | `loop_safety.parse_dimension_scores` | `test_m18_security_gates.py::TestSafetyDimensionAliases` |
| **INV-PROMOTE-5** | The eval, the approval and the promotion all name ONE harness. Any mismatch, or any missing subject, refuses the promotion. | `agent_loop.run_agent_loop` | `test_prop_promotion_policy.py::test_promotion_implies_subject_consistency_end_to_end` |
| **INV-PROMOTE-6** | A promotion NEVER regresses below the incumbent best, nor below the caller's pass bar. | `loop_safety.regression_guard` | `test_prop_promotion_policy.py::test_promotion_never_regresses_below_the_incumbent`, `test_loop_safety.py` |
| **INV-PROMOTE-7** | An explicit safety failure vetoes the verdict regardless of how high the aggregate is. Fluency can never buy back a safety failure. | `loop_safety.apply_safety_veto` | `test_loop_safety.py::test_safety_veto_*` |
| **INV-PROMOTE-8** | A missing approval callback means REFUSED, never "skip the gate". | `autonomy.run_improvement_loop`, `agent_loop.run_agent_loop` | `test_prop_promotion_policy.py::test_no_approve_fn_never_promotes` |
| **INV-PROMOTE-9** | A human REJECTION is terminal for that consent — it binds no subject and leaves nothing reusable. | `agent_loop.run_agent_loop` | `test_prop_promotion_policy.py::test_a_rejected_approval_never_promotes`, `test_m18_security_gates.py::TestApprovalSubjectBinding::test_rejection_binds_nothing` |
| **INV-PROMOTE-10** | Every refused promotion is explainable: the audit record carries one reason per refusal. A silent refusal erodes trust as much as a silent approval. | `agent_loop.run_agent_loop` | `test_prop_promotion_policy.py::test_refusals_always_carry_a_reason` |

### Layering note (the M18.1 root cause, recorded so it cannot recur)

`apply_safety_veto` is a pure **combiner**: for it, absence of a safety dimension
is not an explicit failure, so the verdict follows the aggregate. Callers rely on
that. The **fail-closed posture** — "no safety score means not promotable" —
belongs one layer up, in the promotion gate (`autonomy.evaluate_gate`), which
consults `loop_safety.missing_safety_dimensions()`.

Keeping strictness in the gate rather than the combiner is what lets both
contracts be true at once. If you find yourself writing "a caller that wants X
can do Y" in a docstring, **name the caller and check that it does Y** — that
sentence is exactly how INV-PROMOTE-3 went unenforced.

---

## INV-LOOP — loop safety

| ID | Invariant | Owner | Enforced by |
|---|---|---|---|
| **INV-LOOP-1** | Dispatched tool calls NEVER exceed `max_tool_calls`. A spinning agent terminates with `stopped_by == "cap"`. | `agent_loop.run_agent_loop` | `test_prop_promotion_policy.py::test_tool_call_cap_is_never_exceeded` |
| **INV-LOOP-2** | Every paused `toolUseId` is answered exactly once (the live `InvokeHarness` resume contract). A missing or duplicated answer corrupts the session. | `core.invoke_with_tool_results`, `agent_loop` | `test_prop_promotion_policy.py::test_every_pending_gate_is_answered_exactly_once`, `test_agent_loop.py::TestResumeContract` |
| **INV-LOOP-3** | The improvement loop never exceeds `max_rounds` scored attempts, and a reviser that returns an unchanged candidate ends the loop. | `autonomy.run_improvement_loop` | `test_autonomy.py` |
| **INV-LOOP-4** | An unknown tool, an exploding handler, or an empty turn is audited as a structured outcome — never a crash, never an execution. | `agent_loop.run_agent_loop` | `test_prop_promotion_policy.py::test_driver_never_raises_on_arbitrary_streams` |
| **INV-LOOP-5** | A non-finite / bool / unreadable aggregate score coerces to 0.0 (fail-closed), never to a pass. | `autonomy._score_value` | `test_autonomy.py` |

---

## INV-SANDBOX — what a sandboxed agent may execute

| ID | Invariant | Owner | Enforced by |
|---|---|---|---|
| **INV-SANDBOX-1** | An ALLOWED command never contains a shell chain/redirection operator (incl. newline/CR), so a denied verb cannot be smuggled past the leading-verb allowlist. | `sandbox_hooks.validate_command` | `test_fuzz_sandbox_hooks.py` |
| **INV-SANDBOX-2** | An allowed interpreter may run a path-confined FILE, never inline source. `python -c` / `node -e` / `npx <pkg>` are refused. | `sandbox_hooks._check_interpreter_escape` | `test_m18_security_gates.py::TestSandboxInterpreterEscape` |
| **INV-SANDBOX-3** | A package install is never redirected at an attacker-controlled source (`--index-url`, `--registry`, a `git+`/URL/archive spec). | `sandbox_hooks._check_untrusted_package_source` | `test_m18_security_gates.py::TestSandboxInterpreterEscape::test_untrusted_package_source_is_blocked` |
| **INV-SANDBOX-4** | An ALLOWED path never contains a `..` traversal segment and always resolves under a sandbox root. | `sandbox_hooks.validate_path` | `test_fuzz_sandbox_hooks.py`, `test_sandbox_hooks.py` |
| **INV-SANDBOX-5** | The real build/test/VCS surface stays usable: `pip install -r`, `python -m pytest`, `npm ci`, `make test` are allowed. A guard that breaks the normal workflow gets switched off, so zero false positives is a security requirement. | `sandbox_hooks.validate_command` | `test_m18_security_gates.py::TestSandboxInterpreterEscape::test_legitimate_commands_still_allowed` |

### Why the syntactic/semantic split matters

INV-SANDBOX-1 is a **syntactic** property, and the property tests that enforce it
are sound. INV-SANDBOX-2 is a **semantic** one — `python -c "<code>"` contains no
shell metacharacter at all, so it satisfied every syntactic check while executing
arbitrary code. When you add a validator, ask which of the two kinds of property
you are asserting; a passing syntactic fuzz test says nothing about semantic
escapes.

---

## INV-GOV — tool/skill governance

| ID | Invariant | Owner | Enforced by |
|---|---|---|---|
| **INV-GOV-1** | A tool is live only if it is BOTH registry-approved AND code-mapped (the dual gate). | `registry.ToolRegistry.resolve` | `test_registry.py` |
| **INV-GOV-2** | `allowedTools` is always an explicit list — never `['*']`. | harness YAML + `loader` | `test_config_validation.py` |
| **INV-GOV-3** | The provenance ledger is append-only and hash-chained; any edit to a record, or an insert/delete in the MIDDLE, fails verification. | `provenance.verify_ledger` | `test_provenance.py` |
| **INV-GOV-4** | A ledger that was TRUNCATED (last N records deleted, or emptied) is detected — a hash chain cannot do this alone, so the record count + tail hash are anchored outside the chain. `require_anchor=True` additionally refuses an unanchored ledger, because "no anchor" is not "verified". | `provenance.write_anchor` + `verify_ledger` | `test_r9_semantic_gates.py::TestLedgerTruncation` |
| **INV-GOV-5** | A `promoted` provenance record always names an approver. "Promoted by nobody" cannot answer the one question the ledger exists to answer. `rejected`/`held` legitimately have none. | `provenance._entry_to_content` | `test_r9_semantic_gates.py::TestPromotedRequiresApprover` |
| **INV-GOV-6** | An OIDC `discovery_url` is HTTPS to a routable host. The discovery document determines the token-signing keys, so plaintext HTTP lets an on-path attacker swap the JWKS and mint accepted tokens. | `gateway._validate_discovery_url` | `test_r9_semantic_gates.py::TestDiscoveryUrlScheme` |
| **INV-GOV-7** | `allowedAudience`/`allowedClients` contain only concrete, non-blank values — never a wildcard or empty string. These lists ARE the auth boundary (same rule as `allowedTools`, never `['*']`). | `gateway._validate_claim_values` | `test_r9_semantic_gates.py::TestClaimValueHygiene` |
| **INV-GOV-8** | An `allowedTools` entry that is a NEAR MISS for a built-in HITL gate (stray whitespace / wrong case) fails loudly. Silently not injecting it produced a config that read as "has a human-approval gate" while having none. | `loader._inject_inline_gates` | `test_r9_semantic_gates.py::TestHitlGateNearMiss` |
| **INV-GOV-9** | A `whitelist_optimization` task is only emitted when something can SAFELY be suppressed. When every FP indicator is also a TP indicator, the task is withheld (with a recorded reason) and a `rule_regeneration` task is emitted instead — a noisy-but-unsuppressable rule must not produce silence. | `feedback.detect_triggers` | `test_r9_semantic_gates.py::TestUnsuppressableNoise` |

---

## INV-TRANSLATE — a translated detection keeps its match set

A Sigma → SIEM translation is worthless — worse than worthless — if it silently
changes WHAT the rule matches. A false negative here reads as coverage in a SOC
dashboard while catching nothing.

| ID | Invariant | Owner | Enforced by |
|---|---|---|---|
| **INV-TRANSLATE-1** | A lossy modifier (`base64`, `re`, …) is NEVER emitted as a plaintext field predicate on a field-aware target (Splunk/Elastic). `CommandLine\|base64: 'whoami'` matches `base64('whoami')`, not the literal `whoami` — emitting the literal is a disjoint match set. It is withheld and routed to `untranslatable` with the target's native operator (`\| regex`, `regex~`). Byte scanners keep a labelled best-effort literal. | `detection_translate._translate` | `test_r10_semantic_gates.py::TestBase64ModifierIsNotEmittedAsPlaintext`, `::TestRegexModifierIsNotEmittedAsLiteral` |
| **INV-TRANSLATE-2** | A predicate withheld from a field-aware query surfaces in `notes` — a partial translation must announce that it is partial, never read as full coverage. | `detection_translate._translate` | `test_r10_semantic_gates.py::TestFieldAwareNotesSurfaceWithheldPredicates` |
| **INV-TRANSLATE-3** | Faithful modifiers (`contains`/`startswith`/`endswith`/plain) are unaffected by the withholding, and EQL plain equality stays case-insensitive (`cmd.exe` matches `CMD.EXE`). The fix must not over-withhold. | `detection_translate._translate` | `test_r10_semantic_gates.py::TestFaithfulTranslationsStillWork` |

## INV-COVERAGE — a coverage number reflects capability, not intent

| ID | Invariant | Owner | Enforced by |
|---|---|---|---|
| **INV-COVERAGE-1** | A rule that can NEVER FIRE (no `detection` block, no `condition`, or a `condition` naming an undefined selection) contributes NO coverage, and is reported in `non_actionable_rules` with the technique it falsely claimed. An ATT&CK tag is a statement of INTENT; only a rule that can fire is CAPABILITY, and counting the former as the latter turns the matrix green over a real blind spot. Valid condition grammar (`and not`, `1 of selection_*`, `all of them`) is never falsely excluded. | `detection_coverage._actionability_defect` | `test_r11_semantic_gates.py::TestNonActionableRulesDoNotCountAsCoverage` |
| **INV-COVERAGE-2** | The audit health score penalises a non-actionable rule MORE than an untagged one. An untagged rule under-reports its own coverage (conservative); a non-actionable rule over-reports it (hides a gap). | `detection_audit._health_score` | `test_r11_semantic_gates.py::TestAuditPenalisesNonActionableRules` |

## INV-MATCH — the matcher agrees with Sigma semantics

A wrong verdict here is not just a wrong boolean: `longrunning/bas-runner` reads
this matcher to decide whether a technique is detected, so an under-match publishes
a FALSE BLIND SPOT — the team is sent to build coverage it already has, and the
noise hides the real gaps.

| ID | Invariant | Owner | Enforced by |
|---|---|---|---|
| **INV-MATCH-1** | Sigma value WILDCARDS are honoured: `*` matches any run, `?` exactly one, composed with `contains`/`startswith`/`endswith` rather than overriding them. Only `\*`, `\?` and `\\` are escapes (so Windows paths survive), and an escaped wildcard matches the literal character — including on the non-wildcard path, which is the spelling that exists for exactly that purpose. | `sigma_match._has_wildcard` / `_wildcard_match` / `_unescape_sigma` | `test_r11_semantic_gates.py::TestSigmaWildcardsAreHonoured` |
| **INV-MATCH-2** | Field names resolve case-insensitively (an exact hit always wins), because a rule author's field reference routinely differs in case from the shipped log schema. Two event keys differing only by case are AMBIGUOUS: the key is refused with a caveat rather than guessed, since either choice could flip the verdict. | `sigma_match._resolve_field` | `test_r11_semantic_gates.py::TestFieldNamesAreCaseInsensitive` |
| **INV-MATCH-3** | `detection_dedup` reports a duplicate only on a PROVEN match-set equality, never on text similarity — a false duplicate gets a real rule deleted. A stricter rule is a subsumption, not a duplicate; a different logsource is never a duplicate; a non-provable rule lands in `not_analyzed` rather than counting as "checked, no duplicates". | `detection_dedup._predicate_implies` / `_subset_of` | `test_r11_semantic_gates.py::TestDedupRemainsAMatchSetProof` |

## INV-STREAM — the InvokeHarness stream parser protects the resume contract

| ID | Invariant | Owner | Enforced by |
|---|---|---|---|
| **INV-STREAM-1** | A repeated `toolUseId` in a stream is collapsed to ONE pending entry (first wins). Two entries would make the resume emit two `toolResult`s for one id, which the Bedrock protocol rejects — a corrupted session. Distinct parallel ids are all kept. | `core._consume_stream` | `test_r10_semantic_gates.py::TestStreamDedupesToolUseId` |

## INV-EXPORT — the exported skeleton does not quietly drop a safety gate

| ID | Invariant | Owner | Enforced by |
|---|---|---|---|
| **INV-EXPORT-1** | A `request_*_approval` HITL gate is exported as a clearly-marked SAFETY GATE, distinct from ordinary tools, and the builder emits a warning when one is present. Listing it among business tools invites an adopter wiring `tools=[...]` to drop it — shipping an agent that acts without the approval the harness required. The generated module always parses. | `exporter.export_harness_to_strands` | `test_r10_semantic_gates.py::TestExporterFlagsHitlGatesAsGuardrails` |

---

## INV-DOC — the docs cannot drift

| ID | Invariant | Owner | Enforced by |
|---|---|---|---|
| **INV-DOC-1** | Every public export carries a docstring, and the public surface never silently regresses. | `sentinel_harness/__init__.py` | `test_docs_drift.py` |
| **INV-DOC-2** | Counts quoted in the docs (tests, tools, evidence, scenarios) match reality, and never contradict each other between files. | docs + `tests/` | `test_docs_drift.py::test_quoted_counts_match_reality` |
| **INV-DOC-3** | Every test named in this file exists. | this file | `test_invariants_doc.py` |
