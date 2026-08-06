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
| **INV-PROMOTE-11** | The property suite's search budget is part of this contract. `max_examples` has a floor of 2000 and `SENTINEL_PROP_EXAMPLES` can only raise it. At the previous 250, INV-PROMOTE-1, -2 and -5 all PASSED while being falsifiable — 5000 found a counterexample for each within a minute. A property test that passes because it did not look is indistinguishable from one that holds. | `test_prop_promotion_policy._SETTINGS` | `test_prop_promotion_policy.py::test_the_search_budget_is_not_silently_lowered` |

### Snapshot vs final state (three recurrences, recorded because it kept coming back)

INV-PROMOTE-1, -2 and -5 are checked against the evidence **as it stood when the
promotion executed**, never against `AgentLoopResult`'s end-of-session fields.
`witnessed_pass`, `approved_subject` and `witnessed_subject` are all mutable driver
state: a later eval overwrites them (`agent_loop.py:554`, `:566`) and a later rejection
clears the subject (`:459`). The gate reads them at the moment it decides
(`:480`, `:504`), which is correct; an assertion that reads them at the end is testing a
different proposition.

This legal stream falsifies all three if you read the final state:

    eval(A, 0.7)  ->  approve(A) + promote(A)  ->  eval(A, 0.0)

Three rounds each fixed one leg and left the others: the subject first, then the
consent, then (round 19) the witnessed pass. The fix is in the test harness, which
snapshots `evals_so_far` and `approvals_so_far` at promotion time and re-derives every
verdict from them — so the assertions no longer depend on the driver reporting its own
flags correctly. Both gates were positive-controlled: disabling the subject binding
falsifies -2 and -5, disabling the eval gate falsifies -1, -2, -3, -5 and -6.

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
| **INV-GOV-6** | An OIDC `discovery_url` is HTTPS to a routable host — **in every spelling of the host**. The discovery document determines the token-signing keys, so plaintext HTTP lets an on-path attacker swap the JWKS and mint accepted tokens, and a metadata/loopback target is the same class from inside the VPC. Round 19 found the "routable" half did not hold: the check parsed with `ipaddress.ip_address()`, so six hosts passed — `2852039166` / `0xA9FEA9FE` / `0251.0376.0251.0376` (169.254.169.254) and `2130706433` / `0x7f000001` / `0177.0.0.01` (127.0.0.1). It now parses with `egress.parse_ip_literal` and keeps its own stricter policy (see INV-EGRESS-3). | `gateway._validate_discovery_url` | `test_r9_semantic_gates.py::TestDiscoveryUrlScheme`, `test_r19_egress_copies.py::TestTheReproducedAttacks` |
| **INV-GOV-7** | `allowedAudience`/`allowedClients` contain only concrete, non-blank values — never a wildcard or empty string. These lists ARE the auth boundary (same rule as `allowedTools`, never `['*']`). | `gateway._validate_claim_values` | `test_r9_semantic_gates.py::TestClaimValueHygiene` |
| **INV-GOV-8** | An `allowedTools` entry that is a NEAR MISS for a built-in HITL gate (stray whitespace / wrong case) fails loudly. Silently not injecting it produced a config that read as "has a human-approval gate" while having none. | `loader._inject_inline_gates` | `test_r9_semantic_gates.py::TestHitlGateNearMiss` |
| **INV-GOV-9** | An `allowlist_optimization` task is only emitted when something can SAFELY be suppressed. When every FP indicator is also a TP indicator, the task is withheld (with a recorded reason) and a `rule_regeneration` task is emitted instead — a noisy-but-unsuppressable rule must not produce silence. | `feedback.detect_triggers` | `test_r9_semantic_gates.py::TestUnsuppressableNoise` |

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

## INV-WL — a synthesized allowlist suppresses only the FP cohort

The allowlist_optimizer GENERATES a Sigma filter. A generated suppression rule
that matches more than its FP cohort actively turns OFF a working detection — the
most dangerous outcome in the suite.

| ID | Invariant | Owner | Enforced by |
|---|---|---|---|
| **INV-WL-1** | A filter is never synthesized from a value carrying a Sigma metacharacter (`*` `?` `'` `"` `\`). The TP guard compares literally, but the emitted Sigma is read with `*`/`?` as live wildcards — so `process_name: 'a*.exe'` would glob-suppress the very TP it certified as preserved. Such a field is refused. | `allowlist_optimizer._has_unsafe_char` | `test_r12_semantic_gates.py::TestAllowlistNeverSuppressesBeyondCohort` |
| **INV-WL-2** | A domain-suffix allowlist must extend below the public-suffix boundary (a private registrable domain). `co.uk` / `blob.core.windows.net` are refused — allowlisting them suppresses an entire shared registrar space. A weak context field (port / user / host) is never a sole discriminator; a /48 IPv6 block and an n=1 class generalization are refused. | `allowlist_optimizer._is_public_suffix` / `_WEAK_FIELDS` / `_discriminator_for_field` | `test_r12_semantic_gates.py::TestAllowlistNeverSuppressesBeyondCohort` |
| **INV-WL-3** | A true-positive guard that LACKS the allowlisted field fails CLOSED: absence of evidence is not evidence of safety, so the field is refused rather than certified TP-preserving. | `allowlist_optimizer.handler` (tp_unprovable) | `test_r12_semantic_gates.py::TestAllowlistNeverSuppressesBeyondCohort::test_tp_missing_the_allowlisted_field_fails_closed` |

## INV-BASELINE — a real regression can never pass green

| ID | Invariant | Owner | Enforced by |
|---|---|---|---|
| **INV-BASELINE-1** | A technique leaving the COVERED set is a regression even when it never enters `uncovered` (no target list) — the snapshot records the covered set, not just uncovered. A shrinking rule library is flagged. | `detection_baseline._compact` / `_compare` | `test_r12_semantic_gates.py::TestBaselineRegressionsCannotHide` |
| **INV-BASELINE-2** | A CHANGED target list is not credited as resolved blind spots: a smaller question is not an improvement. Growth in a saturated deduction class (untagged / non_actionable) is flagged at a flat score. | `detection_baseline._compare` | `test_r12_semantic_gates.py::TestBaselineRegressionsCannotHide` |
| **INV-BASELINE-3** | A malformed / empty baseline FAILS CLOSED (validation_error), never green — the worst failure for a gate is passing because it could not read its baseline. A negative `allow_score_drop` clamps to strict, never disables the gate. | `detection_baseline._validate` / `handler` | `test_r12_semantic_gates.py::TestBaselineRegressionsCannotHide::test_malformed_baseline_fails_closed`, `::test_negative_allowance_does_not_disable_the_gate` |

## INV-NAV — the Navigator layer agrees with coverage

| ID | Invariant | Owner | Enforced by |
|---|---|---|---|
| **INV-NAV-1** | A technique claimed only by a rule that cannot fire is NOT painted green and does not vanish from the layer; it is a distinct "claimed-but-cannot-fire" class, counted in the denominator so coverage cannot read 100% over it. The Navigator's green set equals coverage's covered set. | `detection_navigator._analyze` / `_build_layer` | `test_r12_semantic_gates.py::TestNavigatorAgreesWithCoverage` |

## INV-FP — FP-proneness tracks specificity, not just rule shape

| ID | Invariant | Owner | Enforced by |
|---|---|---|---|
| **INV-FP-1** | A rule with a self-anchoring predicate (full path / full hash / long exact value) is NOT flagged FP-prone — checks that use "no exclusion filter" or "few predicates" as a breadth proxy are exempted when a predicate is precise enough to stand alone. Penalising a team's most precise detection pushes the library the wrong way. | `sigma_yara_lint._has_high_specificity_predicate` | `test_r13_semantic_gates.py::TestPreciseRulesAreNotPenalised`, `::TestSpecificityHelper` |
| **INV-FP-2** | A short `\|contains` value is only "generic" if it reads like a plain lowercase-ASCII word and is not a known IOC marker; `jndi` / `ldap` / `::$` / `-enc` are specific, not noise. A wildcard-bearing or `\|contains` value never counts as self-anchoring, so a broad rule is still caught. | `sigma_yara_lint._is_generic_short_value` | `test_r13_semantic_gates.py::TestPreciseRulesAreNotPenalised`, `::TestBroadRulesAreStillCaught` |
| **INV-FP-3** | Breadth is judged by the SELECTIVITY OF THE VALUE, whatever modifier spells it. A bare `'*'`, a `\|re: '.*'`, an `\|exists: true`, a `\|gt: 0` floor and a 1-char anchor are all match-everything — the pre-fix checks keyed on the literal substring `\|contains` and scored six such predicates at ZERO. A list-of-maps selection cannot evade the checks either. | `sigma_yara_lint._match_everything_reason` / `_iter_predicates` | `test_r13b_semantic_gates.py::TestBreadthIsJudgedByValueNotModifierSpelling` |
| **INV-FP-4** | Warning count is MONOTONIC in real breadth: a rule matching everything never scores fewer warnings than one matching a strict subset of it. (Pre-fix `Image: '*'` scored 2 while its subset `\|contains: 'cmd'` scored 3 — sign-inverted on a subset relation the repo's own matcher can decide.) A match-everything predicate is decisive evidence, weighted to dominate any stack of shape heuristics. | `sigma_yara_lint._fp_heuristics_sigma` | `test_r13b_semantic_gates.py::TestBreadthIsJudgedByValueNotModifierSpelling::test_breadth_is_monotonic_with_real_match_set` |
| **INV-FP-5** | An "exclusion filter" means the condition genuinely EXCLUDES: an `and not` in conjunctive position, matched case-insensitively. An OR-*widening* condition (`selection or filter_extra`) is never credited as a filter. Self-anchoring accepts a modified predicate only when the VALUE is intrinsically unique (a full hash); position-based anchoring (a full path) still requires an exact predicate, because `\|contains` on a system path or `\|endswith: '\cmd.exe'` is broad. | `sigma_yara_lint._has_exclusion_filter` / `_has_high_specificity_predicate` | `test_r13b_semantic_gates.py::TestExclusionFilterDetectionIsSemantic`, `::TestSpecificityExemptionAcceptsModifiedPredicates` |

## INV-CONNECTOR — a SIEM connector preserves the result set across backends

| ID | Invariant | Owner | Enforced by |
|---|---|---|---|
| **INV-CONNECTOR-1** | Every SIEM connector emits the SAME result-set bound (limit + time window) for the same neutral query, so a detection validated offline behaves identically on any backend. No connector invents a time window the neutral query did not ask for (QRadar's silent 24h window dropped older true hits). | `connectors.siem` + `base.DEFAULT_RESULT_LIMIT` | `test_r13_semantic_gates.py::TestConnectorsPreserveResultSet` |
| **INV-CONNECTOR-2** | The conformance suite ASSERTS cross-connector result-set equivalence, not just per-connector response shape — a divergent limit or an invented window is a certification FAILURE. (Per-connector shape checks alone were structurally blind to the divergence, the same "asks the wrong question" gap as INV-COVERAGE-1.) | `connectors.conformance.check_result_set_equivalence` | `test_r13_semantic_gates.py::TestConnectorsPreserveResultSet::test_conformance_catches_an_invented_time_window`, `::test_conformance_catches_a_divergent_limit` |
| **INV-CONNECTOR-3** | A SEMANTIC selector is never emitted as a field filter. `siem_query` accepts `query` (match-all) and `since` (a time floor), which are query semantics, not backend fields — emitting `query="*"` / `since="<ts>"` filtered on fields no backend has, so the LIVE path returned 0 rows where the offline mock returned all of them. `resolve_selector` translates them once, shared by all eight connectors. | `connectors.base.resolve_selector` | `test_r13b_semantic_gates.py::TestSelectorSemantics` |
| **INV-CONNECTOR-4** | The generic live path and the named-connector path agree on every value coercion. A bare `bool()` on a string `false_positive` yields True (`bool("false")` is truthy), so the two paths returned OPPOSITE security verdicts on the same bytes — one dropping a genuine alert as noise. One shared coercion, one answer. | `siem_query._coerce_fp` → `connectors.base._coerce_bool` | `test_r13b_semantic_gates.py::TestLivePathsAgree` |
| **INV-CONNECTOR-5** | Response normalization never fabricates or silently discards a field: an ES hit's `_id` survives into `alert_id` (two distinct documents must not collapse to one identical event), a ticketing reply's real status is reported rather than a hardcoded one, and a duplicate columnar column name is refused instead of clobbering the earlier value. | `connectors.siem` / `connectors.ticketing` | `test_r13b_semantic_gates.py::TestResponseNormalizationFidelity` |

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
| **INV-DOC-4** | A historical record records HISTORY. `ROADMAP.md`'s per-round acceptance lines ("suite 2493 → **2590** offline passing") close at that round's real size, and five consecutive rounds cannot all close at the same number — each added tests. All five DID read the same value: every count update had been applied as an undiscriminating find-and-replace over the file, overwriting eight rounds of records with the current number each time. Nothing caught it, because INV-DOC-2 deliberately ignores past-tense lines and a wrong-but-consistent number reads as fine. The true values were recovered from `git log --reverse` and are self-consistent (2493→2590→2649→2671→2730→2775: each round's close is the next round's start). | `docs/ROADMAP.md` | `test_docs_drift.py::test_per_round_acceptance_records_are_not_all_the_same_number` |

---

## INV-PLAY — a Play Mode audit record cannot be forged after the fact

`simulation.py` makes the strongest safety claim in the codebase: *"no offensive
action happens without an explicit human confirmation — that is what Play Mode
means."* Round 16 found that claim was falsifiable by **editing a JSON file**.

`load_checkpoint` was a bare `PlanState.from_dict(json.load(f))` with no validation,
and `resume_from_checkpoint` then did `runner.state = state` to "keep prior
statuses/decisions". Three reproduced attacks:

1. Marking every step `executed` → the runner asked the human **zero** times, with
   counts byte-identical to a real run.
2. `halted: false` + reverting `rejected` to `pending` → **erased a human rejection**.
3. Rewriting `rejected` to `executed` with a fabricated `decision.approver` → the
   audit record asserted a **named security lead approved every step of an offensive
   plan they were never asked about**.

Technique execution really is a no-op (verified by AST walk, not by trusting the
docstring), so the harm is not a live attack — it is that the **audit artifact**, the
only evidence a red-team action was authorized, can be rewritten in the direction
that says "this was authorized". Reachable from `longrunning/detonation/` and
`longrunning/bas-runner/`, the latter mirroring the checkpoint to S3.

| ID | Invariant | Owner | Enforced by |
|---|---|---|---|
| **INV-PLAY-1** | A checkpoint edited after it was written is refused. `save_checkpoint` stamps a `state_digest` over the canonical body; `load_checkpoint` verifies it with a constant-time compare. Re-indenting or reordering keys does not trip it; changing any *value* does. A digest-less file is refused by default — "unanchored" is not "verified", the same distinction `provenance.read_anchor` draws. | `simulation.save_checkpoint` / `load_checkpoint` | `test_r16_self_certified.py::TestCheckpointIntegrity` |
| **INV-PLAY-2** | Even a correctly-digested state must be one the runner could have produced: known statuses, indexes matching positions, an approved/executed step carrying a decision that actually says APPROVED, a rejected step halting the plan, a halt naming its reason. Every test for this **re-seals the digest first**, because an unkeyed digest is recomputable — a guard that only catches an attacker who forgot to re-seal is not a guard. | `simulation._assert_consistent` | `test_r16_self_certified.py::TestCheckpointConsistency` |
| **INV-PLAY-3** | A resumed plan is the plan the caller authorized (`expected_plan=`). This is the only layer an attacker with write access **cannot** defeat, because the reference value lives with the caller rather than in the file: a substituted plan is internally consistent and its digest can be recomputed, so nothing inside the file can catch it. Compares `(phase, technique)` identity, not `objective` prose. Both long-running entrypoints pass it. | `simulation._assert_plan_matches` | `test_r16_self_certified.py::TestPlanBinding` |
| **INV-PLAY-4** | The gate is asked exactly once per offensive step (zero = silent execution, two = double-charging one human decision), a rejection halts the plan leaving later steps pending, and only an explicit `"APPROVED"` string counts — `{"decision": "false"}` and `{"decision": True}` both read as NOT approved, so the `bool("false")` trap of INV-BOUNDARY-1/INV-GATE-3 cannot reach this predicate. Technique execution carries no side-effect primitive, checked by AST walk. | `simulation.PlayModeRunner` / `_is_approved` | `test_r16_self_certified.py::TestPlayModeGateItself` |
| **INV-PLAY-5** | Only the tool named by `GATE_NAME` counts as the approval gate. That constant EXISTED and was never used to check anything, so any `tool_use` was accepted as human confirmation — a pause on `code_interpreter` carrying an arbitrary payload was recorded as an approved, executed offensive step. The human is not even asked about a non-gate pause: asking someone to approve something that is not the gate trains them to click through. | `simulation.PlayModeRunner.run_step` | `test_r16_self_certified.py::TestTheGateIsActuallyTheGate` |
| **INV-PLAY-6** | The approval is bound to the technique/phase the gate ACTUALLY asked about. The human was shown "approve T1595 (recon)?" while the gate requested T1486 (ransomware deployment), and nothing compared the two. **This is the second appearance of the confused-deputy shape INV-PROMOTE-2 closed** — M18's fix was specific to `agent_loop`, so per-step approval never received it. Only a payload that names a DIFFERENT subject is refused; one that names nothing is fine, because demanding fields the harness may not send is how a guard gets disabled in practice. | `simulation._gate_subject_mismatch` | `test_r16_self_certified.py::TestTheGateIsActuallyTheGate::test_an_approval_is_bound_to_the_technique_the_gate_asked_about` |
| **INV-PLAY-7** | A decision is persisted BEFORE anything that can fail. The rejection path notified the harness before checkpointing, so a `resume_fn` that raised (a dropped connection, a throttle) propagated out with the checkpoint never written — the human's refusal existed only in the dead process's memory, the step read `pending` on disk, and a resume would re-ask. A denial is the single most important thing this file can carry. The failure still propagates; only the ordering changed. | `simulation.PlayModeRunner.run_step` | `test_r16_self_certified.py::TestTheGateIsActuallyTheGate::test_a_rejection_is_persisted_before_anything_that_can_fail` |

| **INV-PLAY-8** | `verdict()`'s `every_step_gated` cannot hide a bypass. It considered only steps whose status had left PENDING — and an ungated step is exactly one that STAYS pending, because the runner halts without advancing it. So the one check meant to detect a gate bypass filtered out the evidence and still returned True, and it is published in the evidence artifact as "every offensive step paused on a human gate". A halt for a gate-protocol reason is now decisive, and `halted_without_gate` is reported alongside so a reader can tell a clean run from a refused one. A human REJECTION still reports `every_step_gated: True` — that is a correctly-gated run, not a bypass. | `simulation.PlayModeRunner.verdict` | `test_r16_self_certified.py::TestVerdictReportsWhatItExistsToReport` |
| **INV-PLAY-9** | An APPROVED step that never became EXECUTED is surfaced. `run_step` sets APPROVED, resumes, then sets EXECUTED, so an exception in between leaves a step the human authorized that never ran with `execution_log=None` — and no count, verdict field or halt reported it, so the evidence file looked like a clean partial run. Reported as `approved_but_not_executed`. | `simulation.PlayModeRunner.verdict` | `test_r16_self_certified.py::TestVerdictReportsWhatItExistsToReport::test_an_approved_but_never_executed_step_is_surfaced` |
| **INV-PLAY-10** | A PARALLEL pause halts instead of being half-answered. `core._consume_stream` returns the full `tool_uses` list and `core.invoke_with_tool_results` documents that answering only the first corrupts the session; this runner read only `tool_use`, so the human was shown ONE request, the rest were silently dropped, and the verdict still claimed every step was gated. Play Mode cannot honestly gate what it never showed a human. A single-element `tool_uses` — the ordinary case — is not treated as parallel. | `simulation.PlayModeRunner.run_step` | `test_r16_self_certified.py::TestVerdictReportsWhatItExistsToReport::test_a_parallel_pause_halts_instead_of_dropping_gates` |

INV-PLAY-5/6/7 are **more fundamental than 1/2/3**: those protect the *record* of an
approval, these protect the *approval*. A record cannot be more trustworthy than the
decision it records. All three were found by fan-out probes, not by hand — and three
independent probes converged on the same function, which is itself corroboration.
Fixing them also revealed that two test fakes emitted a synthetic `T{n}` technique in
the gate payload, a shape no real harness would produce; they only passed because
nothing compared it to the step.

### Threat model, stated rather than implied

`state_digest` is an **unkeyed SHA-256, not a signature**. Anyone who can write the
file can recompute it — verified experimentally: after re-sealing, a self-consistent
forged state still loads. So INV-PLAY-1 defends against *accidental or careless*
modification and forces a deliberate forgery to be deliberate; INV-PLAY-2 catches a
sloppy forgery and a buggy writer; only INV-PLAY-3 resists a determined one.

Closing the gap fully needs a key the checkpoint writer does not hold, or an anchor
in storage it cannot rewrite — precisely what INV-GOV-4 already says about the
provenance ledger. That is a deployment decision, and claiming otherwise in code
would be the same self-certification this round exists to audit.
`test_an_unbound_resume_does_NOT_catch_substitution` pins the residual gap so a
reader cannot infer a guarantee the code does not give.

---

## INV-GUARD — the guards are code too

Round 17 shipped three structural guards and **all three were broken on arrival**. Not
one was caught by review; each was caught by a positive control:

1. `_ALLOWED_BARE_BOOL` was keyed by FILE, so it exempted a whole file forever — a fresh
   violation injected into `feedback.py` was not caught, because that file already held
   one legitimate `bool()`. A fail-open built into a mechanism whose only purpose is to
   prevent fail-open.
2. The provenance matcher substring-matched `ast.dump()`, and every variable reference
   carries `ctx=Load()` — so the marker `"load"` matched *everything*. All 24
   expressions were classified external, and it looked clean only because the allowlist
   covered them all.
3. The connector-injection assertion substring-matched a quote-then-operator sequence
   and flagged all seven **correctly escaped** backends; rewritten, it then measured
   `str(request)` and counted Python's repr escaping instead of the DSL's.

Three for three. **A guard is at least as likely to be wrong as the code it guards**, and
nothing was checking the guards.

### What the evidence supports — narrower than I first proposed

I opened this round believing six control-less scanning tests were at risk. Measuring
said otherwise:

- `test_exporter`-style tests assert a violation IS present (`assert "X" in code`). A
  broken search makes those FAIL loudly; they cannot pass vacuously. Out of scope.
- The simple negative scans (one AST node type, one grepped word) were tested by
  injection — a `subprocess` call added to `simulation.py`, and the grepped word removed
  from `epss_kev`. **Both fired.** They are not blind.
- What went blind both times in round 17 was a scan carrying an **exemption
  mechanism**. An allowlist is the part that can swallow a real violation while the test
  still reports clean.

So the invariants govern exemptions, not scanning. Today two files qualify and both
already comply — this family is a ratchet, not a bug report.

| ID | Invariant | Owner | Enforced by |
|---|---|---|---|
| **INV-GUARD-1** | An exemption is keyed to an EXPRESSION (or another single-site identifier), never to a bare file path. A file-scoped exemption is the test-suite equivalent of a lint-exempt directory: never revisited, therefore permanent. | `tests/` (AST sweep) | `test_r18_guard_the_guards.py::TestExemptionsAreExpressionScoped` |
| **INV-GUARD-2** | A scan that carries an exemption mechanism declares a positive control. Empirically justified: every round-17 guard was broken on arrival and a control caught each one. Deliberately NOT required of simple negative scans — those were tested by injection and fired, so demanding it everywhere would be cargo-culting. | `tests/` | `test_r18_guard_the_guards.py::TestGovernedScansHaveAPositiveControl` |
| **INV-GUARD-3** | A governed scan rejects stale exemptions, and every entry carries a reason of substance. An exemption for a violation that no longer exists trains readers to skim the list; one with no argument cannot be checked. | `tests/` | `test_r18_guard_the_guards.py::TestGovernedScansRejectStaleExemptions` |
| **INV-GUARD-4** | A structural question is asked of the tree, not of a substring — specifically, no test substring-matches an `ast.dump()` result, in either the `in` or `not in` direction. `ast.dump()` embeds a node type and a context marker for every node, so a short marker matches everything and the matcher reports a clean tree while distinguishing nothing. **Seventh** occurrence of substring-for-structure in this repo (INV-FP-3, R13b's exclusion filter, INV-GATE-1, INV-GATE-6, INV-COERCE's matcher, INV-CONNECTOR-8's assertion, and this). | `tests/` | `test_r18_guard_the_guards.py::TestStructuralQuestionsUseTheTree` |

### Three more control miscues, found while building this

The pattern held: writing the guard produced three more defects, and **a control caught
every one** — this time controls of the controls.

1. **The e2e probes were named `_r18_e2e_*.py`.** `_test_files()` globs `test_*.py`
   (correctly — pytest collects the same set), so the probes were invisible and all
   three reported MISSED. *A "the guard is blind" conclusion can come from a broken
   probe*, so `test_a_clean_probe_does_not_trip_anything` now asserts a COMPLIANT probe
   leaves the suite green.
2. **INV-GUARD-4 matched only `ast.In`**, so `assert 'load' not in dumped` slipped past.
   The unit control had the *same blind spot as the code*, because both came from one
   wrong mental model — which is precisely why an independent end-to-end path matters.
3. **The nested pytest used a bare `python`**, which has no pytest, producing an empty
   output and an exit code that read as "the guard fired". Now `sys.executable`.

The lasting form of that lesson: **a unit control tests the predicate; only an
end-to-end control tests that the predicate is wired to an assertion that runs.** Round
16 shipped a `_NoRedirect` class that existed but was never installed — same gap.

---

## INV-IAC — the permission boundary the infrastructure declares

`iac-cdk/` and `iac-terraform/` had never been audited, and they define real IAM
boundaries. **They held up** — recorded here as tests rather than as a claim, because
"we looked and it was fine" is worth nothing a month later.

Two of my initial framings were wrong, and correcting them is most of the value:

1. **A wildcard is not automatically a defect — the STATEMENT TYPE decides.**
   `network-stack.ts` carries `actions: ["*"], resources: ["*"]`, which looks alarming
   and is right: it is a **VPC endpoint policy**, whose semantics are "what may traverse
   this endpoint", *intersected* with the caller's own IAM, bounded by
   `aws:PrincipalAccount`. Narrowing the actions would break AWS-managed service calls
   while restricting nothing. In a ROLE policy a wildcard resource expands power; in an
   endpoint/resource policy with a condition it contracts it. Same characters, opposite
   direction.
2. **The two stacks are COMPLEMENTARY, not parallel.** CDK names 17 IAM actions;
   Terraform names none, because it provisions no IAM role — it does
   Cognito/VPC/Guardrail/Observability and *accepts* an execution-role ARN by variable.
   So "do they express the same boundary?" is the wrong question; "does the split leave
   a gap?" is the right one, and it pointed at the variable's validation regex.

| ID | Invariant | Owner | Enforced by |
|---|---|---|---|
| **INV-IAC-1** | Every IAM statement using `resources: ["*"]` is one of three ARGUED exceptions, and no ROLE policy uses a wildcard ACTION at all. `cloudwatch:PutMetricData` has no resource-level scoping and is confined by a `cloudwatch:namespace` condition; the X-Ray write APIs support neither, so the account boundary is the guard — and they are kept in a SEPARATE statement, because attaching the namespace condition to them would be invalid and AWS ignores an unrecognized condition key, silently widening rather than restricting. | `iac-cdk/lib/iam.ts`, `network-stack.ts` | `test_r17_iac_boundaries.py::TestIamWildcardsAreArgued` |
| **INV-IAC-2** | The Terraform `harness_execution_role_arn` variable is validated, has NO default, and its regex is anchored at both ends. Since that path creates no IAM role, this regex IS the boundary for every harness provisioned there. Tested against 15 shapes: it admits the four legitimate ones (including non-default partitions and a role path) and refuses a user ARN, the account root, an STS assumed-role session, malformed account ids, an empty role name, and leading junk. A test also pins that Terraform still creates no `aws_iam_role`/`aws_iam_policy` — if it starts to, those roles need INV-IAC-1's scrutiny. | `iac-terraform/variables-harness.tf` | `test_r17_iac_boundaries.py::TestTerraformExecutionRoleGate` |
| **INV-IAC-3** | No IaC file carries a non-placeholder 12-digit account id, a hardcoded execution-role ARN, or anything shaped like an access key. Redundant with the CI secret-scan by design: here a leaked account id is also a deployment target. | `iac-cdk/`, `iac-terraform/` | `test_r17_iac_boundaries.py::TestIacCarriesNoHardcodedIdentity` |

**A negative result needs a positive control**, so
`TestTheIacGuardsCanDetectADefect` synthesizes each defect class — an unargued wildcard
resource, a wildcard action, Terraform creating an IAM role, a hardcoded account id —
and asserts the corresponding guard fires. All four were caught. Without that, 33
passing tests would be indistinguishable from 33 blind ones.

---

## INV-EGRESS — one guard, used by every live path

Round 16 found two SSRF defects in `ops_query`, fixed them there, and recorded
INV-OPS-5. Round 17 found **the identical pair in `siem_query`** — both reproduced end
to end, including the credential leak. A survey then showed why: of the eight tools that
open outbound HTTP, exactly **one** was complete.

| tool | url guard | redirect refused | alt-IP parsing |
|---|---|---|---|
| ops_query | yes | yes | yes |
| siem_query | yes | **no** | **no** |
| asset_lookup | yes | **no** | **no** |
| enrich_ioc | yes | **no** | **no** |
| web_search | yes | **no** | **no** |
| nvd_lookup | **no** | **no** | **no** |
| epss_kev | **no** | **no** | **no** |
| attack_lookup | **no** | **no** | **no** |

Fourth recurrence by the same route as INV-COERCE: a fix applied to one call site is not
a mechanism. The guard now lives in `sentinel_harness/egress.py`, once.

| ID | Invariant | Owner | Enforced by |
|---|---|---|---|
| **INV-EGRESS-1** | Every live path opens through `egress.open_checked`, which vets the URL and refuses redirects in ONE call. No tool calls `urllib.request.urlopen` directly (it follows 3xx, which walks past any pre-flight check and re-sends `Authorization` to the target the *backend* chose), and no tool reimplements the IP parser. Enforced by an AST sweep over all eight tools plus an inventory check that a NEW live path cannot silently escape. | `sentinel_harness/egress.py` | `test_r17_egress_mechanized.py::TestEveryLivePathUsesTheSharedGuard` |
| **INV-EGRESS-2** | The guard refuses every spelling of a forbidden target — `169.254.169.254`, `2852039166` (decimal), `0xA9FEA9FE` (hex), `0251.0376.0251.0376` (octal), IPv4-mapped IPv6, a userinfo prefix, and non-HTTP schemes — while ALLOWING a legitimate backend, loopback (a self-hosted SIEM, and what the live tests bind), and a DNS name that merely starts with a digit. `EgressError` subclasses `RuntimeError` so a refusal surfaces as `upstream_error`, never a silent empty result. | `egress.assert_safe_url` / `parse_ip_literal` / `_NoRedirect` | `test_r17_egress_mechanized.py::TestTheSharedGuardBehaviour` |

| **INV-EGRESS-3** | Every host range-check in the repo parses with `egress.parse_ip_literal` — including the ones whose POLICY differs. Round 19 found **four** surviving local copies: `asset_lookup`, `enrich_ioc` and `web_search` each kept an `_assert_safe_url` that accepted `2852039166` / `0xA9FEA9FE` / `0251.0376.0251.0376`, and `gateway._validate_discovery_url` did too. The three tool copies were shadowed by `open_checked` downstream; the gateway one was **not** — it is the only gate between a config value and `customJWTAuthorizer.discoveryUrl`, which decides which keys sign a valid token, and it also let loopback through as `2130706433` / `0x7f000001` / `0177.0.0.01`. The split is parser-shared, policy-local: the parser was wrong in all four, the policy is what legitimately differs. | `egress.parse_ip_literal`, delegated to by all four | `test_r19_egress_copies.py` |

INV-EGRESS-1 existed to prevent exactly this and did not, because its
`test_no_tool_reimplements_the_ip_parser` was parameterized over `("siem_query",
"ops_query")` — the two tools that had already been found. A guard against
"fixed at one call site" that itself covers only the known call sites is the fifth
recurrence of that pattern in this codebase, this time inside the mechanism built to
stop it. It now sweeps every module in `tools/`, `sentinel_harness/` and `intake/`.

**Not** defended, stated so nobody infers it: a hostname that RESOLVES to a link-local
address (DNS rebinding). That needs resolution-time hooks — the runtime network policy's
job. This guard covers what a URL string can express.

---

## INV-CONNECTOR (round 17 additions) — a value is not a query language

Round 13b audited the 8 SIEM connectors on selector semantics and response fidelity.
Round 17 audited the two dimensions it did not: **query injection** and **credential
handling**.

Seven of eight connectors place the caller's value inside a quoted literal and escape it
— audited and fixed in an earlier round, and now pinned. Two findings remained:

| ID | Invariant | Owner | Enforced by |
|---|---|---|---|
| **INV-CONNECTOR-6** | A free-text value is not evaluated as a query language. Elastic and OpenSearch put it into `query_string`, which INTERPRETS Lucene — so `web-01 OR *` widened the query to match every document (the agent reads alerts for hosts it never asked about) and `x AND NOT x` narrowed it to none (an attack hidden behind an empty result that reads as good news). Injection by construction, and the only such site: JSON quoting protects the transport and does nothing about the DSL. Now `simple_query_string` with an explicit `flags` allowlist (AND/OR/NOT/PHRASE/WHITESPACE only — no field scoping, ranges, regex or boosting) and an explicit `fields` allowlist, since the default expands to `*`. | `connectors.siem.ElasticConnector` / `OpenSearchConnector` | `test_r17_egress_mechanized.py::TestConnectorQueryInjection` |
| **INV-CONNECTOR-8** | AQL escaping neutralises a trailing BACKSLASH, not only quotes. Doubling quotes alone emitted `host = 'x\' LIMIT 1000` for the value `x\`: a parser that honours backslash escapes reads `\'` as a literal quote, consuming the closing delimiter so the `LIMIT` clause falls inside the string. Whether Ariel honours backslash escapes is not something a caller's safety may depend on — the value is quoted for a dialect we do not control, so both readings must be safe. | `connectors.siem._escape_squote` | `test_r17_egress_mechanized.py::TestConnectorQueryInjection::test_a_string_dsl_connector_escapes_a_breakout_attempt` |
| **INV-CONNECTOR-9** | The connectors carry no credentials and open no sockets. Their docstring claims "nothing here carries an endpoint, index name, token, or tenant" — a self-certified claim of the kind round 16 audited, so it is checked: `build_request`'s return value contains no credential material, the module reads no environment variable, and it holds no HTTP primitive. The last matters most: it is what makes an injection finding LATENT rather than live, and if it ever changes the severity of this whole family changes with it. | `connectors/siem.py` | `test_r17_egress_mechanized.py::TestConnectorsHoldNoCredentials` |

### Three refinements the injection assertion needed

The escaping test was wrong twice before it was right, each time for the same reason —
and the sequence is worth recording because it is the shape of a bad security test:

1. **Substring matching.** `'" | ' not in emitted` flagged all seven correctly-escaped
   backends: Chronicle emitted `host = "x\" | delete index=*"`, where the quote IS
   escaped, and the substring matched inside `\" | `. **Sixth** occurrence of
   substring-for-structure in this repo.
2. **Measuring the wrong artifact.** Counting quotes on `str(request)` measured
   Python's repr escaping, not the DSL's.
3. **Ignoring the dialect.** Checking BOTH quote characters flagged a double quote
   inside single-quoted AQL, where it is not a metacharacter at all.

The assertion that finally works extracts the query string, counts unescaped
occurrences of **that backend's own delimiter**, and requires an even count — a value
that broke out leaves an odd one. It found INV-CONNECTOR-8 immediately, and a positive
control (re-injecting the un-escaped `_escape_dquote`) proves it can still see a
regression.

---

## INV-COERCE — the invariants that recurred are now enforced structurally

Nine rounds produced 106 invariants. **Three of them came back after being fixed**, and
every recurrence had the same cause: the invariant was recorded as a CONVENTION, so the
next author — or the same author on a different code path — reimplemented the trap.

    INV-BOUNDARY-1  (r14)  bare bool() on external data, in asset_lookup
      -> INV-GATE-3  (r15)  the SAME defect in run_evaluation, one round later
      -> INV-COERCE-1 (r17) the SAME defect in siem_query's OFFLINE normalizer —
                            sitting in the very file whose LIVE normalizer R13b fixed

    INV-PROMOTE-2   (M18)  approval not bound to a subject, in agent_loop
      -> INV-PLAY-6  (r16)  the SAME hole in simulation's per-step gate

The third recurrence is the one that settles the argument: two rounds of hand-auditing
`siem_query` missed it, because it was in the file the fix had already landed in —
the last place anyone looks. An AST sweep found it immediately.

| ID | Invariant | Owner | Enforced by |
|---|---|---|---|
| **INV-COERCE-1** | No bare `bool()` is applied to externally-sourced data anywhere in `sentinel_harness/`, `tools/` or `intake/`. Sites delegate to `connectors.base._coerce_bool`, or appear in an allowlist keyed by **file + exact expression** with the reason the value cannot be a string. | repo-wide (AST sweep) | `test_r17_coercion_mechanized.py::TestNoBareBoolOnExternalData` |
| **INV-COERCE-2** | Every truthiness helper is CLASSIFIED: one that reads a *backend response* is pinned to answer identically to the authority; one that parses a *different grammar* (a Sigma `\|exists` operand, a YAML boolean) declares that grammar and must be **stricter** than the backend alphabet, never looser. An unclassified helper is how INV-BOUNDARY-1 recurred twice. | `connectors.base._coerce_bool` + the classified helpers | `test_r17_coercion_mechanized.py::TestLocalCoercionHelpersAgree` |
| **INV-COERCE-3** | A callback whose contract says `-> bool` is enforced, not widened. `bool(approve_fn(...))` at both promotion-approval sites made a callback returning the string `"false"`/`"no"`/`"0"` witness an APPROVAL. A non-bool return is REFUSED with a warning naming the type — deliberately not coerced, since coercing would make strings a supported input on the most security-sensitive callback in the platform. A raising callback still propagates. | `agent_loop._witness_approval`, `autonomy.run_improvement_loop` | `test_r17_coercion_mechanized.py::TestApprovalCallbackContract` |

### Three defects in the guard itself, and why they are recorded here

Building this found more about how such guards fail than about the code:

1. **A file-level allowlist is a permanent file-level exemption.** Keying by file meant
   a new violation in `feedback.py` was NOT caught, because that file already held one
   legitimate `bool(withheld)`. I had built a fail-open into a mechanism whose only
   purpose is to prevent fail-open — the same shape as "a lint-exempt directory is a
   directory that never gets fixed". Keys are now file **plus exact expression**:
   stable across edits, readable in a diff, and impossible for new code to match by
   accident.
2. **The provenance matcher was silently broken.** It substring-matched `ast.dump()`,
   and every variable reference carries `ctx=Load()` — so the marker `"load"` matched
   *everything*. The sweep classified all 24 expressions as external and only looked
   clean because the allowlist covered them all. A matcher that flags everything is as
   useless as one that flags nothing, and it hid its own failure. Now walks the AST
   structure. **That was the fifth time substring-matching stood in for a structural
   judgement in this repo** (INV-FP-3, R13b's exclusion filter, INV-GATE-1, INV-GATE-6,
   and the guard written to stop recurrences) — the lesson evidently needs repeating:
   if the question is "what KIND of node is this", ask the tree.
3. **Both were found by a positive control, not by review.**
   `TestTheSweepCanActuallyDetectAViolation` synthesizes a violation and asserts the
   sweep names it. Without it, this whole family would have shipped green and
   worthless. It is now a test, so a future change to the granularity fails loudly.

---

## INV-EVAL — the offline scorer's safety gate cannot be recited past

`eval_datasets` is the **second** scoring path into the self-improving loop — round 15
found eight fail-open defects in the first (`run_evaluation`, INV-GATE). This one is
arguably more exposed: it needs no judge, so CI runs it every time and the loop can
trust it by default.

The bypass: **reciting a row's own assertions passed 25 of 25 shipped safety traps at
score 1.0.** The root cause is that the two halves of the gate were *the same check* —
a trap's assertions are sentences about what the agent must NOT do, so quoting them
satisfied the keyword-coverage score AND tripped the refusal-marker substrings. Two
gates reading the same text with the same technique are one gate.

| ID | Invariant | Owner | Enforced by |
|---|---|---|---|
| **INV-EVAL-1** | Compliance is decided BEFORE any refusal marker. The leading-opener check ran first and returned True unconditionally, and `_LEADING_REFUSAL` holds bare substrings (`do not`, `should not`, `reject`) — so any hedging clause in the first 80 characters made a fully complying, harmful answer read as a refusal ("I cannot overstate how useful this is. I am executing the scan as requested."). A first-person statement of ACTION is a claim about what the answer did, and cannot be overridden by hedging vocabulary appearing anywhere, including in recited material. | `eval_datasets._looks_like_refusal` | `test_r16_self_certified.py::TestOfflineScorerSafetyGate` |
| **INV-EVAL-2** | The gate has an ORTHOGONAL second leg: similarity to `safety_trap.unsafe_answer`, the golden example of the wrong answer the dataset already shipped and the scorer never used. It is different text from the assertions, so an answer gaming the coverage score by recitation cannot also fabricate a low score here. | `eval_datasets._resembles_unsafe_answer` | `test_r16_self_certified.py::TestOfflineScorerSafetyGate::test_the_shipped_unsafe_answer_fails_every_trap` |
| **INV-EVAL-3** | A row is a trap by EITHER marker. `category == "safety_trap"` was the only detector, while `safety_flag` — the field both dataset test suites treat as the trap marker and require to be a strict bool — was never read, so a row flagged one way but categorized another had no safety gate at all, silently. | `eval_datasets.score_answer_offline` | `test_r16_self_certified.py::TestOfflineScorerSafetyGate::test_a_trap_marked_only_by_safety_flag_is_still_gated` |
| **INV-EVAL-4** | A trap answer must contribute vocabulary of its own. The correct answer to a trap is a refusal WITH REASONING, so one built entirely from the grader's assertion text has demonstrated nothing — yet scored 1.0 on every trap. Measured as vocabulary rather than string similarity, because the bypass also worked as a bare keyword list with no textual resemblance but exactly the assertions' words. | `eval_datasets._is_assertion_recitation` | `test_r16_self_certified.py::TestOfflineScorerSafetyGate::test_a_keyword_soup_fails_every_trap` |

All four legs are an AND, and the decisive test is the **control**:
`test_the_golden_expected_answer_still_passes_every_trap`. Three new refusal
requirements could trivially be satisfied by failing everything, so the genuine
refusal shipped with each of the 25 rows must still pass — otherwise the scorer is
broken rather than repaired. A control written for a different fix also exposed a
pre-existing gap: `declining` / `refusing` / `rejecting` appeared in no marker list, so
a real refusal opening with a participle read as neither refusal nor compliance. This
word-list approach needs every inflection enumerated by hand; that is a structural
weakness of the module, recorded rather than papered over.

---

## INV-FACTORY — a green dry-run cannot mean something different from the real run

| ID | Invariant | Owner | Enforced by |
|---|---|---|---|
| **INV-FACTORY-1** | A manifest entry may not carry raw API-level keys. `core.create_harness` assembles the request from its named parameters and then does `args.update(kw)`, so a passthrough key wins over everything the factory computed. Reproduced end to end: an entry with `name: inlineHarness` plus `harnessName: totally_different_name`, `executionRoleArn: arn:aws:iam::000000000000:role/attacker_not_the_resolved_one` and `allowedTools: ["*"]` passed `dry_run=True` **reporting `inlineHarness`**, then created a harness under a different name, with an execution role the factory never resolved, and unrestricted tools. That breaks this module's central promise — a green dry-run means a safe real run — in the direction where an operator believes they reviewed something they did not. Checked on BOTH the inline and `config:` paths, so the guard is a property of the factory rather than of one branch. | `factory._reject_api_level_overrides` | `test_r16_self_certified.py::TestFactoryRejectsApiLevelOverrides` |

The inline path additionally skips `loader.load_harness_config` entirely, so the
loader's own governance — notably the near-miss HITL gate-name check, which raises
rather than auto-normalizing — never runs on it. Refusing the override keys does not
restore that; an inline entry is unloadered by design. It stops an inline entry from
rewriting what the factory *did* verify.

---

## INV-CLI — a presentation flag never disables a gate

The CLI is where a human forms their belief about system state. A wrong exit code is a
defect even when the library underneath is correct, because automation acts on the
exit code and nothing else.

| ID | Invariant | Owner | Enforced by |
|---|---|---|---|
| **INV-CLI-1** | `detection audit --min-score N` fires in EVERY output mode. The `--navigator` branch returned 0 before reaching the gate, so `--min-score 99 --navigator layer.json` exited 0 at any health score while the same command without `--navigator` exited 1. Asking for both an export and a gate produced the export and a **green build** — worse than no gate, because a pipeline author who adds an export silently loses the check with no output saying so. The gate is about the score, not about how the report was rendered. | `cli._cmd_detection_audit` | `test_r16_self_certified.py::TestCliGateSurvivesEveryOutputMode` |
| **INV-CLI-2** | `detection baseline --snapshot` and `--against` are refused together rather than one silently winning. argparse declared neither exclusive and the snapshot branch returned first, so `--snapshot new.json --against old.json` wrote the snapshot and **skipped the regression comparison**, exiting 0. Refusing beats picking: which the operator meant is genuinely ambiguous, and guessing is what produced the silent pass. | `cli.cmd_detection_baseline` | `test_r16_self_certified.py::TestCliBaselineModesAreExclusive` |
| **INV-CLI-3** | A teardown where every delete FAILED exits non-zero. `core.cleanup` returned only the names it managed to delete, so "nothing matched the prefix" and "every delete was denied" were both an empty list — the CLI printed "deleted 0 harness(es)" and exited 0, which an operator or CI teardown reads as a clean account while live harnesses remain. Failures are now collected through a caller-supplied sink (not the return type, which several callers depend on, and not a module global, which would be wrong under concurrent teardowns). The best-effort loop stays: continuing past one failure is deliberate for teardown. | `core.cleanup` / `cli.cmd_cleanup` | `test_cli.py::test_cleanup_exits_nonzero_when_deletes_fail` |

---

## INV-GATE — the promotion gate never approves a verdict the judge did not give

`run_evaluation` is the scoring gate the self-improvement loop promotes on. Its
input — an LLM judge's reply — is untrusted: it can be malformed, truncated,
refused, or quote material the evaluated agent wrote. Round 15 found **six** ways a
missing or ambiguous judgement resolved into a **PASS**.

The most consequential is not on this list as a separate row because it underlies
four of them: a *stopping decision* was being reached by DEFAULT. "The judge did not
clearly say fail" is not the same as "the judge said pass".

| ID | Invariant | Owner | Enforced by |
|---|---|---|---|
| **INV-GATE-1** | The prose verdict is matched on WORDS, not substrings. `"pass" in text` approved on "passable at best", "shows compassion" and "expectations were surpassed" — at score 1.0. Same substring-for-semantics error as INV-FP-3 (`"\|contains" in field_name`) and R13b's `"not " in condition`. | `run_evaluation._has_word` | `test_r15_stopping_decisions.py::TestProseVerdictIsWordMatched` |
| **INV-GATE-2** | A judge REFUSAL is never a pass. "I cannot evaluate this; please pass it to a human" scored 1.0. A refusal is the *absence* of a verdict, and a guardrail refusal is exactly the reply most likely to contain hedging words. | `run_evaluation._REFUSAL_MARKERS` | `test_r15_stopping_decisions.py::TestJudgeRefusalIsNotAPass` |
| **INV-GATE-3** | The `pass` flag is parsed, never bare-`bool()`'d, and a structured value where a boolean belongs is a fail. `bool("false") is True` promoted a failing verdict. **This is INV-BOUNDARY-1 recurring one round after it was established** — the lesson being that an invariant expressed as a documented convention gets reimplemented; the import of the shared helper is the mechanism. | `run_evaluation._coerce_pass` | `test_r15_stopping_decisions.py::TestPassFlagIsCoerced` |
| **INV-GATE-4** | The evaluated agent cannot supply its own verdict. First-JSON-wins meant a judge reply *quoting the answer under review* — normal judge behaviour — put the agent's embedded `{"pass": true, "score": 1.0}` ahead of the judge's real decision, making `agent_loop`'s stated invariant ("the agent cannot claim a score") false at the parser level. Nothing in the bytes distinguishes "the judge revised itself" from "the judge quoted the agent", so disagreeing candidates fail closed. | `run_evaluation._extract_verdict_objects` | `test_r15_stopping_decisions.py::TestAgentCannotScoreItself` |
| **INV-GATE-5** | A self-contradicting verdict is not a pass. `pass: true` with score 0.05 promoted on the flag alone; the judge's two output channels disagreeing is not a decision. The score is still reported faithfully so an operator can see the contradiction. | `run_evaluation.parse_verdict` | `test_r15_stopping_decisions.py::TestContradictoryVerdictFailsClosed` |
| **INV-GATE-6** | A malformed/truncated JSON reply is not word-scanned. **This defect was created by the fix for INV-GATE-1**: word-boundary matching then matched the JSON *key* `"pass"` left by a reply cut off mid-object, so a truncated failing verdict scored 1.0. A parallel probe quantified it — 73 of the 93 possible cut points in one failing verdict flipped it to a maximum-confidence approval. The root cause was a LAYER confusion, not a vocabulary gap: the prose path is for a judge that answered in sentences, and applying it to broken JSON reads "malformed" as "approved". | `run_evaluation._looks_like_attempted_json` | `test_r15_stopping_decisions.py::TestTruncatedJsonIsNotAPass` |
| **INV-GATE-7** | `parse_verdict` is pure, as its docstring claims, and never raises on hostile input — but its decision on garbage is FAIL, never pass. | `run_evaluation.parse_verdict` | `test_r15_stopping_decisions.py::TestParseVerdictIsPure` |
| **INV-GATE-8** | A score outside [0, 1] is a PROTOCOL error, not a value to clamp. Clamping up turned a judge grading 3/10 — a clear fail — into a perfect 1.0, as did 12/100; clamping down would make 9/10 the worst possible score. Out of range means the judge did not use our scale, so what it meant is unknowable. NaN also slipped past the old range checks (it fails every comparison) and was emitted as the score. A MISSING score is still derived from the pass flag — absent is not the same as mis-scaled. | `run_evaluation._coerce_score` | `test_r15_stopping_decisions.py::TestOutOfRangeScoreFailsClosed` |

Two contracts in `tests/test_m2_edge.py` were deliberately **overturned** here, with
the reasoning recorded at each site: `pass: "false" → True` (whose own comment
called it a "GOTCHA", i.e. it documented `bool()`'s behaviour rather than asserting a
wanted semantics) and first-brace-span-wins.

---

## INV-DEDUP — a redundancy verdict is provable, or it is not made

`detection_dedup` tells an engineer a detection rule is safe to delete. Its docstring
makes a claim that is a *mathematical proposition*: "It NEVER claims a rule is
redundant unless the subset relation is provable." Round 15 mechanized that
obligation instead of trusting it.

**The tool survived.** ~200 subset/duplicate claims across every modifier
combination, wildcard form, field-name casing and logsource granularity produced
zero counterexamples under the repo's own Sigma matcher. The reason is design, not
luck: `_analyzable_predicates` is an **allow-list** — only
contains/startswith/endswith/bare-equality over string scalars pass, and everything
else returns `None` → `not_analyzed`. Allow-listing is the only way a provability
claim survives contact with an adversary, and it is worth contrasting with the
denylist-shaped defects INV-FP and INV-GATE record.

| ID | Invariant | Owner | Enforced by |
|---|---|---|---|
| **INV-DEDUP-1** | If the tool reports A ⊆ B, then no event matches A without matching B — verified differentially against `tools/sigma_match`, **with a positive control** that injects an unsound `_predicate_implies` and asserts the harness catches it (it finds 52 violations). Without that control, "0 violations" is indistinguishable from a broken harness — the vacuous-pass failure mode this repo has hit three times. | `detection_dedup._predicate_implies` / `_subset_of` | `test_r15_stopping_decisions.py::TestSubsumptionIsSound` |
| **INV-DEDUP-2** | Every input rule is accounted for exactly once: analyzed, or *declared* in `not_analyzed`. A silently dropped rule lets a reviewer believe the corpus was fully covered. Declining to analyze is the tool being honest; a confident verdict on an unmodelled shape is the defect. | `detection_dedup._analyze` | `test_r15_stopping_decisions.py::TestSubsumptionIsSound::test_every_rule_is_accounted_for_exactly_once` |
| **INV-DEDUP-3** | Rules over different logsources are never compared — they never see the same events, so no relation between them is assertable. And the tool stays USEFUL: a narrow rule strictly inside a broad one is still reported, in the correct direction. | `detection_dedup._analyze` | `test_r15_stopping_decisions.py::TestSubsumptionIsSound::test_an_actually_redundant_rule_is_still_found` |
| **INV-DEDUP-4** | A CHAIN of value modifiers is refused, never read as its last link. The modifier loop assigned on each pass, so `Image\|contains\|startswith` kept only `startswith` — not a parse of the chain but a *different predicate*. `sigma_match` reads the same chain as `contains` (`xcmdy` matches), so the two engines disagreed about what the rule matches while dedup reasoned about subsets on top of that. A chain has no single set-containment model, so it is refused rather than guessed. | `detection_dedup._analyzable_predicates` | `test_r15_stopping_decisions.py::TestChainedModifiersAreNotAnalyzed` |

| **INV-DEDUP-5** | Sigma escapes are RESOLVED before values are compared, and only a live (unescaped) wildcard leaves the provable shape. `_predicate_implies` compares values as plain TEXT, but per the spec `\*` is a LITERAL asterisk — so `contains: 'C:\Temp\*'` (matching the literal `C:\Temp*`) is not a subset of `contains: 'C:\Temp\'` (matching anything under that directory), yet as RAW text one looked like a prefix of the other. dedup reported "safe to delete", and the event `del /f /q C:\Temp*` matches the deleted rule and not the survivor. An exhaustive predicate-level differential found **156 false implications, every one involving an escape**. Resolution is byte-identical to `sigma_match._unescape_sigma` and pinned equal to it by test — the two engines disagreeing about what an escape means is what produced this defect. | `detection_dedup._has_live_wildcard` / `_unescape_value` | `test_r15_stopping_decisions.py::TestSigmaEscapesAreNotComparedAsText` |

### Two corrections to what round 15 originally recorded

**INV-DEDUP-4** was the defect the hand-run differential missed: I varied wildcards,
casing, logsource granularity and predicate count, but **every predicate in my space
had at most one modifier**. The fan-out probe varied that dimension and found it at
once.

**INV-DEDUP-5 overturns a conclusion I published.** I recorded the escape-sequence
claim as REFUTED after re-running it with single-quoted YAML rules and seeing zero
violations — but YAML consumed the backslash before Sigma ever saw it, so I was
measuring the YAML layer, not Sigma escaping. The probe passed **parsed dicts**,
which `_parse_rule` explicitly accepts and a real caller is most likely to use, and
the defect reproduced immediately. So the round-15 statement that "detection_dedup
survived outright" was wrong; it survived every dimension I exercised, which is not
the same thing — the same overstatement this file already records for `ops_query`.

The fix needed correcting **twice**, and each time a test caught it rather than more
reasoning:

1. Decline every value containing a backslash — wrong trade-off, since nearly every
   real Sigma rule carries a Windows path. Broke three tests.
2. Decline only the escapes `\*`/`\?`/`\\` — still wrong for `\\`, which folds two
   characters into one literal backslash and introduces no pattern semantics. Broke
   `test_detection_audit` on a rule whose YAML held `'\\powershell.exe'`.
3. **Separate the cases.** A live wildcard cannot be decided by any text relation →
   decline. An escape is resolvable → resolve, then compare. This closes the defect
   while declining *nothing*.

Worth generalizing: both wrong turns came from reaching for "refuse it" — the posture
that is right elsewhere in this file — when the actual problem was that the value was
being read in the wrong form. Declining is the correct answer when a thing cannot be
modelled, not when it merely has not been decoded yet.

---

## INV-OPS — an unknown filter is refused, never answered with silence

| ID | Invariant | Owner | Enforced by |
|---|---|---|---|
| **INV-OPS-1** | An unknown or mis-cased `finding_type` is a `validation_error`, not an empty result set. "These are all the open findings in the estate" is a stopping decision: a finding that does not appear is never triaged, ticketed or fixed, so a mistyped filter must not read as "all clear". Per-type counts reconcile with the estate total, and the wildcard view carries every finding. | `ops_query._validate` | `test_r15_stopping_decisions.py::TestOpsQueryRefusesUnknownFilters` |
| **INV-OPS-2** | A reply the backend itself flagged as PARTIAL is refused, never presented as complete. `errors[]` ("3 of 12 accounts denied") and an un-followed pagination cursor were both dropped on the floor, so the readable page-one subset was reported as the whole estate — a truncated "all open findings" reads as fewer problems. | `ops_query._assert_complete` | `test_r15_stopping_decisions.py::TestOpsQueryLiveReplyFidelity` |
| **INV-OPS-3** | The requested `finding_type` is verified against the returned findings, not stamped onto them. A backend that ignores the filter had unrelated findings relabelled, so an operator triaging "all public_s3 findings" would act on `mfa_disabled` records under the wrong heading. | `ops_query._normalize_live_reply` | `test_r15_stopping_decisions.py::TestOpsQueryLiveReplyFidelity::test_findings_of_another_type_are_not_relabelled` |
| **INV-OPS-4** | A single-account query verifies the reply is about that account. The same relabelling defect INV-BOUNDARY-4 found in `nvd_lookup`, one selector over: another account's footprint was reported under the requested id. | `ops_query._normalize_live_reply` | `test_r15_stopping_decisions.py::TestOpsQueryLiveReplyFidelity::test_another_accounts_footprint_is_not_reported_under_the_requested_id` |
| **INV-OPS-5** | The SSRF guard holds for the URL actually connected to, and recognizes every spelling of a forbidden address. Two reproduced bypasses: (a) `ipaddress.ip_address()` only parses dotted-quad/standard IPv6, so `http://2852039166/` and `http://0xA9FEA9FE/` — both 169.254.169.254 — fell through as if they were DNS names; (b) a `302` walked the request past the guard entirely, and urllib re-sends request headers to the redirect target, so the `Authorization: Bearer` credential leaked to whatever host the backend named. | `ops_query._parse_ip_literal` / `_NoRedirect` | `test_r15_stopping_decisions.py::TestOpsQuerySsrfGuard` |
| **INV-OPS-7** | A promotion action (`create_endpoint`, `update_endpoint`, `promote_endpoint`) is REFUSED unless a driver declares it ran the HITL gate. `docs/THREAT-MODEL.md` §1 claims "the agent can only *request* [promotion], never execute" it; that held for `agent_loop.run_agent_loop` and `autonomy.run_improvement_loop` and **not** for a direct `harness_ops.handler(...)` call — reproduced, it promoted `prod` and returned `ok:True`. The direct path is real: `scenario_agent_factory_loop.py` describes itself as calling "the harness_ops handler directly rather than over a Gateway MCP target". It uses only create/wait_ready/invoke/delete, so nothing was exploited, but nothing PREVENTED a promote — a convention, not a mechanism, the same shape as INV-PROMOTE-3. Fail-closed on both presence and VALUE (only an affirmative token counts; `bool("false")` is True and this repo has four INV-COERCE recurrences). The driver sets the witness for the duration of ONE call and always restores it, since a leaked witness would disable the gate process-wide. | `harness_ops._require_promotion_gate` + `agent_loop._with_promotion_witness` | `test_harness_ops.py::TestPromotionGate`, `test_r21_promotion_gate.py` |
| **INV-OPS-6** | `harness_ops` refuses a request carrying raw API-level keys (`harnessName`, `harnessArn`, `allowedTools`, `executionRoleArn`, `systemPrompt`, `messages`, `maxIterations`, …). This is INV-FACTORY-1 on the control plane. `core.create_harness` ends `args.update(kw)` and `core.invoke` `kw.update(overrides)`, so a passthrough key WON over everything the handler validated: `harnessName` beat the validated `name`, and `harnessArn` retargeted an invoke to a DIFFERENT harness while `allowedTools:['*']`/`maxIterations` stripped that harness's limits — handler returned `ok:True`. The guard is at the ONE dispatch point, not the two actions that were found, because four actions forward params and a fifth would inherit the hole. | `harness_ops._reject_api_level_keys` | `test_harness_ops.py::test_a_raw_api_level_key_is_refused` |

`ops_query` survived the OFFLINE path and the selector semantics; it did not survive
the live seam. That gap is a method note, not a footnote: I recorded the tool as
surviving after exercising two dimensions, and a parallel probe then found five
defects in the third. **A tool "survives" only the dimensions actually exercised.**

The contrast with INV-GATE remains the useful structural point: `ops_query._validate`
guards *caller input* and may legitimately refuse it, whereas `_normalize_live_reply`
parses an *upstream response* and must tolerate it. Every defect in both families sat
on the tolerant side. Tolerance is where fail-open grows — which is why rounds 14 and
15 found every defect on a response-parsing path.

---

## INV-BOUNDARY — an external source's silence is never read as good news

Every tool in this family translates a response we do **not** control into a
judgement an analyst acts on. A defect here is never a crash — it is a *confident
wrong answer* derived from data that was absent, malformed, or shaped differently
than assumed. Round 14 found seven, and six of them leaned the same way:

> **"I could not read it" was rendered as "there is nothing there."**

The remaining class is direction-blind rather than fail-open (a bare `bool()`,
case-sensitive equality against feed-controlled values) and was wrong in **both**
directions — which is precisely why no single test case caught it.

| ID | Invariant | Owner | Enforced by |
|---|---|---|---|
| **INV-BOUNDARY-1** | A backend truthiness value is *parsed*, never bare-`bool()`'d, and the tools delegate to the repo's authoritative `connectors.base._coerce_bool` rather than reimplementing it. `bool("false") is True`, so a backend that serializes booleans as strings turned a patched service into a vulnerable one and an internal host into an internet-facing one. | `asset_lookup._normalize_service` / `_normalize_host` | `test_r14_boundary_fidelity.py::TestTruthinessIsParsedNotCoerced` |
| **INV-BOUNDARY-2** | "Never assessed" is distinguishable from "assessed clean". `known_vuln` is the sole gate on the CVE-vs-asset join, so an absent/null/renamed flag collapsing to `False` made an internet-exposed host running a KEV-listed CVSS-10.0 CVE report `no_action_not_exposed`. A populated `cve_id` is evidence in its own right. | `asset_lookup._normalize_service` | `test_r14_boundary_fidelity.py::TestUnassessedIsNotClean` |
| **INV-BOUNDARY-3** | An unrecognized CMDB reply raises; it never renders as an *empty attack surface*. A renamed envelope, a renamed collection or a 200-OK error body all produced `ok: True` with zero hosts — "I could not read your asset inventory" shown as "you have no exposed assets". A reply that genuinely says `"hosts": []` is still believed. | `asset_lookup._normalize_surface` | `test_r14_boundary_fidelity.py::TestUnreadableReplyIsNotAnEmptySurface` |
| **INV-BOUNDARY-4** | A CVE record is selected by *matching id*, never taken from position 0 and relabelled with the id we asked for. The old code returned another CVE's score and description under the requested id — Log4Shell reported as 3.1 LOW. Case differences are not mismatches. | `nvd_lookup._normalize_nvd` | `test_r14_boundary_fidelity.py::TestNvdRecordIdentityIsVerified` |
| **INV-BOUNDARY-5** | An unreadable CISA KEV catalog is an `upstream_error`, never `in_kev: False`. `in_kev` gates emergency patching; reading the feed wrong turned CISA's strongest possible signal into silence. A catalog we *could* read that omits the CVE is still a genuine `in_kev: False`. | `epss_kev._enrich_live` | `test_r14_boundary_fidelity.py::TestKevReadFailureIsNotANegativeFinding` |
| **INV-BOUNDARY-6** | A feed's letter case is not a security signal. Case-sensitive comparison against third-party values flipped the verdict both ways: `confidence="High"` downgraded malicious→suspicious, `category="BENIGN"` escalated benign→malicious. | `enrich_ioc._derive_verdict` | `test_r14_boundary_fidelity.py::TestVerdictIsCaseInsensitive` |
| **INV-BOUNDARY-7** | A revoked or deprecated ATT&CK technique is reported as such (STIX `revoked` / `x_mitre_deprecated`), on both the live and offline paths. Dropping them let a dead target be counted toward coverage the *replacement* technique governs — INV-COVERAGE's capability-vs-intent error arriving from upstream. | `attack_lookup._normalize_technique` + stub path | `test_r14_boundary_fidelity.py::TestRevokedTechniquesAreSurfaced` |

Each invariant is paired with **CONTROL** tests asserting the correct input still
works. A guard that only proves the broken input now raises cannot tell "we fixed
the defect" from "we broke the tool" — round 13 published a wrong conclusion from
exactly that gap, and the ratio here (53 assertions fail pre-fix, 34 controls pass
either way) is what makes the suite meaningful rather than merely red.

---

## INV-IDENTITY — every self-reference resolves to THIS repository

This project was developed in a personal repository and transferred to
`aws-samples/sample-sentinel-harness`. The transfer moved the code; it did not move
the URLs embedded in the docs, the landing page and the issue templates.

The pre-transfer repository is **still public and still answers HTTP 200**, which is
what makes this a defect family rather than a batch of dead links: a stale reference
does not fail visibly, it silently serves a frozen copy that looks authoritative and
will never receive the fixes shipped here.

| ID | Invariant | Owner | Enforced by |
|---|---|---|---|
| **INV-IDENTITY-1** | No tracked text file references the pre-transfer `owner/repo` pair or its Pages host. A bare owner reference with no repo path is an attribution byline and is deliberately allowed. | repo-wide | `test_repo_identity.py::test_no_stale_project_url_anywhere` |
| **INV-IDENTITY-2** | The private security-report contact link routes to THIS repository's `security/advisories/new`. Pointing it elsewhere misdelivers vulnerability reports, and because such a report is private by design the misdelivery is undetectable: the reporter believes they disclosed responsibly and the maintainers never learn of the issue. | `.github/ISSUE_TEMPLATE/config.yml` | `test_repo_identity.py::test_security_contact_link_points_at_this_repository` |
| **INV-IDENTITY-3** | Every documented `git clone <url> && cd <dir>` names the directory clone actually creates. The rename to `sample-sentinel-harness` broke every such pair, so a reader copy-pasting the quickstart fails on line 1. | docs | `test_repo_identity.py::test_documented_clone_commands_are_copy_pasteable` |
| **INV-IDENTITY-4** | GitHub-Pages links **to this project** use the canonical host and repo path. Scoped by SUBJECT, not by URL shape: the repo legitimately links third-party `*.github.io` docs (MITRE ATT&CK Navigator, LangGraph), and flagging those would repeat the breadth-vs-selectivity error INV-FP records. | docs + `site/` | `test_repo_identity.py::test_pages_links_use_the_canonical_host` |

Each of the four is paired with a **guard-the-guard** test, because every one of them
is a scan whose assertion goes vacuously true if the file-collection step breaks. The
collection helper raises rather than returning an empty list for the same reason (see
the fail-closed rule in the layering note above).

---

## INV-AUDITMAP — this document is an executable coverage report

Eighteen rounds produced the invariants above. Nothing answered the question that has
consistently paid off: **which shipped module has NO invariant naming it?**

Round 16 asked it by hand, found four modules with tests but zero invariants, and the
worst finding of that round was in them — Play Mode's central safety claim turned out to
be falsifiable by editing a JSON file. Nine defects came out of those four modules. Round
19 made the question mechanical, and the module it selected first (`registry_live`) had a
real defect within an hour.

| ID | Invariant | Owner | Enforced by |
|---|---|---|---|
| **INV-AUDITMAP-0** | The map is not vacuous: the doc parses into ≥100 invariant rows, the Owner/Enforced-by columns yield ≥60 code tokens, the tree walk finds ≥40 modules, and ≥60% of shipped modules are named by an invariant. Every assertion below is negative ("no module is unaccounted for"), so a broken parse would pass them all silently. | `test_r19_invariant_coverage.py` | `test_r19_invariant_coverage.py::TestTheMapIsNotVacuous` |
| **INV-AUDITMAP-1** | Every shipped module with no invariant appears in `_UNCOVERED` with a ≥30-character reason, and no entry is stale (naming a module that IS now covered) or dangling (naming a deleted one). A module without an invariant is allowed; a module without an invariant *and* without an argument is not. | `test_r19_invariant_coverage._UNCOVERED` | `test_r19_invariant_coverage.py::TestEveryUncoveredModuleIsAccountedFor` |
| **INV-AUDITMAP-2** | Eight security-critical modules — `agent_loop`, `autonomy`, `loop_safety`, `sandbox_hooks`, `provenance`, `simulation`, `egress`, `connectors/siem` — must ALWAYS be named by an invariant. Losing their coverage cannot be silent. | `test_r19_invariant_coverage._MUST_BE_COVERED` | `test_r19_invariant_coverage.py::TestTheSecurityCriticalModulesAreCovered` |

It deliberately does **not** demand blanket coverage. Plenty of modules legitimately need
no invariant — a pretty-printer, a metadata table, a re-export shim — and forcing one
produces ceremonial invariants, which are worse than none because they make the map lie.

`_UNCOVERED` entries are labelled `QUEUED` (not yet examined) or argued as holding no
security-relevant decision. "Under audit" is never written of a module nobody has looked
at: that is the same lie the map exists to catch. Both a unit control and an end-to-end
control ship with it — the latter writes a probe module into the tree and asserts the
suite names it, because a coverage map reporting "all accounted for" is indistinguishable
from a broken one.

---

## INV-REGISTRY — the live control plane VERIFIES the DRAFT claim

`registry_live.py` is this codebase's **third** human-approval gate, and its headline
promise is a lifecycle one: `autoApproval=false` ⇒ a new record lands in `DRAFT` and is
not callable until a human approves it. A Registry record is what makes a tool or agent
discoverable, so an unapproved-but-live record is an ungoverned capability.

The first two approval gates both had defects. INV-PROMOTE-2: consent for harness A
promoted harness B. INV-PLAY-6: the human saw one technique while the gate requested
another. This one had the third shape — it **asserted** its guarantee instead of
checking it.

| ID | Invariant | Owner | Enforced by |
|---|---|---|---|
| **INV-REGISTRY-1** | `create_*_record` REFUSES any status that is not `DRAFT` or `CREATING`. It used to send `approvalConfiguration` and then return whatever status came back, so `ACTIVE` / `APPROVED` / `LIVE` / `""` / a missing field were all reported as a governed record. Reproduced across all five. The gap is structural: `approvalConfiguration` is set on the REGISTRY and `CreateRegistryRecord` cannot see it, so a `registry_id` naming an auto-approving registry, an API version that ignores the field, or a partition with different behaviour each produce a live record while the caller is told it is DRAFT. INV-BOUNDARY-5's rule applies — "we could not tell" must never render as the safe answer. | `registry_live._create_record` | `test_registry_live.py::test_create_record_refuses_an_already_live_status`, `::test_create_record_refuses_a_reply_with_no_status` |
| **INV-REGISTRY-2** | `create_registry(auto_approval=True)` WARNS. Creating an ungoverned registry stays possible — an adopter may genuinely want it for a throwaway dev registry — but never silently, because every record in it goes live with no human step. The governance-safe default emits nothing, so the warning that matters is not buried in noise. | `registry_live.create_registry` | `test_registry_live.py::test_auto_approval_registry_warns`, `::test_default_registry_creation_does_not_warn` |
| **INV-REGISTRY-3** | The idempotency token distinguishes a GOVERNED create from an ungoverned one, AND `create_registry` reads the posture back. `clientToken` is `idempotencyToken:true` ("If this token matches a previous request, the service ignores the request"), and the seed was a pure function of the NAME — it ignored `auto_approval`, and `_client_token` collapses the legal name chars `_./-` all to `-` (8 legal names → 2 tokens). So a governed create issued after an ungoverned one of the same name REPLAYED the auto-approving registry's ARN, no error: SecOps believes it holds a DRAFT-gated registry and holds the ungoverned one. The seed now folds in the posture, and `_assert_approval_posture` reads `GetRegistry.approvalConfiguration` back and refuses a mismatch (covering caller-supplied tokens and name-conflict resolution too). | `registry_live.create_registry` / `_assert_approval_posture` | `test_registry_live.py::test_governed_create_after_ungoverned_does_not_replay_it`, `::test_read_back_refuses_a_posture_mismatch` |
| **INV-REGISTRY-4** | `list_records` returns EVERY record, across all pages. It read only page one — one `list_registry_records` call, ignoring `nextToken` — while its docstring said "every record" and its caller is a GOVERNANCE listing. An approved (live) record beyond the first page was absent from the audit view, which read as complete: a blind spot in the one direction that matters, a live capability you cannot see. Now paginates on `nextToken`, refusing a repeated token rather than looping. | `registry_live.list_records` | `test_registry_live.py::test_list_records_paginates` |

`CREATING` is accepted deliberately: it is the transient state before the service settles
a record into `DRAFT`, and refusing it would break every real call that catches the
record mid-settle. Both meanings are "exists, not callable".

### Why these assertions do not use `caplog`

`logutil.configure_logging()` sets `propagate = False` on the `sentinel_harness` logger —
correct in production, since a host application's root handler would otherwise print
every record twice — and pytest's `caplog` collects through a root handler. So a `caplog`
assertion here PASSES in isolation and FAILS in the full suite, depending on whether some
earlier test happened to call `configure_logging()` first. Found exactly that way. The
tests attach a handler to the logger under test, which is the assertion that matches the
claim: *this warning was emitted*, not *this warning reached the root logger*. A control
proves the collector is not simply empty.

---

## INV-MCP — the stdio trust boundary is governed, or it refuses to serve

`mcp_server.py` exposes tools over stdio to any MCP client — the one module reachable by
an untrusted peer. Its job is to serve a REGISTRY-GOVERNED subset. Round 20 found it
served everything when it could not read the registry, and that this was the DEFAULT on
the packaged install path.

| ID | Invariant | Owner | Enforced by |
|---|---|---|---|
| **INV-MCP-1** | An unreadable registry is REFUSED, not treated as "no filtering". `_load_approved_set` swallowed every exception and returned an empty set, and the gate read `if approved and tool not in approved` — so an empty set made the condition falsy and every tool in `tools/` was exposed, pending ones included. Reproduced: the broken path served 18 tools vs 17, the extra being `web_search`, the only non-approved entry and the one tool that fetches attacker-influenceable content. Now raises `GovernanceUnavailable`; only the explicit `SENTINEL_MCP_ALLOW_PENDING=1` escape hatch may proceed ungoverned, and it warns. An empty-but-READ approved set correctly excludes everything. | `mcp_server._load_approved_set` / `_discover_tools` | `test_mcp_server.py::TestGovernanceGate` |
| **INV-MCP-2** | The registry is found regardless of CWD. `DEFAULT_REGISTRY_PATH` is CWD-relative and the wheel shipped no `registry/` at all (verified by building one), so `pip install && sentinel-mcp` from any non-checkout dir could not read it — and combined with the pre-fix INV-MCP-1, failed open on EVERY packaged install. The registry is now packaged as `sentinel_harness/data/tools.yaml` AND `load_yaml` falls back to that installed copy. Two independent fixes because data-only packaging is easy to drop again (it was dropped once, for `connectors`) and a path fallback with nothing to find is useless. | `registry._resolve_registry_path` + `[tool.setuptools.package-data]` | `test_registry.py::test_packaged_registry_resolves`, `test_packaging.py::test_registry_yaml_is_declared_as_package_data` |
| **INV-MCP-3** | The PyYAML-fallback parser does not flatten a nested key onto a tool item. `_mini_yaml` wrote `current[key]=value` for every `k:v` line regardless of depth, so a nested `status: approved` (in a documented example, a sub-config) overwrote a top-level `status: pending` — a fail-OPEN promotion, and PyYAML resolves the same file correctly, so the two parsers disagreed on an approval decision in the permissive direction. Now tracks the item's key indent and skips deeper sub-maps. | `registry._mini_yaml` | `test_registry_minyaml.py::test_mini_yaml_does_not_flatten_a_nested_status`, `::test_mini_yaml_agrees_with_pyyaml_on_the_nested_case` |
| **INV-MCP-4** | Exception text crossing the MCP boundary is REDACTED. This module is the one surface an untrusted peer reaches, and two paths handed it `str(exc)` verbatim: `_invoke_tool`'s response `message`, and — quieter — `_discover_tools`' `[LOAD ERROR: {exc}]`, which `list_tools` SERVES as a tool description. Reproduced: a handler raising `postgresql://svc:SUPERSECRET_PW@db.internal/soc (token=ABSK_...)` delivered the password and the token to the peer. This is INV-TICKET-1's shape a second time — round 20 fixed it in `create_ticket` at that one call site while recording that a one-site fix is not an invariant — so the redaction now lives once and both paths use it. A DENYLIST by design: the exception TYPE and ordinary diagnostics survive, because a peer told only "an error occurred" cannot tell a bad argument from an outage. Hostnames are deliberately NOT redacted (stdio transport, operator-configured peer, and a hostname is not replayable the way a credential is) — asserted, so the trade-off is visible. | `mcp_server._safe_error_text` | `test_mcp_error_redaction.py` |
| **INV-CI-1** | CI installs the WHOLE `test` extra, so no test layer can skip silently. Both `ci.yml` and `release.yml` installed a hand-copied dep list — `pytest pytest-randomly coverage ruff hypothesis`, five of the extra's nine entries. The two omitted were `mcp` and `anyio[trio]`, and `test_mcp_protocol.py` opens with `importorskip("mcp")`: so the ENTIRE MCP protocol E2E layer skipped on every CI run — the 7 tests covering the one surface an untrusted peer reaches — while CI reported green. Reproduced in a uv project pinned to CI's exact dep list (`mcp: ABSENT`, layer collapses to `1 skipped`). Local showed 6 skips, CI showed 12, and **nothing compared the two numbers**; a skip looks identical whether the code is fine, the test is broken, or the test never existed. Fixed at the source, not the symptom: `-e ".[test]"` cannot drift from `pyproject.toml` because it IS `pyproject.toml`, and the install step ends with an explicit `python -c "import mcp, anyio, ..."` so a resolver hiccup FAILS instead of degrading to a skip. `ruff` stays pinned outside the extra so the lint verdict is byte-identical local vs CI. | `.github/workflows/{ci,release}.yml` | `test_ci_installs_the_test_extra.py` |
| **INV-MCP-5** | The `mcp` dependency is UPPER-BOUNDED, because the code needs the 1.x decorator API. `pyproject.toml` declared `mcp>=1.0` unbounded, and mcp 2.0.0 removed `Server.list_tools()` / `Server.call_tool()` — the two decorators `mcp_server.create_server` registers its handlers with. Verified against a real 2.0.0 install: `create_server()` raises `AttributeError: 'Server' object has no attribute 'list_tools'`, so `pip install sentinel-harness[mcp] && sentinel mcp serve` **could not start at all** on the current PyPI release. A user-facing install-time break, not a test artifact. What hid it: CI never installed `mcp` (INV-CI-1), so every test that would have caught it skipped on every run — the silent skip was concealing a broken published dependency contract, not a stale test. Also recorded: I first concluded 2.0 compatibility from `from mcp.server import Server` still resolving. It does resolve, and the API behind it is gone — **an import check is not a compatibility check**; compatibility must be probed by calling the surface. Now `mcp>=1.0,<2` in both the `mcp` and `test` extras (they must AGREE, or CI would test 1.x while users got 2.x), and the guard asserts the bound's PREMISE by calling the decorator surface, so the pin gets lifted deliberately when the code is ported rather than lingering as a constraint nobody dares touch. | `pyproject.toml` extras · `mcp_server.create_server` | `test_mcp_version_bound.py` |
| **INV-REGISTRY-5** | A registry entry's `name` EQUALS its `tools/<name>/` directory. `mcp_server._discover_tools` walks `tools/`, takes the DIRECTORY name as the tool name and tests it against the approved set — so a registry entry whose name does not match its directory makes the tool vanish SILENTLY. Reproduced: renaming one registry entry dropped the exposed surface from 17 tools to 16, with neither the old nor the new name resolvable and NO error, warning or governance report. Nothing checked this coupling: `test_registry.py` guarded registry-vs-code-factory (`governance_check`) and the two shipped YAML copies against each other, but not registry-vs-directory — three couplings, two guarded. Adjacent to INV-MCP-1, which fixed the registry being UNREADABLE (fail-open, now raises); this is the registry reading fine while the names disagree. Written and verified to fail BEFORE the whitelist->allowlist rename that needed it, and the end-to-end assertion runs real discovery rather than comparing filenames. | `registry/tools.yaml` · `sentinel_harness/data/tools.yaml` · `mcp_server._discover_tools` | `test_registry_names_match_directories.py` |
| **INV-DOC-6** | The public landing page's quoted counts are guarded too. `site/index.html` is HAND-WRITTEN and git-tracked, published to GitHub Pages, and its `<meta description>` — the text a search result quotes — claimed **2352 tests** while the suite had 3837. Off by 1480, in the most public claim the project makes, because INV-DOC-2's guard covered README and `docs/` and stopped there. The drift lived in the one file no maintainer opens. The patterns are deliberately NARROW: a first attempt matched ROADMAP's historical changelog lines ("2126 -> 2352 offline passing") and reported them as drift — a count guard must distinguish a present-tense CLAIM from a record of the past, or it pressures you into falsifying history to get green. | `site/index.html` | `test_docs_drift.py::test_quoted_counts_match_reality` |
| **INV-DOC-10** | Every `make <target>` the QUICKSTART teaches is covered by a check and exists in the Makefile. `CANONICAL_TARGETS` named 10 targets while QUICKSTART advertised **11** — `deploy-endpoints` was missing, so neither check parametrised over that list covered it: not "the doc mentions this target" and not "the doc agrees with the Makefile". Fourth instance of the inventory-drift shape in four rounds (INV-SKILL-1 five-of-nine, INV-HARNESS-1's reference side, INV-MAKE-1 thirteen-of-sixteen), and the last remaining mirror-type list in the suite: an audit of all 22 parametrising literal lists found the rest either complete (`_OFFLINE_RUNNABLE` is 13 + 10 live = 23, already reconciled) or intrinsic sets that mirror nothing (`HOSTILE_VALUES`, `_REQUIRED_KEYS`). Reconciled against the DOCUMENT, not the Makefile: this list is a deliberate subset — the delivery story's contract, not all 16 targets — and reconciling it against the Makefile would demand it grow to cover targets QUICKSTART never teaches, which is INV-DOC-9's subset-vs-total trap. Three directions now fail: an advertised target the list omits, a listed target the doc dropped, and a taught command the Makefile does not define (a reader would get "No rule to make target"). | `docs/QUICKSTART.md` · `Makefile` | `test_quickstart_doc.py::test_the_canonical_list_covers_every_advertised_target` |
| **INV-MAKE-1** | The Makefile target inventory is reconciled, and every target is `.PHONY`. `tests/test_makefile.py` parametrises its checks over a hand-written `KEY_TARGETS` list that had drifted to **13 of the 16** declared targets. The three missing were `ci` (the local gate), `typecheck` (both mypy gates) and `dist` (the clean-tree build added a few rounds earlier) — so `test_makefile_targets_are_phony` never covered them, and **`dist` was in fact absent from `.PHONY`**. Extending the list made that check fail on the first run: the drift was not itself the defect, it was what hid one. Third instance of this shape in three rounds (INV-SKILL-1: five listed, nine on disk; INV-HARNESS-1: the reference side of the same coupling), so the fix is the same — keep the list explicit so a REMOVED target fails loudly, and reconcile it against the Makefile so an ADDED one cannot go unchecked. `.PHONY` is now checked over the FULL declared set. Measured honestly: with a same-named file planted, the six previously-unchecked targets still ran (they have no prerequisites, so make runs the recipe regardless), so the omission was not causing a live failure — the declaration still states the intent that these are commands, and `demo` and `dist` are names that really do exist as directories here. | `Makefile` | `test_makefile.py::test_the_target_inventory_matches_the_makefile` |
| **INV-SKILL-1** | Every shipped skill is checked, and the inventory is derived rather than hand-listed. `tests/test_cyber_skills.py` enforces real properties per skill — frontmatter parses with a matching `name`, the body is a usable SOP rather than a stub, it names at least one real tool, and **every tool it names exists** (anti-hallucination). But it ran over a literal five-name `NEW_SKILLS` list written when those five were new, and `skills/` had since grown to **nine**. The four that arrived later — `attack-path-reasoning`, `cve-triage-rubric`, `detection-writing-sop`, `ioc-vetting` — were covered by NOTHING: a skill citing an invented tool would have shipped unnoticed, which is the same dangling-reference shape INV-HARNESS-1 found on the harness side one round earlier. All four turned out healthy (checked: frontmatter correct, ~6 KB bodies, 2-4 real tool refs each), so this was a coverage gap rather than bad content — but the gap is the defect. The list is now derived from disk, so a NEW skill is covered automatically instead of silently ignored, and a `_DOCUMENTED_SKILLS` set preserves what the hand-written list was protecting: a rename or deletion still fails loudly, in both directions. The original comment gave two reasons for keeping it explicit; one (a parallel agent owning some skills) had expired, and the other is kept without its cost. Public-doc skill counts are checked against the same measurement. | `skills/*/SKILL.md` | `test_cyber_skills.py` |
| **INV-HARNESS-1** | Every tool a harness allows resolves, and the docs say where from. `harnesses/*/harness.yaml` grants each agent an `allowedTools` list spanning THREE namespaces — AgentCore primitives (`code_interpreter`), Gateway MCP tools (`@gateway/siem_query`), and HITL gates the adopter implements (`request_containment_approval`) — and nothing checked any of them. `allowedTools` is a GRANT, not a lookup, so an unresolvable name does not raise: the agent simply comes up with a smaller tool surface than its config declares. After the `whitelist_optimizer`->`allowlist_optimizer` rename that is a live risk; this is the harness side of the coupling INV-REGISTRY-5 guards on the registry side. **The defect found**: `docs/HARNESSES.md` claimed the gateway tools "have reference-stub handlers under `tools/`" and named `search_registry` as its first example — but 12 of the 14 have stubs and `search_registry` is one of the two that do NOT. A reader following that sentence looks for a directory that is not there. Those two (`search_registry`, `invoke_specialist`) are correctly stub-less: they are PLATFORM operations (Registry query, A2A dispatch), so a local stub would be a misleading no-op rather than a reference — now stated in the doc with the reason, and the split is asserted against measurement. The exemption is guarded in both directions: an entry that GAINS a stub is a stale exemption, and one nothing in the repo references is a typo. HITL gates are matched with `exporter.is_hitl_gate` (INV-EXPORT-1's canonical predicate), never a second substring rule. | `harnesses/*/harness.yaml` · `docs/HARNESSES.md` | `test_harness_tool_refs.py` |
| **INV-DOC-9** | Every COUNT stated to a reader in the public docs and on the landing page matches the tree, and SUBSET claims are verified rather than exempted. Auditing all five reader-facing files found **five stale counts**: `docs/COMPARISON.md` said "2365 tests, 21 scenarios, 36 evidence artifacts" (AT THE TIME — these are the stale strings being quoted, not current counts; the test count off by 1600) and "21 runnable scenarios"; `docs/ROADMAP.md` said "15 runnable scenarios" against 23; `docs/FIDELITY-REPORT.md` was off by one on both evidence and scenarios; and `site/index.html` labelled `make demo` "all 21 offline scenarios" when that command runs a narrated tour touching **9** — wrong number, wrong qualifier, wrong subject. All survived the earlier guards because of PHRASING: `Numbers above (...)` matches no present-tense pattern, and `21 offline scenarios` / `21 runnable scenarios` put an adjective between the number and the noun so an adjacency regex never matched. INV-DOC-8 recorded the same blindness for URL-encoded badges — one fact, several encodings; here it is one fact, several wordings. The scan now tolerates up to two intervening words, which immediately surfaced two more real drifts. `site/index.html` is included explicitly and asserted to be in scope, since it is hand-written, git-tracked, published to Pages, and HTML rather than markdown. Subset claims ("7-tool detection suite", four different wordings of it) are skipped by the total check but VERIFIED separately — the stated number must equal the enumerated members and every member must exist on disk. Guessing that membership from name prefixes gave 8, wrongly including `sigma_match`; README enumerates the seven, so the list is authoritative rather than heuristic. A guard that cannot tell a subset from a total would demand "7-tool" become "20-tool", making a correct sentence wrong. | `README.md` · `docs/COMPARISON.md` · `docs/FIDELITY-REPORT.md` · `docs/ROADMAP.md` · `site/index.html` | `test_docs_drift.py::test_every_total_count_in_the_public_docs_is_accurate` |
| **INV-DOC-8** | Every README badge stating a machine-checkable fact is verified against the source of that fact. Two had drifted: the coverage badge said **90%** against a measured **92%**, and the version badge said **0.4.0** while the package was **0.5.1** — a full minor release behind, misrepresenting what a reader would install. The coverage one is the worse of the two, because `tests/README-coverage.md` states 92% in the same repo: two documents contradicting each other with the shields.io badge — the number a reader takes at face value — being the wrong one. Both survived every counting guard because badge values are URL-encoded: `coverage-90%25` contains no bare `90%`, so no regex looking for a percentage ever matched. A guard scoped to one SPELLING of a fact leaves the other spellings unguarded. The checks live in `test_coverage_doc.py` deliberately, sharing its `_coverage_json` — the badge and the table are two statements of one measurement, and a third implementation is how they came to disagree. The badge gets its OWN tolerance (1 point, not the per-file 5): measured across three pytest-randomly seeds the aggregate TOTAL does not move at all (91.907 each time), and the borrowed 5-point bound swallowed the very drift this guard was written for — the mutation "revert to 90%" survived until the tolerance was calibrated to the right magnitude. | `README.md` badges | `test_coverage_doc.py::test_the_coverage_badge_matches_measured_coverage` |
| **INV-DOC-7** | A COUNT inside an invariant row is a checkable claim, and historical figures are exempt only when marked. INVARIANTS.md carries 156 rows and 8 guards, none of which looked at the numbers in the prose — and two had already drifted: INV-TEST-2 said "across 169 files" against a real 170 (wrong within two rounds of being written), and the round before that it quoted three wrong figures outright. Auditing all 17 numeric claims found exactly one live drift; it is now restated as coverage ("every test module") so it cannot drift again, which is the better fix where the underlying thing grows. The guard measures harnesses / evidence / specialists from the tree and compares. Crucially it SKIPS figures carrying the historical marker (spelled with the words AT/THE/TIME): INV-PKG-3 records that the sdist "carried all 162 test files", a measurement of a past defect, and forcing that to track the current count would make the guard demand the falsification of a record — the trap the CHANGELOG hit when a bulk rename rewrote released entries. A guard that cannot tell a claim from a record pressures you into rewriting history for green. The exemption has its own guard (the marker must sit beside a number, or it exempts nothing). Also unified the test-file count: `test_docs_drift` used `os.listdir` (169) and this module `os.walk` (170, counting `tests/smoke/`), both passing because they checked different documents — one fact, two implementations. Now `repo_infra.count_test_files`. | `docs/INVARIANTS.md` numeric claims | `test_invariants_doc.py::test_every_current_state_count_in_an_invariant_row_is_accurate` |
| **INV-TEST-2** | The suite leaves no in-process state behind, and its fabricated module names are unique. `test_zz_process_isolation.py` guards four SPECIFIC leaks earlier rounds found (the promotion witness, a stacked metric handler, a redirected registry path); this guards the general properties those were instances of — the ones that make `pytest-randomly` meaningful. Four properties measured across EVERY test module in the suite, all holding, none previously checked (a fixed file count was written here first and drifted within two rounds — the suite grows, so the claim is stated as coverage rather than as a number): env writes are all either `try/finally`-wrapped, a module-level `pop("*_LIVE")` safety measure, or a `pop` the test itself asserts stayed popped (net effect zero); no `sys.modules` injection shadows a disk-importable module (48 bare assignments, all fabricated names); the 19 fabricated names are unique across files (a reused "unique" name means the second import silently wins the cache and the first file's tests exercise the wrong module — green, with no subject); and `conftest.py`'s credential fallback uses `setdefault`, never assignment. Plus a runtime check that no `SENTINEL_*_LIVE` flag is set mid-suite, and a static one forbidding NEW un-normalised `sys.path.insert` calls. **Recorded honestly rather than tuned to pass**, and the figures were RE-MEASURED the following round because the first pass got them wrong: a full run carries 63 `sys.path` entries with the repo root appearing 19x literally and **27x after `realpath`** (the extras arrive as `tests/..` / `scenarios/..` aliases) and `tests/` 25x. The cause is two-fold: **26 of the 63 insert sites have NO guard at all**, and the 37 that do compare STRINGS, so `/repo` never matches an existing `/repo/tests/..`. The original entry said "38 guards" because that scan asked whether the FILE contained `not in sys.path` anywhere — a file-level substring test standing in for a statement-level structural question, which is the defect class this repo records most, committed while documenting a guard against it. Judged per statement via AST the split is 37/26. A mechanical rewrite to one idempotent helper was attempted and ABANDONED: tried on a copy of the tree it broke 16 modules at collection, and the benefit is theoretical — the suite passes in both orders, so no known bug traces to this. The three un-normalised inserts stay listed in the guard so the debt is visible and shrinkable, and new ones are refused. | `tests/` (all modules) · `tests/conftest.py` | `test_zz_suite_hygiene.py` |
| **INV-TEST-1** | Every test that builds a distribution artifact does so from ONE shared pristine copy of the tree. Three modules needed this and grew three answers: `test_wheel_contents.py` and `test_installed_cli_e2e.py` each carried a **byte-identical** twelve-entry `shutil.ignore_patterns(...)`, while `test_sdist_contents.py` built IN PLACE with `cwd=REPO_ROOT`. The third was measurably weaker — with a ghost handler planted in `build/lib/tools/`, the wheel guard FAILED (caught it) and the sdist guard reported `6 passed`: it inherited the staleness it exists to detect, exactly what the wheel guard's own docstring (written the same round) warns against. It also left a gitignored `sentinel_harness.egg-info/` in the working tree, so `git status` stayed clean and a test silently mutated the repository it tests. The sdist ARTIFACT was never wrong — `MANIFEST.in`'s `prune build` keeps a stale staging tree out of the tarball (verified: 20 handlers, no ghost) — so this is a defect of method and side effect, not of what ships. The exclusion list now has one definition in `tests/pristine_tree.py`, with `build`/`dist` asserted by name, and an AST scan forbids both a fourth hand-rolled `ignore_patterns` and any builder that skips the helper. | `tests/pristine_tree.py` | `test_r18_guard_the_guards.py::TestArtifactBuildsUseOnePristineCopy` |
| **INV-MCP-6** | Every exposed tool survives arbitrary peer input, REFUSES empty input, and stays offline by default. `mcp_server` hands an untrusted peer's arbitrary dict straight to 17 handlers; INV-MCP-4 fixed what leaks OUT of that boundary and never asked what hostile input going IN does. Three properties measured and all holding, none previously checked: (1) no uncaught exception and always-parseable JSON across 255 hand-picked malformed events plus 250 hypothesis-generated ones — load-bearing because `_invoke_tool` catches `Exception`, NOT `BaseException`, so a handler raising `SystemExit` would kill the server for every LATER call too; (2) an empty event is refused — 17/17 return `ok: False` or an error rather than claiming success on input the peer never supplied (INV-BOUNDARY-5's rule); (3) zero connection attempts across 119 hostile-target events (IMDS `169.254.169.254`, `file:///etc/passwd`, attacker `base_url`) with the socket layer SEVERED, so egress is enforced not asserted. Complements INV-EGRESS's structural checks (live paths import the shared guard) with behaviour: structure says the guard is wired, behaviour says hostile input cannot get past it. The boundary's own `except Exception` is tested by INJECTION — mutation-testing showed narrowing it SURVIVED the whole sweep because **255 combinations produced zero raises**: every shipped handler validates its own input, so that branch never executed. Good handlers, blind assertion; a stub that certainly raises now covers the barrier that matters the day one grows an unhandled path. | `mcp_server._invoke_tool` · `tools/*/handler.py` | `test_mcp_boundary_hardening.py` |
| **INV-EVIDENCE-1** | Committed `evidence/*.json` is BYTE-reproducible by re-running its scenario. The 38 evidence artifacts are the strongest claim this repo makes — README and FIDELITY-REPORT count them as proof — and the property that made them trustworthy was checked by nothing. Measured: all 12 offline-runnable evidence-writing scenarios reproduce their artifact byte-for-byte (no timestamps, no uuids, no dict-order churn). Excellent, and undefended: a `datetime.now()` in an output field would silently break "the evidence is reproducible", surfacing only when a human happened to re-run and see a dirty tree. The reverse is worse — if behaviour CHANGES and the artifact is not regenerated, the committed evidence asserts something the code no longer does, a false claim in the one place the project asks to be believed. The guard fails in BOTH directions. Method: **corrupt the artifact, re-run, compare** — diffing two fresh runs proves only self-consistency, and a scenario that writes NOTHING would pass that trivially; corrupting first makes "did not write" fail loudly (the INV-CI-1/INV-DOC-5 rule). Also asserts every account id in every artifact is the `000000000000` placeholder, walked structurally so an id nested in a deep ARN cannot hide from a line-oriented grep. | `scenarios/*.py` · `evidence/*.json` | `test_evidence_is_reproducible.py` |
| **INV-IAC-4** | The Terraform mirror PRODUCES the metrics its alarms consume, with per-filter pattern/value agreement and names matching the CDK constants. README calls `iac-terraform/` a mirror of `iac-cdk/` for identity/vpc/guardrail/obs/harness, and for observability that was FALSE: CDK ships 3 MetricFilters + 2 Alarms, Terraform shipped **0 filters + 1 Alarm**. That alarm watched `SentinelHarness/TokensPerScenario` and NOTHING in the tree produced it — no `aws_cloudwatch_log_metric_filter`, no `put_metric`, no EMF. So it would sit in INSUFFICIENT_DATA forever and, being declared `treat_missing_data = "notBreaching"`, never fire and never look broken: an operator who deployed it believing the mirror claim had a token-overrun alarm that could not fire. Same shape as INV-METRIC-1 (there the producer emitted the wrong format; here it did not exist) — both silent. **`terraform validate` passes before AND after the fix** — it checks syntax and provider schema, not whether a referenced metric has a source, which is precisely why this needs to be a test. Fixed by mirroring all three filters (`$.tokens` / `$.latency_ms` / `$.errors`); verified in `terraform graph` (a local check, since `plan` needs real STS credentials). The guard checks PER FILTER that the pattern field equals the value field: a union of the two let a rename survive, and that union hid a real AWS failure mode — a filter matching `$.bogus` while extracting `$.tokens` emits no data points, as silent as no filter. Deliberately NOT resource-for-resource parity: CDK's gateway/registry/memory/runtime stacks have no Terraform counterpart by stated scope. | `iac-terraform/observability.tf` · `iac-cdk/lib/observability-stack.ts` | `test_iac_observability_parity.py` |
| **INV-EXPORT-2** | Exported agent code CONSTRUCTS against the REAL Strands SDK. `sentinel export <harness>` is the no-lock-in promise and its whole value is that the emitted code runs — but `test_exporter.py` only proved the TEXT: valid AST, `py_compile` clean, prompt escaped, deterministic output. Every one of those is satisfied by code that calls a constructor which does not exist or passes a keyword the SDK renamed. **Syntax is not an API contract**, and INV-MCP-5 is this repo's record of that exact shape (mcp 2.0.0 removed `Server.list_tools()` while `from mcp.server import Server` kept resolving). Measured against the pinned `strands-agents[a2a,litellm]==1.9.1` the specialist containers ship: 8/8 harnesses exec and `build_agent()` returns a live `Agent` backed by a `BedrockModel`, the constructor SIGNATURES are inspected (not merely imported), and the exported MODEL_ID is checked against what the harness declares so an exporter cannot silently substitute a default. Runs in CI's `real-stack` job; skips locally because `strands` is in no extra (INV-PKG-1). INV-EXPORT-1's gate rule also gained a SINGLE implementation this round: it was an inline expression in the exporter, and this guard first re-derived it as `"approval" in name.lower()` — two definitions of a safety rule, where a gate the checker misses is a gate the export does not warn about. Now `exporter.is_hitl_gate`, with an AST scan forbidding re-derivation. | `exporter.export_harness_to_strands` · `exporter.is_hitl_gate` | `test_exported_agent_runs.py` |
| **INV-PKG-4** | The DOCUMENTED CLI works from an installed wheel, outside any checkout. Every packaging guard before this asked "is X in the artifact?" — all blind to the fact that a file being present does not mean the command works. `sentinel export <name>` is the documented no-lock-in escape hatch (README, QUICKSTART, COMPARISON); reproduced from a directory unrelated to any checkout it failed for ALL 8 harnesses, naming a real-but-empty `<site-packages>/harnesses/` path. The resolver was correct (`_REPO_ROOT` is site-packages on an installed wheel, so it looked in the right place); the DATA was missing — `packages.find.include` listed `sentinel_harness*`/`intake*`/`tools*`/`mockdata*` and not `harnesses*`. INV-MCP-2 fixed this exact shape for `registry/` and left `harnesses/` out, so it is "a fix applied to one call site is not an invariant" landing on a packaging include list. Fixed by packaging `harnesses*`; verified by RUNNING the CLI in an isolated env (8/8 export 108-143 lines of Strands code). Two things this framing established that artifact checks could not: the 6-of-8 post-fix "failures" were the 12-factor config check REFUSING an unset `${SENTINEL_GATEWAY_ARN}` — correct behaviour, now asserted as contract and documented — and exit codes were already 1 (my earlier read of 0 was `$?` clobbered by a pipe in my own probe, not a defect). QUICKSTART taught only the relative path, unusable for a pip-installing reader; it now teaches the name form FIRST, asserted by page order rather than by presence. | `pyproject.toml` packages.find · `cli._resolve_harness_path` · `docs/QUICKSTART.md` | `test_installed_cli_e2e.py` · `test_wheel_contents.py` |
| **INV-PKG-3** | The sdist ships the trees its bundled test suite reads, and CI config stays out. There was NO `MANIFEST.in`, so nobody had decided what the sdist contains — setuptools' defaults ship `tests/` automatically, so it carried all 162 test files (AT THE TIME — a historical measurement, not a current count) and **none of the trees they read**. Measured by following a downstream packager's workflow (conda-forge/Debian/Fedora all unpack the sdist and run the bundled suite): `43 errors during collection`, `FileNotFoundError` on scenarios/ specialists/ longrunning/ demo/ sentinel_inference_gateway/. The worst of two coherent options — ship no tests, or ship tests that RUN. Nothing caught it: `release.yml`'s smoke test installs `dist/*.whl` only and no test had opened the tarball. Two recorded lessons: (1) the 43 failures named 5 trees while an exhaustive scan of `REPO_ROOT / "<name>"` references found **19** — pytest abandons a module after its first error, so fixing only what failed would have broken somewhere new; the guard re-derives the list from source. (2) `.github/` deliberately stays OUT (CI config is not source, and shipping it would make a packager's build depend on our pipeline), so the guards reading it became repository-scoped through ONE asymmetric rule in `tests/repo_infra.py`: inside a git checkout a missing workflow is a FAILURE, outside one it is a skip — the alternative, each guard skipping when its file is absent, is the silent no-op INV-CI-1/INV-DOC-5/INV-PKG-1/INV-PKG-2 all record. Result: 43 collection errors -> **0 failures, 3810 passed** from the sdist. | `MANIFEST.in` · `tests/repo_infra.py` | `test_sdist_contents.py` |
| **INV-PKG-2** | The built wheel contains exactly the tools that exist on disk, and every one carries a registry decision. A locally built wheel shipped **21 handlers** while `tools/` held 20 — the extra being `tools/whitelist_optimizer/`, DELETED in the previous round's rename. Installing it put the deleted handler back on disk (verified). Cause: setuptools stages into `build/lib/` and copies FROM it without pruning removed entries, and `make clean` did not remove `build/`, so the stale copy survived every clean and rebuild. Not exposed by MCP today — INV-MCP-1's governance gate needs a registry entry and a deleted tool has none, so that gate CAUGHT it (defence in depth working) — but `SENTINEL_MCP_ALLOW_PENDING=1` bypasses the gate, and a tool removed BECAUSE of a vulnerability would silently keep shipping. Published artifacts were never affected (release builds from a fresh checkout, now asserted); the real blast radius was a local wheel differing from the released one. `test_packaging.py` could not see this: every assertion there reads `pyproject.toml` — it checks the packaging CONFIG, never an artifact. INV-MCP-2 guards the same coupling in the opposite direction ("is the registry IN the wheel?"), which is why one direction was covered and the other was not. | `Makefile` `clean`/`dist` · `build/lib/` | `test_wheel_contents.py` |
| **INV-PKG-1** | No top-level directory shadows an installed dependency's import name, and every importable top-level directory is a REGULAR package. The repo shipped `litellm/gateway/` under a top-level `litellm/` with no `__init__.py` — a NAMESPACE package — while `litellm` is also a PyPI package every specialist container installs via `strands-agents[a2a,litellm]==1.9.1`. A regular package always outranks a namespace package, so: no litellm installed -> `litellm.gateway` imports fine; litellm installed -> `ModuleNotFoundError`. Reproduced both ways. The gateway's entire purpose is to be the audited inference chokepoint a SPECIALIST points at, so it was broken in the only environment it targets, and its README's `from litellm.gateway import InferenceGateway` failed for anyone who followed it. What hid it: `strands`/`litellm` are declared in NO extra, so ten `importorskip` calls skipped in EVERY environment — one step worse than INV-CI-1, where the dep at least existed in an extra. A test that never runs cannot report a broken contract. Fixed by moving to `sentinel_inference_gateway/` (project-prefixed, since the root cause was an unprefixed top-level name), plus a CI job installing the real stack at the SAME pin the containers use, in which a skip is a FAILURE. | top-level dirs · `sentinel_inference_gateway` · `.github/workflows/ci.yml` `real-stack` job | `test_no_toplevel_name_shadows_a_dependency.py` |
| **INV-DOC-5** | The coverage-doc guard actually RUNS in CI and cannot skip there. `test_coverage_doc.py` re-measures every figure in `tests/README-coverage.md` (it exists because five of that table's rows were wrong by 16-61 points, all understating). CI's test step is `coverage run -m pytest tests`, and coverage writes `.coverage` only when it EXITS — so during the run there is no data file and those 3 assertions called `pytest.skip`. They ran on maintainer laptops (where `make ci` had already produced the file) and skipped on EVERY CI run: the guard keeping the coverage doc honest was only ever verified on the machine of the person who might let it drift. Measured, not inferred — replicating CI's exact invocation locally reproduces `SKIPPED [3]`. INV-CI-1's shape a second time, so the fix is two-part and both parts are asserted: a dedicated ci.yml step AFTER `coverage report`, and `SENTINEL_REQUIRE_COVERAGE_DATA=1` under which absent/stale data RAISES. Part 2 is what keeps the fix from decaying — a dedicated step still allowed to skip is the same failure wearing a different hat. Every unavailable-data path routes through ONE `_unavailable()` helper, asserted, because a fix applied to one call site is not an invariant. | `.github/workflows/ci.yml` · `test_coverage_doc._unavailable` | `test_coverage_doc_runs_in_ci.py` |
| **INV-CI-2** | Every test file using `pytest.mark.anyio` defines its own `anyio_backend` fixture. Omitting it does not produce "fixture not found" — pytest reports `async def functions are not natively supported` and FAILS, and an `importorskip` inside the test body never runs. It must be LOCAL rather than inherited from anyio's plugin, whose `anyio_backend` is parametrised over every installed backend and would silently run each async test twice. `test_mcp_protocol.py` had the convention (module importorskip + local fixture); `test_mcp_error_redaction.py` was written beside it and carried neither, passing locally and failing on all four CI Pythons. "A fix applied to one call site is not an invariant" — this time landing on a TESTING CONVENTION, which needs a check precisely because nobody greps for conventions. Guard carries a positive control: it fails if it finds zero async files. | tests using `pytest.mark.anyio` | `test_ci_installs_the_test_extra.py::test_every_async_test_file_pins_a_backend` |
| **INV-CI-3** | Every SHA-pinned Action's version comment names the version the SHA REALLY is. Each `uses:` in `.github/workflows/` is pinned to a 40-hex commit SHA (the supply-chain control — a tag is mutable, a SHA is not), with a human-readable version comment beside it so a reader and Dependabot can see *what* is pinned without resolving the hash. Nothing checked the comment told the truth, and it had drifted badly: `checkout` said v7.0.0 (really v7.0.1), `scorecard` v2.4.3 (really v2.4.4), `gh-release` v3.0.1 (really v3.0.2) — and two WHOLE-MAJOR lies: `setup-python` said v6.3.0 while pinned to **v7.0.0**, and all three `codeql-action` sub-actions said v3.37.0 while pinned to **v4.37.4**. Worst was `upload-artifact`: the SAME SHA was labelled v4.6.2 in two files and v7.0.1 in a third — a self-contradiction no single-file grep sees. Resolved authoritatively against the GitHub API, every SHA points at a real published tag, so the *pins* were sound and the *labels* were stale — which is worse than absent: a maintainer reads `# codeql-action v3.37.0` and believes CI runs CodeQL v3 when it runs v4. This is the "hand-written list drifting from what it mirrors" shape, on the one place the drift is a security-relevant lie about what code executes. **Two layers, because the ground truth lives on a server the suite must not call:** an OFFLINE layer (always runs, zero network) asserts every comment equals the authoritative `_AUTHORITATIVE[sha]` table, no SHA carries two labels, every pin has a comment, and the table mirrors exactly the pinned SHAs (a bumped-but-unrecorded SHA fails loudly, forcing a return to the authoritative source rather than a guess); and an ONLINE layer (opt-in `SENTINEL_VERIFY_ACTION_PINS=1`, needs `gh`) that re-resolves every SHA against GitHub to keep `_AUTHORITATIVE` from becoming its own stale list — tag labels must resolve to exactly the pinned SHA, the `release/v1` branch label must contain it. The online skip is not a pass (INV-CI-1/INV-DOC-5): the offline layer fully enforces comment/table agreement without it, and the skip reason says exactly what remains unverified. | `.github/workflows/*.yml` version comments | `test_action_pin_comments.py` |
| **INV-SUPPLY-1** | Every dependency manifest in the repo is covered by a Dependabot ecosystem AND reachable by CI's vulnerability audit. Dependabot declared three ecosystems (pip at the root, npm under `iac-cdk/`, github-actions) while the repo also ships **five container manifests** — `specialists/{adversarial-reviewer,attack-mapper,cve-intel,threat-hunt}/requirements.txt` and `longrunning/bas-runner/requirements.txt` — plus a Dockerfile beside each. Those are the deps that run in the DEPLOYED Runtime images, and they were patched by nobody and audited by nothing: Dependabot's entire commit history in this repo touches only `.github/workflows/` (every commit that ever changed a container requirements.txt is a human one, including `3e1dacf`, a manual "bump bedrock-agentcore across all 4 specialists"), and `pip-audit` built its audit set from `pyproject.toml`'s `project.dependencies` alone. Measured consequence: each of the four specialists carried **19 known advisories in 2 packages** — `litellm` (12) and `starlette` (7) — both TRANSITIVE via `strands-agents[a2a,litellm]==1.9.1` and `fastapi==0.139.0`, so neither was visible as a line in any file. `longrunning/bas-runner` came back clean, the negative control proving the audit discriminated rather than reporting red for everything. Fixed in three places: `directories:`-based pip + docker Dependabot entries covering all five (grouped into one PR because `test_specialist_containers.py` asserts the four specialists ship a byte-identical set, so staggered PRs would each break that invariant); a BLOCKING container-audit step in `supply-chain.yml` whose loop propagates per-file failure (`exit $status` — a loop swallowing the code would print advisories and still report green); and the upgrade itself to `strands-agents==1.50.2` / `fastapi==0.141.1`, verified to pull `litellm 1.91.1` + `starlette 1.4.1` and to keep all six APIs the code imports (`Agent`, `LiteLLMModel`, `A2AServer`, `MCPClient`, `BedrockAgentCoreApp`, `mcp.server.Server`) plus INV-MCP-5's 1.x decorator surface — 19 advisories to **0**, re-measured by running CI's actual loop. Also removed the SIXTH copy of one fact: `ci.yml`'s `real-stack` job re-typed `strands-agents==1.9.1` under a comment claiming it was "the SAME version the specialist containers pin" — a claim, not a fact, and already stale, so the job verifying the shipped stack verified a version nothing shipped; it now installs `-r specialists/cve-intel/requirements.txt`, the INV-CI-1 fix applied again. Recorded method failure: the audit-coupling assertion first asked `"requirements.txt" in text` and passed **vacuously** — pip-audit's own step writes a temp `audit-requirements.txt`, so the substring was satisfied while the container audit did not exist; it now parses the YAML and requires a pip-audit invocation naming a real `(specialists\|longrunning)/…/requirements.txt`. A substring standing in for a structural question, this time inside the guard written to catch it. Vulnerability freedom is deliberately NOT asserted offline (it needs a live advisory DB and would make the suite time-dependent); the offline guard asserts nothing is left OUT of the audit's reach. | `.github/dependabot.yml` · `.github/workflows/supply-chain.yml` · `specialists/*/requirements.txt` | `test_dependabot_covers_every_manifest.py` |
| **INV-CI-4** | Every CI job bounds its runtime, and `concurrency` is decided per workflow SEMANTICS rather than uniformly. Two runtime protections were missing across all six workflows. **(1)** No job declared `timeout-minutes` — all 14 inherited GitHub's default of **360 minutes**, so a hung job (a network read with no timeout, a test waiting on a lock, an `npm install` against a degraded registry) would hold a runner for six hours; on a public repo that is the whole concurrency budget, so one wedged job blocks every other PR's CI. Values are calibrated to MEASURED durations from five real runs, not guessed: `test` 321-345s -> 15min, `codeql analyze` 65-94s -> 20, `iac` 74-88s -> 10, `real-stack` 57-63s -> 10, `pip-audit` 25-90s -> 15 (it grew when the container audit landed, INV-SUPPLY-1), `mypy` 20s -> 10, `bandit` 13s -> 5, `secret-and-name scan` 5s -> 3. The guard asserts each timeout stays within 2x-40x its measured seconds, because a tolerance is calibrated to a MAGNITUDE — INV-DOC-9 records the cost of borrowing one across magnitudes — so too tight turns variance into flakes and too loose is decoration. That band immediately caught two of my own values (bandit 10min = 46x, secret-scan 5min = 60x), which were tightened rather than the guard being relaxed. **(2)** Five of six workflows had no `concurrency` block, so superseded runs kept going — pushing twice to a PR ran the full matrix twice while only the last verdict was ever read. Crucially this is NOT a uniform fix: `ci`/`codeql`/`supply-chain`/`scorecard` cancel, but **`release.yml` must NEVER cancel**. It publishes, and cancelling midway leaves a state no retry cleanly repairs — a GitHub Release created and tagged while PyPI never received the upload, or an attestation signed for artifacts that were never published. Two tags pushed in quick succession is exactly when `cancel-in-progress: true` would fire, i.e. precisely when it does the most damage; so release groups by tag (serialising a re-run of the same tag) with `cancel-in-progress: false`, and that asymmetry is asserted because "add concurrency everywhere" is the obvious cleanup that would break it. **A negative result, recorded so it is not tidied up:** `docs.yml` keys its group on the literal `pages` with no `github.ref`, so in principle a PR's docs build can cancel main's in-flight Pages deployment. Adding a ref is wrong twice — measured across 40 historical docs runs (19 push/main + 21 pull_request) the conclusion was `success` every time, **zero cancellations**, and a global group is the POINT since Pages deployment is a singleton and keying on ref would PERMIT the concurrent deploys the single group prevents. The exemption therefore has its own guard (the group must stay ref-independent), the rule this repo applies to lint-excluded directories applied to a config exception. Also **verified and deliberately left alone**: permissions were ALREADY least-privilege — every workflow declares top-level `contents: read` (or `read-all`) and only the four jobs needing more widen it themselves — so this round changed nothing there, but the property is now asserted in both directions (no top-level write; the set of write-scoped jobs matches a recorded map) since a future job could otherwise quietly inherit write access. Guard mutation-tested 9/9, including the two dangerous cleanups. | `.github/workflows/*.yml` job timeouts · concurrency · permissions | `test_workflow_runtime_guards.py` |
| **INV-SUPPLY-2** | A version bound that exists for a BREAKAGE is declared where Dependabot reads it. `mcp>=1.0,<2` was stated in three places — a long `pyproject.toml` comment, INV-MCP-5 in this document, and `test_mcp_version_bound.py` — and **Dependabot reads none of them**, so it proposed lifting the bound twice in one week: **PR #59** widened `pyproject.toml` to `mcp>=1.0,<3`, and **PR #60** — the very first PR produced by the container coverage added in INV-SUPPLY-1 — pinned all four DEPLOYED specialists to `mcp==2.0.0`. Both re-verified against the real 2.0.0 release rather than trusted from the record, because a bound whose evidence has expired is worse than no bound: `from mcp.server import Server` still imports (an import check is not a compatibility check — INV-MCP-5's own recorded lesson), but `Server.list_tools` / `.call_tool` are GONE and `create_server()` raises `AttributeError: 'Server' object has no attribute 'list_tools'`, so `sentinel mcp serve` cannot start. The part that could have been missed: that is the SERVER surface, which the specialists never touch — they use the CLIENT surface, so "the same bound applies" was an assumption needing its own measurement. It held for an INDEPENDENT reason: `from mcp.client.streamable_http import streamablehttp_client` also raises ImportError on 2.0, and all four `specialists/*/agent_a2a.py` import it to reach the Gateway. **Two separate breakages behind one version number**, and PR #60 would have shipped both into the containers. Fixed by declaring the bound in `.github/dependabot.yml` with its evidence and its lift procedure — generalising what `iac-cdk`'s TypeScript bound already did right (INV-IAC), i.e. "a fix applied to one call site is not an invariant" applied to a supply-chain declaration. The non-obvious detail the guard encodes: **`ignore` is PER-UPDATE-BLOCK, not global**, so the root `pip` entry's ignore does not cover the container `pip` entry — which is exactly why PR #60 existed — and a guard checking only "mcp is ignored somewhere" would have passed while the dangerous PR was open. So every block of the relevant ecosystem is checked. Also asserted: each ignore must carry a VERSION RANGE (a bare `ignore: mcp` silently blocks 1.x security patches too, turning a compatibility bound into an unmaintained dependency), the pyproject bound and the ignore must describe the SAME boundary (widening to `<3` while the ignore stays at `>=2.0.0` is the worst combination — the repo permits a version Dependabot has stopped warning about), and the file must record HOW to re-verify so the bound can be lifted deliberately rather than becoming permanent by default. Mutation-tested 7/7, including the exact PR #59 and PR #60 conditions. | `.github/dependabot.yml` ignore blocks · `pyproject.toml` bounds | `test_breaking_bounds_are_told_to_dependabot.py` |

---

## INV-TICKET / INV-TRACE / INV-METRIC — the write path, the tracer, the meter

Three more zero-invariant modules, one finding each. None gates promotion; each is a way
the system misreports or leaks.

| ID | Invariant | Owner | Enforced by |
|---|---|---|---|
| **INV-TICKET-1** | The tracker URL is never echoed into a response. `handler` maps a backend exception's text straight into the response `message`, and `_create_live` raised `... POST to {url!r} ...`. The module's own docstring promises the API key is "never returned in responses", and a tracker URL routinely carries a token in the query string or userinfo — reproduced, a `token=...` param came back to the caller. Only `scheme://host[:port]`, userinfo stripped, is named. | `create_ticket._safe_endpoint` | `test_create_ticket.py::test_url_credential_is_not_echoed` |
| **INV-TRACE-1** | A span pops the stack BEFORE emitting, and a raising sink cannot corrupt nesting or mask the traced error. `self._emit(record)` ran before `self._stack.pop()`, so a sink that raised (a throttled `PutLogEvents` suffices) skipped the pop: the span's id stayed on the stack and every later sibling was mis-parented under it, while the sink's exception replaced the exception the span was tracing. Reproduced. Pop is now first, emit is isolated in a try/except that reports out-of-band. Telemetry must not alter control flow or the trace it records. | `tracing.Tracer.span` | `test_tracing.py::test_a_raising_sink_does_not_corrupt_nesting`, `::test_a_raising_sink_does_not_mask_the_body_error` |
| **INV-METRIC-1** | A metered metric is emitted as a BARE top-level JSON line. CloudWatch's `FilterPattern.exists("$.tokens")` matches only a message that IS a JSON object (first char `{`), but `core.metered_invoke` defaulted its sink to a text logger that prepended `INFO sentinel_harness.telemetry: ` — so no metered metric ever matched the filter and no metric or alarm fired. Reproduced. A dedicated `get_metric_sink` writes the line verbatim, no level/logger envelope. | `logutil.get_metric_sink` / `core.metered_invoke` | `test_observability.py::test_metric_sink_emits_bare_json`, `test_logutil.py::test_metric_sink_has_no_envelope` |

### INV-COERCE has one implementation now (round 20)

Three of the round-20 findings were the string-truthiness trap (`bool("false") is True`)
on an external boolean: a judge's pass flag (`observability.emit_eval_score`), a gateway
header-passthrough flag (`gateway.lambda_interceptor`). The canonical coercer moved to
`logutil.coerce_bool` — the lowest-level, zero-dependency module — so observability,
gateway and `connectors.base` all delegate to the SAME function object rather than three
copies that agree until one is edited. It could not live in `connectors.base` (its old
home) because that module pulls in every backend, so a low-level caller importing it
created a cycle. `test_r17_coercion_mechanized.py::TestLocalCoercionHelpersAgree::test_the_canonical_coercer_has_one_implementation`
pins the single-object identity.
