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

## INV-WL — a synthesized whitelist suppresses only the FP cohort

The whitelist_optimizer GENERATES a Sigma filter. A generated suppression rule
that matches more than its FP cohort actively turns OFF a working detection — the
most dangerous outcome in the suite.

| ID | Invariant | Owner | Enforced by |
|---|---|---|---|
| **INV-WL-1** | A filter is never synthesized from a value carrying a Sigma metacharacter (`*` `?` `'` `"` `\`). The TP guard compares literally, but the emitted Sigma is read with `*`/`?` as live wildcards — so `process_name: 'a*.exe'` would glob-suppress the very TP it certified as preserved. Such a field is refused. | `whitelist_optimizer._has_unsafe_char` | `test_r12_semantic_gates.py::TestWhitelistNeverSuppressesBeyondCohort` |
| **INV-WL-2** | A domain-suffix whitelist must extend below the public-suffix boundary (a private registrable domain). `co.uk` / `blob.core.windows.net` are refused — whitelisting them suppresses an entire shared registrar space. A weak context field (port / user / host) is never a sole discriminator; a /48 IPv6 block and an n=1 class generalization are refused. | `whitelist_optimizer._is_public_suffix` / `_WEAK_FIELDS` / `_discriminator_for_field` | `test_r12_semantic_gates.py::TestWhitelistNeverSuppressesBeyondCohort` |
| **INV-WL-3** | A true-positive guard that LACKS the whitelisted field fails CLOSED: absence of evidence is not evidence of safety, so the field is refused rather than certified TP-preserving. | `whitelist_optimizer.handler` (tp_unprovable) | `test_r12_semantic_gates.py::TestWhitelistNeverSuppressesBeyondCohort::test_tp_missing_the_whitelisted_field_fails_closed` |

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
