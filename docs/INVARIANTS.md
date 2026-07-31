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
| **INV-GOV-3** | The provenance ledger is append-only and hash-chained; any edit to a record or its linkage fails verification. | `provenance.verify_ledger` | `test_provenance.py` |

---

## INV-DOC — the docs cannot drift

| ID | Invariant | Owner | Enforced by |
|---|---|---|---|
| **INV-DOC-1** | Every public export carries a docstring, and the public surface never silently regresses. | `sentinel_harness/__init__.py` | `test_docs_drift.py` |
| **INV-DOC-2** | Counts quoted in the docs (tests, tools, evidence, scenarios) match reality, and never contradict each other between files. | docs + `tests/` | `test_docs_drift.py::test_quoted_counts_match_reality` |
| **INV-DOC-3** | Every test named in this file exists. | this file | `test_invariants_doc.py` |
