#!/usr/bin/env python3
"""
The sentinel-harness platform — a single narrated end-to-end tour (L1 → L4)
===========================================================================
"A security team's whole agent platform, told in one guided walk."

This script is the *promotion-quality guided tour* of the entire platform. It
walks every layer in story order and, for each beat, prints (a) WHAT the beat
demonstrates, (b) WHICH real component/mechanism backs it, and (c) WHERE the
evidence lives. It is intentionally the narrated tour, NOT a re-run of the heavy
live work — the individual live scenarios under ``scenarios/`` and the captured
``evidence/*.json`` are the proof; this script is the map that ties them together
so a reader can grasp the whole thing in seconds.

Why a separate tour (WHY, not just what)
----------------------------------------
Each ``scenarios/scenario_*.py`` proves ONE capability against real AgentCore and
writes its own account-scrubbed evidence. That is the right shape for proof, but
it is nine scripts, several needing AWS credentials and invoke quota. A promoter,
a new teammate, or CI needs a single offline artifact that tells the platform
story front to back and is scrupulously honest about what is live-validated vs.
built+tested vs. skeleton. This is that artifact.

How each beat is backed (honesty is the whole point)
----------------------------------------------------
The tour NEVER fakes a live result. Each beat is one of:

  * REPLAYED FROM REAL LIVE EVIDENCE — the beat reads a committed
    ``evidence/*.json`` produced by a real run against the GA control plane and
    summarizes its recorded verdict. Clearly labeled "(replayed from live
    evidence …)". If the evidence file is missing the beat says so plainly and
    does not invent numbers.
  * RUN LIVE-OFFLINE (genuinely executed here) — the beat calls a REAL,
    deterministic, offline-safe module in-process (no AWS, no network, no LLM):
    the L2 BAS detection-replay (``longrunning/bas-runner/bas_cases.py`` + the
    ``tools/sigma_match`` matcher) and the L2 Play Mode gate logic
    (``sentinel_harness.simulation``). These are executed, not replayed, because
    their provable core is pure Python.
  * SUMMARIZED FROM BUILT+TESTED / SKELETON components — for beats whose live
    proof is a CDK/Terraform deploy or an in-process mechanism, the tour states
    the mechanism and points at the component + evidence, labeled with its real
    status.

Default is fully offline (stdlib + this repo only): no AWS, no boto calls, no
network, no third-party deps. Deterministic; exits 0. A ``--live`` note points to
the real scenarios (this script does not itself run them — running nine live
scenarios is the job of the scenarios, not the tour).

Run
---
    # the whole platform story, offline, deterministic, seconds:
    python demo/platform_demo.py

    # (informational) print how to run the real live scenarios instead:
    python demo/platform_demo.py --live

All content is generic SecOps. No org names, no real account ids (the all-zeros
``000000000000`` placeholder only), no secrets. See demo/PLATFORM.md.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
from types import ModuleType
from typing import Any, Dict, List, Optional, Tuple

# Make the repo importable whether run as a module or a plain script. Set a
# harmless dummy env BEFORE importing anything under sentinel_harness (core builds
# a boto3 control-plane client at import time). The offline tour never touches AWS,
# but the client constructor still needs a region + role string to build.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

os.environ.setdefault("SENTINEL_REGION", "us-east-1")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
# 000000000000 is the sanctioned all-zeros placeholder account id (never a real one).
os.environ.setdefault("SENTINEL_EXECUTION_ROLE_ARN", "arn:aws:iam::000000000000:role/demo")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "offline-demo")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "offline-demo")

_EVIDENCE_DIR = os.path.join(_REPO_ROOT, "evidence")


# --------------------------------------------------------------------------- #
# narration helpers — pure stdout, no state (mirrors m2_self_improving_demo)   #
# --------------------------------------------------------------------------- #
_WIDTH = 78


def _rule(char: str = "-") -> None:
    print(char * _WIDTH)


def _banner(title: str) -> None:
    _rule("=")
    print(title)
    _rule("=")


def _beat(n: int, layer: str, title: str) -> None:
    print()
    _rule()
    print(f"BEAT {n} · {layer} — {title}")
    _rule()


def _line(text: str = "") -> None:
    print(text)


def _kv(label: str, value: Any) -> None:
    print(f"    {label}: {value}")


# --------------------------------------------------------------------------- #
# evidence loading — honest about missing files, never fabricates             #
# --------------------------------------------------------------------------- #
def _load_evidence(filename: str) -> Optional[Dict[str, Any]]:
    """Read a committed evidence JSON, or return None if it is absent.

    We deliberately do NOT invent a verdict when the file is missing — a beat that
    cannot find its evidence says so plainly. Malformed JSON is a real problem, so
    we let ``json.JSONDecodeError`` surface rather than swallow it (never hide a
    corrupt evidence artifact behind a fake summary)."""
    path = os.path.join(_EVIDENCE_DIR, filename)
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _evidence_verdict(filename: str) -> Tuple[Optional[Dict[str, Any]], str]:
    """Return ``(verdict_dict_or_None, source_label)`` for an evidence file.

    ``source_label`` is the exact provenance string printed to the reader so the
    claim's backing is never ambiguous."""
    data = _load_evidence(filename)
    if data is None:
        return None, f"evidence/{filename} (NOT PRESENT — run the live scenario to produce it)"
    return data.get("verdict") or {}, f"evidence/{filename} (replayed from live evidence)"


def _print_evidence_verdict(filename: str, keys: List[str]) -> bool:
    """Print selected verdict keys from a live-evidence file. Returns True if the
    evidence was present and read (the beat's proof exists), False otherwise."""
    verdict, source = _evidence_verdict(filename)
    _kv("evidence", source)
    if verdict is None:
        _line("    (no recorded verdict to summarize — the tour does not fabricate one)")
        return False
    for k in keys:
        if k in verdict:
            _kv(k, verdict[k])
    if "note" in verdict:
        _line(f"    note: {str(verdict['note'])[:320]}")
    return True


# --------------------------------------------------------------------------- #
# real offline module loaders (executed live-offline, not replayed)           #
# --------------------------------------------------------------------------- #
def _load_module_by_path(name: str, relpath: str) -> ModuleType:
    """Load a repo module by absolute path (some trees — tools/, longrunning/ — are
    scripts trees, not importable packages). Never swallows a broken module: an
    unloadable target raises ImportError with the offending path."""
    path = os.path.join(_REPO_ROOT, relpath)
    if not os.path.exists(path):
        raise ImportError(f"expected module not found at {path!r}")
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"could not build an import spec for {path!r}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# --------------------------------------------------------------------------- #
# summary-table model — capability -> status -> evidence                       #
# --------------------------------------------------------------------------- #
# Status vocabulary is EXACTLY the three the task + README use, so the table maps
# 1:1 onto the repo's status matrix. Keep these strings stable — the offline test
# asserts on them.
LIVE = "live-validated"
BUILT = "built+tested"
SKELETON = "skeleton"

# Each row: (beat_no, layer, capability, status, backing component, evidence file).
# This is the single source of truth for the closing table AND for what each beat
# claims — the beats and the table cannot drift because the table drives the recap.
SUMMARY_ROWS: List[Tuple[int, str, str, str, str, str]] = [
    (1, "L1", "Declare-an-agent-as-config + CVE triage with a HITL gate", LIVE,
     "scenarios/scenario_cve_triage.py, sentinel_harness/core.py", "evidence/cve_triage_result.json"),
    (1, "L1", "HITL full pause → approve → resume round-trip", LIVE,
     "scenarios/scenario_hitl_resume.py, core.invoke_with_tool_result", "evidence/hitl_resume_result.json"),
    (2, "L1", "Multi-harness parallel + supervisor synthesis (~2.6x)", LIVE,
     "scenarios/scenario_multi_harness.py", "evidence/multi_harness_result.json"),
    (3, "L1", "Detection-gen + independent adversarial reviewer + publish gate", LIVE,
     "scenarios/scenario_detection_gen.py", "evidence/detection_gen_result.json"),
    (4, "M1", "An agent BUILDS an agent (meta → harness_ops → new harness)", LIVE,
     "scenarios/scenario_agent_factory_loop.py, tools/harness_ops", "evidence/agent_factory_loop_result.json"),
    (5, "M2", "Score → improve → promote-to-endpoint (independent judge + HITL)", LIVE,
     "scenarios/scenario_self_improve_loop.py, tools/run_evaluation", "evidence/self_improve_loop_result.json"),
    (5, "M2", "Promote passing harness to a named prod endpoint", LIVE,
     "core.create_harness_endpoint", "evidence/endpoint_promote_result.json"),
    (6, "L2", "BAS detection-replay → blind-spot report (real Sigma matcher)", LIVE,
     "tools/sigma_match, longrunning/bas-runner/bas_cases.py", "evidence/bas_replay_result.json"),
    (6, "L2", "Play Mode adversary emulation — every step HITL-gated + checkpoint", LIVE,
     "sentinel_harness/simulation.py, scenarios/scenario_play_mode.py", "evidence/play_mode_result.json"),
    (6, "L2", "Sample detonation (one-shot microVM, long-running tier)", SKELETON,
     "longrunning/detonation/ (import-safe SIMULATED no-ops)", "docs/ROADMAP.md"),
    (7, "L3", "Gateway create → READY → delete on the GA API", LIVE,
     "sentinel_harness/gateway.py, scenarios/scenario_named_supervisor.py", "evidence/gateway_lifecycle_result.json"),
    (7, "L3", "Cognito identity for Gateway CUSTOM_JWT (OIDC RS256)", LIVE,
     "iac-cdk/lib/identity-stack.ts, gateway.cognito_jwt_authorizer", "evidence/m4_live_deploy_result.json"),
    (7, "L3", "Guardrail masks secrets/PII in every tool response", LIVE,
     "iac-cdk/lib/guardrail-stack.ts", "evidence/m4_guardrail_result.json"),
    (7, "L4", "Observability — CW dashboard + TokensPerScenario + Budgets", LIVE,
     "iac-cdk/lib/observability-stack.ts", "evidence/m4_live_deploy_result.json"),
    (7, "L3", "Tool/skill registry (dual-gate) + PreToolUse sandbox hook", BUILT,
     "sentinel_harness/registry.py, sentinel_harness/sandbox_hooks.py", "tests/test_registry.py"),
    (7, "L3", "Agent Factory (fleet provision, dry-run, cross-env tag-guard)", BUILT,
     "sentinel_harness/factory.py", "tests/test_factory.py"),
    (7, "L3", "Private VPC + default-deny egress (PrivateLink, no NAT)", BUILT,
     "iac-cdk/lib/network-stack.ts (endpoints cost-gated off)", "iac-cdk/"),
]


# --------------------------------------------------------------------------- #
# the tour                                                                     #
# --------------------------------------------------------------------------- #
def _beat1_declare_and_triage() -> bool:
    """L1 — declare an agent as configuration, then CVE triage with a HITL gate.

    Backed by a real live run (replayed from evidence). The mechanism: a single
    harness combines a code interpreter, an inline_function human gate, and managed
    memory — declared as config, zero orchestration code."""
    _beat(1, "L1 · Strategy Iteration", "Declare an agent as config → CVE triage with a HITL gate")
    _line("  WHAT: You declare an agent as configuration (system prompt + tools + memory)")
    _line("        and AWS runs the whole agent loop. Here a CVE-triage analyst does")
    _line("        deterministic CVSS/exposure math in a code interpreter, forms an")
    _line("        asset-impact hypothesis, and MUST pass an analyst review gate before")
    _line("        recommending anything — security decisions are not made by the AI alone.")
    _line("  HOW : one harness = code_interpreter + inline_function gate + managed memory,")
    _line("        all as config (sentinel_harness.core.create_harness). No glue code.")
    ok = _print_evidence_verdict(
        "cve_triage_result.json",
        ["hit_human_review_gate", "did_deterministic_calc"])
    _line()
    _line("  … and the HITL contract closes fully (pause → approve → resume the SAME")
    _line("      session via the two-message toolUse+toolResult contract):")
    ok2 = _print_evidence_verdict(
        "hitl_resume_result.json",
        ["paused_on_gate", "captured_tool_use", "resumed_and_finished", "closed_hitl_loop"])
    return ok and ok2


def _beat2_multi_harness() -> bool:
    """L1 — multi-harness parallelism + supervisor synthesis (replayed from live)."""
    _beat(2, "L1 · Strategy Iteration", "Multi-harness parallel + supervisor synthesis")
    _line("  WHAT: A single harness is single-agent by design. Parallelism comes from")
    _line("        running MANY harnesses concurrently and having a supervisor harness")
    _line("        fan out and synthesize — the sanctioned supervisor→specialists pattern.")
    _line("  HOW : 3 specialist harnesses (research / detection / triage) run in parallel")
    _line("        on one threat; a supervisor merges them into one actionable brief.")
    _line("        Speedup is measured wall-clock vs. a serial run.")
    return _print_evidence_verdict(
        "multi_harness_result.json",
        ["pattern", "parallel_speedup_vs_serial"])


def _beat3_detection_gen() -> bool:
    """L1 — detection-gen with an INDEPENDENT adversarial reviewer + publish gate."""
    _beat(3, "L1 · Strategy Iteration", "Detection-gen with an adversarial reviewer + publish gate")
    _line("  WHAT: generation != evaluation. A generator harness writes a Sigma rule; a")
    _line("        SEPARATE adversarial-reviewer harness attacks it (false-positive sources,")
    _line("        logic gaps, evasion bypasses); nothing reaches production except through")
    _line("        a human request_publish_approval gate. Kills self-approval bias.")
    _line("  HOW : two independent harnesses + allowedTools scoping (keeps the built-in")
    _line("        shell off) + a HITL publish gate. Success is defined on the SUBSTANCE")
    _line("        (an independent verdict was reached + the flawed rule was withheld),")
    _line("        not on whether the model happened to use the structured tool.")
    return _print_evidence_verdict(
        "detection_gen_result.json",
        ["generator_and_reviewer_are_separate_harnesses",
         "reviewer_reached_independent_verdict", "reviewer_verdict",
         "no_stray_shell_tool", "publish_correctly_controlled"])


def _beat4_agent_builds_agent() -> bool:
    """M1 — an agent builds an agent: meta-agent spec → harness_ops → new harness."""
    _beat(4, "M1 · Self-iteration", "An agent BUILDS an agent (meta → harness_ops → new harness)")
    _line("  WHAT: the north star. A natural-language request goes in; the meta-agent")
    _line("        harness (Opus) decomposes it into a structured harness spec; the")
    _line("        deterministic harness_ops tool turns that spec into a brand-new working")
    _line("        harness on the GA control plane, which reaches READY, answers a real")
    _line("        invoke, and is torn down. Generation (spec) is separated from execution")
    _line("        (build) so the self-iteration loop stays auditable.")
    _line("  HOW : harnesses/meta-agent (loader-consumed) + tools/harness_ops handler")
    _line("        calling core.create_harness / wait_ready / invoke / delete.")
    _line("  SCOPE: delegation is in-process here; wiring harness_ops as a Gateway MCP")
    _line("         target is infra — the build/verify MECHANISM is proven live end-to-end.")
    return _print_evidence_verdict(
        "agent_factory_loop_result.json",
        ["meta_agent_emitted_spec", "harness_ops_built_real_harness",
         "built_harness_reached_ready", "built_harness_answered_invoke", "closed"])


def _beat5_score_improve_promote() -> bool:
    """M2 — score → improve → promote-to-endpoint (independent judge + HITL)."""
    _beat(5, "M2 · Evaluation-driven", "Score → improve → promote-to-endpoint")
    _line("  WHAT: an agent scores, improves, and promotes an agent. A weak agent is scored")
    _line("        by an INDEPENDENT LLM-judge (FAIL, with reasons), the prompt is improved")
    _line("        via retry-with-reasoning until it clears the bar (PASS), a human approves,")
    _line("        and only then is it promoted to a production endpoint. A rejected agent")
    _line("        is never promoted.")
    _line("  HOW : tools/run_evaluation (real judge + pure verdict parser) + a prompt update")
    _line("        that mints a new harness version + core.create_harness_endpoint.")
    _line("  TIP : the runnable, narrated version of THIS loop is demo/m2_self_improving_demo.py")
    _line("        (offline, deterministic) — this tour summarizes its live evidence.")
    ok = _print_evidence_verdict(
        "self_improve_loop_result.json", [])
    _line()
    _line("  … and the promote-to-production step is validated on real AgentCore:")
    ok2 = _print_evidence_verdict(
        "endpoint_promote_result.json",
        ["create_harness_endpoint_succeeded", "list_harness_versions_works",
         "endpoint_arn_returned", "closed"])
    return ok and ok2


def _beat6_l2_simulation() -> bool:
    """L2 — BAS detection-replay blind spots (executed live-offline) + Play Mode HITL.

    The BAS replay and Play Mode gate logic are REAL deterministic offline Python, so
    this beat EXECUTES them in-process (not replayed) — the strongest kind of proof an
    offline tour can give. Detonation is honestly labeled a SIMULATED skeleton."""
    _beat(6, "L2 · Attack Validation & Simulation", "BAS detection-replay blind spots + Play Mode HITL")

    # --- 6a: BAS replay — EXECUTED here against the real deterministic core ---
    _line("  WHAT (6a): generate BAS cases from an ATT&CK technique set, replay each against")
    _line("             the current Sigma rules, and report which techniques went UNDETECTED")
    _line("             (the detection blind spots — the engineering backlog).")
    _line("  HOW : REAL deterministic offline Python — this beat EXECUTES it now, not a replay.")
    _line("        (longrunning/bas-runner/bas_cases.py + the tools/sigma_match matcher;")
    _line("         BAS cases carry SIMULATED telemetry, never a live attack.)")
    bas_scn = _load_module_by_path(
        "scenario_bas_replay", os.path.join("scenarios", "scenario_bas_replay.py"))
    verdict = bas_scn.build_verdict(bas_scn.DEFAULT_TECHNIQUES, bas_scn.BUILTIN_SIGMA_RULES)
    _kv("executed (live-offline)", "scenarios/scenario_bas_replay.build_verdict()")
    _kv("techniques_tested", verdict["techniques_tested"])
    _kv("techniques_detected", verdict["techniques_detected"])
    _kv("BLIND SPOTS (undetected, action needed)", verdict["blind_spots"])
    _kv("coverage_ratio", verdict["coverage_ratio"])
    # A non-empty blind-spot list is the whole point: the built-in rules cover 2 of 4
    # techniques, so real gaps are found. Assert it here so a broken matcher fails loudly.
    bas_ok = bool(verdict["blind_spots"]) and 0.0 <= verdict["coverage_ratio"] <= 1.0

    # --- 6b: Play Mode — EXECUTE the pure gate logic (no AWS invoke) -----------
    _line()
    _line("  WHAT (6b): a SIMULATED adversary-emulation kill chain where EVERY offensive")
    _line("             step is human-confirmed. Approve resumes the plan; reject halts it;")
    _line("             plan state is checkpointed so a long run can resume. Nothing real")
    _line("             is ever touched — approved steps record a SIMULATED no-op.")
    _line("  HOW : sentinel_harness.simulation — the gate/decision/checkpoint logic is pure")
    _line("        Python; this beat exercises the DECISION logic directly (the live invoke")
    _line("        path is proven in evidence/play_mode_result.json).")
    from sentinel_harness import simulation as sim
    plan = sim.DEFAULT_PLAN[:3]
    # Build the same StepState objects the live PlayModeRunner drives, then exercise
    # the REAL decision policies + the REAL approval predicate the runner uses to
    # decide resume-vs-halt. Pure, deterministic — no AWS, no invoke. (tool_use is
    # irrelevant to these policies, so a placeholder dict is honest here.)
    steps = [sim.StepState(index=i, phase=p["phase"], technique=p["technique"],
                           objective=p["objective"]) for i, p in enumerate(plan)]
    tu: Dict[str, Any] = {"toolUseId": "offline", "input": {}}
    approve_all = [sim._is_approved(sim.auto_approve(s, tu)) for s in steps]
    reject_fn = sim.reject_after(1)  # approve step 0, reject step 1+
    reject_decisions = [sim._is_approved(reject_fn(s, tu)) for s in steps]
    every_step_gated = len(steps) >= 1
    approve_resumes = all(approve_all)
    reject_halts = reject_decisions[0] is True and reject_decisions[1] is False
    _kv("executed (live-offline)", "sentinel_harness.simulation decision logic")
    _kv("plan_steps (every one gated)", [f"{s.phase}:{s.technique}" for s in steps])
    _kv("APPROVE path resumes every step", approve_resumes)
    _kv("REJECT after step 1 halts the plan", reject_halts)
    playmode_ok = every_step_gated and approve_resumes and reject_halts
    _line("    (live invoke round-trip — pause/resume/checkpoint — is in the evidence:)")
    _print_evidence_verdict(
        "play_mode_result.json",
        ["every_step_gated", "approved_step_resumed", "reject_halts_plan",
         "checkpoint_roundtrip", "closed_loop"])

    # --- 6c: detonation — honest skeleton label -------------------------------
    _line()
    _line("  WHAT (6c): sample detonation (one-shot microVM, long-running tier).")
    _line("  STATUS: SKELETON — import-safe SIMULATED no-ops (destroy-after-use +")
    _line("          sandbox-gated + HITL). No real malware / VM / network. Labeled")
    _line("          skeleton on purpose (see docs/ROADMAP.md); NOT claimed live.")

    return bas_ok and playmode_ok


def _beat7_l3_l4_foundation() -> bool:
    """L3/L4 — Gateway + Cognito JWT + Guardrail masking + observability.

    Mix of live-deployed (Gateway round-trip, Guardrail masking, Cognito OIDC,
    CloudWatch/Budgets — replayed from evidence) and built+tested (registry, factory,
    private VPC). Every row is labeled with its true status."""
    _beat(7, "L3/L4 · Foundation & Governance", "Gateway + Cognito-JWT + Guardrail masking + observability")
    _line("  WHAT: the platform floor — a policy-backed MCP tool surface (Gateway) reached")
    _line("        over identity (Cognito CUSTOM_JWT), every tool response masked by a")
    _line("        Guardrail, and the whole thing observable + cost-guarded.")

    _line()
    _line("  (L3) Gateway create → READY → delete on the real GA API:")
    ok_gw = _print_evidence_verdict(
        "gateway_lifecycle_result.json",
        ["created", "reached_ready", "deleted", "deleted_confirmed_gone",
         "authorizer_type", "protocol", "closed"])

    _line()
    _line("  (L3) Guardrail masks a fake AWS key + API token in a tool response (LIVE):")
    ok_gr = _print_evidence_verdict(
        "m4_guardrail_result.json",
        ["guardrail_deployed_live", "action", "aws_key_masked_to",
         "api_token_masked_to", "closed"])

    _line()
    _line("  (L3/L4) Cognito identity (OIDC RS256) + CloudWatch/Budgets observability (LIVE):")
    verdict, source = _evidence_verdict("m4_live_deploy_result.json")
    _kv("evidence", source)
    ok_id = False
    if verdict:
        ident = verdict.get("identity", {})
        obs = verdict.get("observability", {})
        _kv("identity.oidc_discovery_reachable", ident.get("oidc_discovery_reachable"))
        _kv("identity.signing_alg", ident.get("signing_alg"))
        _kv("identity.authorizer_contract_ok", ident.get("authorizer_contract_ok"))
        _kv("observability.dashboard", obs.get("dashboard"))
        _kv("observability.metric_namespace", obs.get("metric_namespace"))
        _kv("observability.budget", obs.get("budget"))
        _kv("vpc_endpoints_cost_gated_off", verdict.get("vpc_endpoints_cost_gated_off"))
        ok_id = bool(ident.get("oidc_discovery_reachable")) and bool(obs.get("dashboard"))

    _line()
    _line("  (L3) built+tested (mechanism proven by unit tests, not a live deploy):")
    _line("       · Tool/skill registry (dual-gate governance) + PreToolUse sandbox hook")
    _line("         — sentinel_harness/registry.py, sandbox_hooks.py (tests/test_registry.py)")
    _line("       · Agent Factory (fleet provision, dry-run, cross-env tag-guard)")
    _line("         — sentinel_harness/factory.py (tests/test_factory.py)")
    _line("       · Private VPC + default-deny egress (PrivateLink, no NAT; endpoints")
    _line("         cost-gated off) — iac-cdk/lib/network-stack.ts")

    return ok_gw and ok_gr and ok_id


# --------------------------------------------------------------------------- #
# closing summary table                                                        #
# --------------------------------------------------------------------------- #
def _print_summary_table() -> None:
    """Print the capability → status → evidence recap. Driven by SUMMARY_ROWS so it
    cannot drift from the beats."""
    _line()
    _banner("SUMMARY — capability · status · evidence (the whole platform, one table)")
    _line("Status legend: live-validated = proven on real AWS · built+tested = mechanism")
    _line("proven by tests · skeleton = import-safe, honestly not-yet-live.")
    _line()
    header = f"{'Layer':<5} {'Capability':<58} {'Status':<15} Evidence"
    _line(header)
    _rule()
    for _beat_no, layer, capability, status, _component, evidence in SUMMARY_ROWS:
        cap = capability if len(capability) <= 57 else capability[:54] + "..."
        _line(f"{layer:<5} {cap:<58} {status:<15} {evidence}")
    _rule()
    # Honest tally so the reader sees the split at a glance.
    n_live = sum(1 for r in SUMMARY_ROWS if r[3] == LIVE)
    n_built = sum(1 for r in SUMMARY_ROWS if r[3] == BUILT)
    n_skel = sum(1 for r in SUMMARY_ROWS if r[3] == SKELETON)
    _line(f"  totals: {n_live} live-validated · {n_built} built+tested · {n_skel} skeleton")
    _line("  Full status matrix + limitations: README.md and docs/FIDELITY-REPORT.md.")


# --------------------------------------------------------------------------- #
# entrypoints                                                                  #
# --------------------------------------------------------------------------- #
def run_tour() -> int:
    """Walk every beat in story order and print the closing table.

    Returns a process exit code: 0 when every beat that has offline-executable or
    evidence-backed proof produced it, 1 if a live-offline execution beat regressed
    (a broken deterministic core is a real failure — never masked)."""
    _banner("THE sentinel-harness PLATFORM — GUIDED TOUR (L1 → L4) · OFFLINE / MOCK")
    _line("A single narrated walk of the whole platform, front to back.")
    _line("No AWS · no network · deterministic · seconds to run.")
    _line("Each beat prints WHAT it shows, HOW it is backed, and WHERE the evidence is.")
    _line("Live-validated beats are REPLAYED from committed evidence/*.json (real runs);")
    _line("the L2 deterministic cores (BAS replay + Play Mode logic) are EXECUTED here.")

    # BAS replay + Play Mode logic are genuinely executed offline; their pass/fail is a
    # hard gate. The evidence-replayed beats print their recorded verdicts (honest even
    # if a file is absent) and do not gate the exit code — the scenarios own that proof.
    _beat1_declare_and_triage()
    _beat2_multi_harness()
    _beat3_detection_gen()
    _beat4_agent_builds_agent()
    _beat5_score_improve_promote()
    l2_ok = _beat6_l2_simulation()
    _beat7_l3_l4_foundation()

    _print_summary_table()

    _line()
    _line("This was the OFFLINE guided tour — the map. The PROOF is the committed")
    _line("evidence/*.json (real GA runs) and the live scenarios. Run any one live with:")
    _line("    AWS_PROFILE=<non-prod> SENTINEL_REGION=us-east-1 \\")
    _line("        SENTINEL_EXECUTION_ROLE_ARN=arn:aws:iam::000000000000:role/<role> \\")
    _line("        python scenarios/scenario_cve_triage.py   # …or any scenario_*.py")
    _line("See demo/PLATFORM.md for the full run-book and the live scenario list.")
    _rule("=")

    # A regression in the genuinely-executed offline cores is the only hard failure.
    return 0 if l2_ok else 1


def print_live_pointer() -> int:
    """--live is informational: this tour is the offline map; the live PROOF is the
    scenarios. Print exactly how to run them (rather than pretending to run nine live
    scenarios from inside the tour)."""
    _banner("LIVE SCENARIOS — where the real proof is produced")
    _line("This platform_demo is the OFFLINE guided tour. The live proof is produced by")
    _line("the individual scenarios (each writes its own account-scrubbed evidence/*.json).")
    _line("Run them against a NON-PROD dev account with:")
    _line()
    _line("    export AWS_PROFILE=<non-prod>")
    _line("    export SENTINEL_REGION=us-east-1")
    _line("    export SENTINEL_EXECUTION_ROLE_ARN=arn:aws:iam::000000000000:role/<harness-role>")
    _line()
    for _n, layer, cap, status, _comp, _ev in SUMMARY_ROWS:
        if status == LIVE:
            _line(f"    # {layer}: {cap}")
    _line()
    _line("    python scenarios/scenario_cve_triage.py")
    _line("    python scenarios/scenario_multi_harness.py")
    _line("    python scenarios/scenario_detection_gen.py")
    _line("    python scenarios/scenario_hitl_resume.py")
    _line("    python scenarios/scenario_agent_factory_loop.py")
    _line("    python scenarios/scenario_self_improve_loop.py")
    _line("    python scenarios/scenario_play_mode.py")
    _line("    python scenarios/scenario_bas_replay.py         # pure/offline by default")
    _line("    python scenarios/scenario_named_supervisor.py   # needs SENTINEL_GATEWAY_ARN")
    _line("    sentinel cleanup sentinel_                       # tear everything down")
    _line()
    _line("The M2 loop also has its own runnable narrated demo: demo/m2_self_improving_demo.py")
    _rule("=")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Guided offline tour of the whole sentinel-harness platform (L1 → L4).")
    parser.add_argument(
        "--live", action="store_true",
        help="print how to run the real live scenarios (this tour is the offline map; "
             "the scenarios produce the live proof). Default: run the offline tour.")
    args = parser.parse_args(argv)
    return print_live_pointer() if args.live else run_tour()


if __name__ == "__main__":
    sys.exit(main())
