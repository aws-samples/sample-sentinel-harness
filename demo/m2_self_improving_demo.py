#!/usr/bin/env python3
"""
M2 self-improvement loop — a runnable, narrated demo
====================================================
"An agent scores, improves, and promotes an agent."

This single script tells the whole M2 story end to end and prints it as a
step-by-step narrative:

    request  ->  weak agent answer  ->  judge scores it (FAIL, with reasons)
             ->  improve the prompt  ->  judge scores again (PASS)
             ->  human-in-the-loop APPROVE  ->  promote to a prod endpoint
             ->  a REJECT path proves a passing agent is NOT promoted without a human.

Two modes
---------
* DEFAULT (offline / mock)  — the mode used for demos, CI, and laptops with no
  cloud access. Every AWS seam is monkeypatched (the SAME seams the offline test
  suite uses: ``core.create_harness``, ``core.invoke``, ``core.update_harness``,
  ``core.wait_ready``, ``core.create_harness_endpoint``, ``core.get_harness_endpoint``,
  ``core.delete_harness``, ``core.delete_harness_endpoint``, ``core.new_session``,
  ``core.list_harnesses``). The judge's replies are FIXED canned verdicts, so the
  run is fully deterministic: no ``random``, no network, no AWS, no wall-clock
  sleeps. It finishes in well under a second and exits 0 on success.

* ``--live`` (or ``SENTINEL_DEMO_LIVE=1``) — delegates to the real scenario
  ``scenarios/scenario_self_improve_loop.py`` against a real AgentCore control
  plane. This builds real harnesses, invokes real models, and creates a real
  endpoint, so it needs AWS credentials, ``SENTINEL_EXECUTION_ROLE_ARN``, and
  enough InvokeHarness quota. The live scenario logic is NOT duplicated here —
  this script imports and calls it.

Run
---
    # offline, no AWS, deterministic (the default):
    python demo/m2_self_improving_demo.py

    # live, against real AgentCore (documented in demo/README.md):
    python demo/m2_self_improving_demo.py --live

The offline narrative is the promotion artifact; the live path is the proof.
"""
from __future__ import annotations

import argparse
import os
import sys

# Make the repo importable whether run as a module or a plain script, and set a
# harmless dummy env BEFORE importing sentinel_harness.core (its module import
# builds a boto3 control-plane client). In offline mode we never touch AWS, but
# the client still needs a region + role string to construct.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

os.environ.setdefault("SENTINEL_REGION", "us-east-1")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
# 000000000000 is the sanctioned all-zeros placeholder account id (never a real one).
os.environ.setdefault("SENTINEL_EXECUTION_ROLE_ARN", "arn:aws:iam::000000000000:role/demo")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "offline-demo")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "offline-demo")


# --------------------------------------------------------------------------- #
# narration helpers — pure stdout, no state                                    #
# --------------------------------------------------------------------------- #
_WIDTH = 74


def _rule(char: str = "-") -> None:
    print(char * _WIDTH)


def _banner(title: str) -> None:
    _rule("=")
    print(title)
    _rule("=")


def _step(n: int, title: str) -> None:
    print()
    _rule()
    print(f"STEP {n} — {title}")
    _rule()


def _line(text: str = "") -> None:
    print(text)


# --------------------------------------------------------------------------- #
# fixed demo data — a Log4Shell triage task, weak vs strong agents             #
# --------------------------------------------------------------------------- #
TASK = "Triage CVE-2021-44228 (Log4Shell). Give a risk read for a security analyst."

CRITERIA = [
    "Names the vulnerability class (JNDI/LDAP remote code execution in Log4j2).",
    "States severity is critical (CVSS ~10) and that it is exploited in the wild / in CISA KEV.",
    "Gives at least one concrete recommended action (patch/upgrade Log4j, mitigate JNDI lookups).",
    "Is specific and actionable, not a yes/no or a single vague sentence.",
]

# The deliberately underspecified agent answers with one useless word.
WEAK_ANSWER = "noted"

# After the improvement, the agent produces a real analyst-grade risk read.
STRONG_ANSWER = (
    "CVE-2021-44228 (Log4Shell) is a JNDI/LDAP remote code execution flaw in "
    "Apache Log4j2. Severity is CRITICAL (CVSS 10.0) and it is actively exploited "
    "in the wild and listed in CISA's Known Exploited Vulnerabilities (KEV) "
    "catalog. Any service logging attacker-controlled strings via a vulnerable "
    "Log4j2 version is at risk of full remote code execution. Recommended actions: "
    "upgrade Log4j2 to 2.17.1 or later, and as an interim mitigation set "
    "log4j2.formatMsgNoLookups=true / remove the JndiLookup class."
)

# Canned, FIXED judge verdicts (raw judge replies). The judge is the ONLY model
# call in the real tool; here we make its reply deterministic so the whole loop is
# reproducible. The verdict JSON matches the schema the judge is instructed to emit
# ({"score","pass","reasons","suggestions"}) and is parsed by the SAME pure parser
# the production tool uses (run_evaluation.parse_verdict) — the demo does not
# hand-roll any scoring.
JUDGE_REPLY_FOR_WEAK = (
    '{"score": 0.0, "pass": false, '
    '"reasons": ["Answer is a single word \\"noted\\" with no analysis.", '
    '"Does not name the vulnerability class or severity.", '
    '"No recommended action given."], '
    '"suggestions": ['
    '"Identify the vulnerability as Log4Shell (CVE-2021-44228), a JNDI/LDAP RCE in Log4j2.", '
    '"State severity is critical (CVSS 10.0) and that it is in CISA KEV / exploited in the wild.", '
    '"Give a concrete remediation step, e.g. upgrade Log4j2 to 2.17.1 or disable JNDI lookups."]}'
)
JUDGE_REPLY_FOR_STRONG = (
    '{"score": 0.95, "pass": true, '
    '"reasons": ["Names the JNDI/LDAP RCE vulnerability class in Log4j2.", '
    '"States critical severity (CVSS 10.0) and CISA KEV / active exploitation.", '
    '"Gives concrete remediation (upgrade to 2.17.1, disable JNDI lookups)."], '
    '"suggestions": []}'
)

THRESHOLD = 0.7
ENDPOINT_NAME = "prod"


# --------------------------------------------------------------------------- #
# offline mode — monkeypatch the AWS seams, then walk the loop                 #
# --------------------------------------------------------------------------- #
def _install_offline_stubs(core):
    """Replace every AWS-touching ``core`` function with an in-memory fake.

    Returns a ``dict`` of the fake control plane's state so the caller can make
    assertions after the run (used by the test). The judge's reply is chosen by
    inspecting the prompt the judge is invoked with: the prompt embeds the agent
    answer, so a prompt containing the weak answer gets the FAIL verdict and one
    containing the strong answer gets the PASS verdict — fully deterministic.

    The original ``core`` functions are stashed under ``state['_originals']`` so
    the caller can restore them with :func:`_restore_core` — important when the
    demo is imported into a shared test process, so the stubs never leak into
    another test module."""
    _PATCHED = ("new_session", "create_harness", "update_harness", "wait_ready",
                "invoke", "create_harness_endpoint", "get_harness_endpoint",
                "delete_harness_endpoint", "delete_harness", "list_harnesses")
    state = {
        "_originals": {name: getattr(core, name, None) for name in _PATCHED},
        "harnesses": {},          # harnessId -> {"name","system_prompt","version"}
        "endpoints": {},          # (harnessId, endpointName) -> {"status": "READY"}
        "invoke_calls": [],       # (arn, prompt) for every core.invoke
        "endpoint_creates": [],   # harnessId promoted
        "endpoint_deletes": [],
        "harness_deletes": [],
        "_seq": 0,
    }

    def _next_id(name):
        state["_seq"] += 1
        return f"{name}-{'0' * 6}{state['_seq']}"

    def fake_new_session(prefix="sentinel"):
        # Deterministic: no randomness. Session ids only need to be non-empty here.
        return f"{prefix}-" + "0" * 33

    def fake_create_harness(name, system_prompt, **kw):
        hid = _next_id(name)
        state["harnesses"][hid] = {"name": name, "system_prompt": system_prompt, "version": 1}
        arn = f"arn:aws:bedrock-agentcore:us-east-1:000000000000:harness/{hid}"
        return {"harnessId": hid, "arn": arn, "status": "CREATING"}

    def fake_update_harness(harness_id, *, system_prompt=None, **kw):
        h = state["harnesses"].setdefault(harness_id, {"version": 1})
        if system_prompt is not None:
            h["system_prompt"] = system_prompt
        h["version"] = h.get("version", 1) + 1   # a real update mints a new version
        return {"harness": {"harnessId": harness_id, "version": h["version"]}}

    def fake_wait_ready(harness_id, timeout=360):
        # No sleeping, no polling — the fake control plane is instantly READY.
        return {"harnessId": harness_id, "status": "READY"}

    def fake_invoke(arn, session_id, text, **kw):
        state["invoke_calls"].append((arn, text))
        # The judge harness is invoked by the run_evaluation tool: its prompt embeds
        # the agent answer under scoring. Return the FIXED verdict for that answer.
        if WEAK_ANSWER in text and STRONG_ANSWER not in text and "CRITERIA" in text:
            return {"text": JUDGE_REPLY_FOR_WEAK, "stop_reason": "end_turn",
                    "tools_used": [], "tool_use": None, "events": [], "metadata": {},
                    "error": None}
        if STRONG_ANSWER in text and "CRITERIA" in text:
            return {"text": JUDGE_REPLY_FOR_STRONG, "stop_reason": "end_turn",
                    "tools_used": [], "tool_use": None, "events": [], "metadata": {},
                    "error": None}
        # Otherwise this is the triage AGENT being invoked on the task: return the
        # answer that matches its current prompt (weak until improved, then strong).
        hid = arn.rsplit("/", 1)[-1]
        prompt = (state["harnesses"].get(hid, {}) or {}).get("system_prompt", "")
        answer = STRONG_ANSWER if "senior" in prompt.lower() else WEAK_ANSWER
        return {"text": answer, "stop_reason": "end_turn", "tools_used": [],
                "tool_use": None, "events": [], "metadata": {}, "error": None}

    def fake_create_harness_endpoint(harness_id, endpoint_name, **kw):
        state["endpoints"][(harness_id, endpoint_name)] = {"status": "READY"}
        state["endpoint_creates"].append(harness_id)
        return {"endpointName": endpoint_name, "status": "CREATING"}

    def fake_get_harness_endpoint(harness_id, endpoint_name):
        ep = state["endpoints"].get((harness_id, endpoint_name))
        if ep is None:
            raise RuntimeError("ResourceNotFoundException: no such endpoint")
        return {"endpoint": {"endpointName": endpoint_name, **ep}}

    def fake_delete_harness_endpoint(harness_id, endpoint_name):
        state["endpoints"].pop((harness_id, endpoint_name), None)
        state["endpoint_deletes"].append(harness_id)
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    def fake_delete_harness(harness_id, keep_memory=False):
        state["harnesses"].pop(harness_id, None)
        state["harness_deletes"].append(harness_id)
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    def fake_list_harnesses():
        return [{"harnessName": h["name"], "harnessId": hid}
                for hid, h in state["harnesses"].items() if "name" in h]

    core.new_session = fake_new_session
    core.create_harness = fake_create_harness
    core.update_harness = fake_update_harness
    core.wait_ready = fake_wait_ready
    core.invoke = fake_invoke
    core.create_harness_endpoint = fake_create_harness_endpoint
    core.get_harness_endpoint = fake_get_harness_endpoint
    core.delete_harness_endpoint = fake_delete_harness_endpoint
    core.delete_harness = fake_delete_harness
    core.list_harnesses = fake_list_harnesses
    return state


def _restore_core(core, state) -> None:
    """Put back the original ``core`` functions the stubs replaced (best-effort).

    Restoring keeps the demo from leaking its in-memory fakes into a shared
    process (e.g. a pytest run that also exercises the real ``core`` wrappers)."""
    for name, orig in (state.get("_originals") or {}).items():
        if orig is not None:
            setattr(core, name, orig)


def run_offline() -> int:
    """Walk the whole self-improvement loop against the in-memory fakes and narrate
    every beat. Returns a process exit code (0 = the loop closed as expected).

    Installs the offline stubs, runs the loop, and ALWAYS restores the real
    ``core`` functions afterward so the fakes never leak into a shared process."""
    from sentinel_harness import core

    state = _install_offline_stubs(core)
    try:
        return _run_offline_loop(core, state)
    finally:
        _restore_core(core, state)


def _run_offline_loop(core, state) -> int:
    """The narrated loop itself, run against the already-installed fakes."""
    # Load the real scoring tool by path (tools/ is a scripts tree). It calls
    # core.invoke internally, which is now our deterministic fake, and parses the
    # verdict with its real pure parser — so the SCORING mechanism is genuine.
    import importlib.util

    tool_path = os.path.join(_REPO_ROOT, "tools", "run_evaluation", "handler.py")
    spec = importlib.util.spec_from_file_location("run_evaluation_handler", tool_path)
    run_evaluation = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(run_evaluation)

    def score(judge_arn, answer):
        return run_evaluation.handler({"action": "score_answer", "params": {
            "judge_arn": judge_arn, "agent_answer": answer, "criteria": CRITERIA}}, None)

    _banner("M2 SELF-IMPROVEMENT LOOP  ·  OFFLINE / MOCK MODE (no AWS)")
    _line("An agent scores, improves, and promotes an agent.")
    _line("Every AWS call is stubbed; the judge verdicts are fixed and deterministic.")

    # --- STEP 0: build the independent LLM-judge harness -------------------- #
    _step(0, "Build the independent LLM-judge harness")
    judge = core.create_harness("sentinel_llm_judge", "You are an impartial judge.")
    core.wait_ready(judge["harnessId"])
    judge_arn = judge["arn"]
    _line(f"  judge harness: {judge['harnessId']}  (status READY)")
    _line("  The judge is a SEPARATE harness — it scores the agent, so the agent")
    _line("  cannot grade its own homework.")

    # --- STEP 1: build a deliberately weak agent ---------------------------- #
    _step(1, "Build a deliberately underspecified triage agent")
    weak_prompt = ("You are a CVE assistant. Reply with ONLY the single word "
                   "'noted' and nothing else.")
    agent = core.create_harness("sentinel_selfimprove_cve", weak_prompt)
    agent_id = agent["harnessId"]
    agent_arn = agent["arn"]
    core.wait_ready(agent_id)
    _line(f"  agent harness: {agent_id}  (status READY)")
    _line(f"  system prompt: {weak_prompt!r}")

    # --- STEP 2: request -> weak answer -> judge scores FAIL ---------------- #
    _step(2, "Request -> weak answer -> judge scores it (expect FAIL)")
    _line(f"  request : {TASK}")
    ans1 = core.invoke(agent_arn, core.new_session("cve"), TASK)
    _line(f"  answer  : {ans1['text']!r}")
    v1 = score(judge_arn, ans1["text"])
    _line(f"  verdict : ok={v1['ok']}  score={v1['score']}  passed={v1['passed']}")
    _line("  judge reasons:")
    for r in v1["reasons"]:
        _line(f"    - {r}")
    _line("  judge improvement suggestions:")
    for s in v1["suggestions"]:
        _line(f"    * {s}")

    scored_fail = v1["ok"] is True and v1["passed"] is False and v1["score"] < THRESHOLD
    _line(f"  => below the pass bar ({THRESHOLD}): {scored_fail}")

    # --- STEP 3: self-improve (retry-with-reasoning) ------------------------ #
    _step(3, "Self-improve: rewrite the prompt from the judge's suggestions")
    strong_prompt = ("You are a senior vulnerability-triage analyst. For a given CVE, "
                     "produce a concise, complete risk read for a SOC analyst: the "
                     "vulnerability class and mechanism, severity (CVSS) and whether it "
                     "is in CISA KEV / exploited in the wild, blast radius, and concrete "
                     "recommended actions (patch version, mitigations). Be specific.")
    core.update_harness(agent_id, system_prompt=strong_prompt)
    core.wait_ready(agent_id)
    new_version = state["harnesses"][agent_id]["version"]
    _line("  applied a full-replacement prompt update (retry-with-reasoning).")
    _line(f"  the update minted a new harness version: v{new_version}")
    _line("  (In the autonomous M4 build the self-improving harness authors this")
    _line("   rewrite from v1.suggestions; here the loop applies it deterministically.)")

    # --- STEP 4: re-score -> PASS ------------------------------------------- #
    _step(4, "Re-invoke -> re-score (expect PASS)")
    ans2 = core.invoke(agent_arn, core.new_session("cve2"), TASK)
    _line(f"  answer  : {ans2['text'][:100]}...")
    v2 = score(judge_arn, ans2["text"])
    _line(f"  verdict : ok={v2['ok']}  score={v2['score']}  passed={v2['passed']}")
    for r in v2["reasons"]:
        _line(f"    - {r}")
    improved = v2["score"] > v1["score"]
    scored_pass = v2["ok"] is True and (v2["passed"] or v2["score"] >= THRESHOLD)
    _line(f"  => score rose {v1['score']} -> {v2['score']} (improved={improved})")
    _line(f"  => at/above the pass bar ({THRESHOLD}): {scored_pass}")

    # --- STEP 5a: HITL APPROVE -> promote to endpoint ----------------------- #
    _step(5, "Human-in-the-loop gate + promotion")
    promoted = False
    endpoint_live = False
    if scored_pass:
        _line("  A passing agent reaches the promotion gate. A human must approve")
        _line("  before anything is promoted to production.")
        human_approves = True
        _line(f"  HITL decision (APPROVE path): approve={human_approves}")
        if human_approves:
            core.create_harness_endpoint(agent_id, ENDPOINT_NAME,
                                         description="promoted after passing eval")
            got = core.get_harness_endpoint(agent_id, ENDPOINT_NAME)
            endpoint_live = bool((got or {}).get("endpoint"))
            promoted = True
            _line(f"  -> CreateHarnessEndpoint('{ENDPOINT_NAME}') : endpoint live = {endpoint_live}")
            _line("  The passing agent is now promoted to a production endpoint.")

    # --- STEP 5b: HITL REJECT -> NO promotion ------------------------------- #
    _line()
    _line("  REJECT path (same passing agent, a human who declines):")
    reject_before = list(state["endpoint_creates"])
    human_approves_2 = False
    _line(f"  HITL decision (REJECT path): approve={human_approves_2}")
    if not human_approves_2:
        _line("  -> no CreateHarnessEndpoint call is made.")
    reject_withholds = state["endpoint_creates"] == reject_before
    _line(f"  a rejected agent is NOT promoted: {reject_withholds}")

    # --- teardown (endpoint before harness — control-plane order) ----------- #
    _step(6, "Teardown (endpoint before harness, then the judge)")
    core.delete_harness_endpoint(agent_id, ENDPOINT_NAME)
    core.delete_harness(agent_id)
    core.delete_harness(judge["harnessId"])
    _line(f"  deleted endpoint '{ENDPOINT_NAME}', agent harness, judge harness.")

    # --- summary ------------------------------------------------------------ #
    closed = all([scored_fail, improved, scored_pass, promoted, endpoint_live,
                  reject_withholds])
    _line()
    _banner("SUMMARY — what this demo proved")
    checks = [
        ("weak agent was really scored by an independent judge", v1["ok"] is True),
        ("weak agent scored BELOW the pass bar (FAIL)", scored_fail),
        ("a prompt update minted a new harness version", new_version > 1),
        ("re-score rose and cleared the bar (PASS)", improved and scored_pass),
        ("HITL APPROVE promoted the agent to a prod endpoint", promoted and endpoint_live),
        ("HITL REJECT withheld promotion (no endpoint)", reject_withholds),
    ]
    for label, ok in checks:
        _line(f"  [{'PASS' if ok else 'FAIL'}] {label}")
    _line()
    _line(f"  loop closed end to end: {closed}")
    _line()
    _line("  This is the offline/mock run — deterministic, no AWS, seconds to run.")
    _line("  For the real proof against AgentCore, run with --live (see demo/README.md)")
    _line("  and the evidence/ files (evidence/self_improve_loop_result.json,")
    _line("  evidence/endpoint_promote_result.json).")
    _rule("=")

    return 0 if closed else 1


# --------------------------------------------------------------------------- #
# live mode — delegate to the real scenario (do NOT duplicate its logic)       #
# --------------------------------------------------------------------------- #
def run_live() -> int:
    """Delegate to the real live scenario against AgentCore. Needs credentials,
    ``SENTINEL_EXECUTION_ROLE_ARN``, and InvokeHarness quota (see demo/README.md)."""
    _banner("M2 SELF-IMPROVEMENT LOOP  ·  LIVE MODE (real AgentCore)")
    _line("Delegating to scenarios/scenario_self_improve_loop.py — this builds real")
    _line("harnesses, invokes real models, and creates a real endpoint.")
    _line("Requires AWS credentials, SENTINEL_EXECUTION_ROLE_ARN, and invoke quota.")
    _line()

    from scenarios import scenario_self_improve_loop as scenario

    judge_arn = scenario.build_judge()
    judge_id = judge_arn.split("/")[-1]
    try:
        result = scenario.run(judge_arn)
    finally:
        try:
            scenario.sh.delete_harness(judge_id)
        except Exception as exc:  # noqa: BLE001 — best-effort teardown; surface, don't crash
            _line(f"  judge teardown note: {str(exc)[:120]}")

    verdict = (result or {}).get("verdict", {})
    _line()
    _banner("LIVE VERDICT")
    for k, v in verdict.items():
        if k == "note":
            continue
        _line(f"  {k}: {v}")
    _line()
    _line(verdict.get("note", ""))
    # The live path is subject to the account's real InvokeHarness quota; a 403 on
    # the second eval is an environment limit, not a mechanism failure. We report
    # exactly what the scenario proved and only exit non-zero on a hard error.
    return 0


# --------------------------------------------------------------------------- #
# entrypoint                                                                    #
# --------------------------------------------------------------------------- #
def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Runnable demo of the M2 self-improvement loop "
                    "(score -> improve -> promote).")
    parser.add_argument(
        "--live", action="store_true",
        help="run against real AgentCore via scenarios/scenario_self_improve_loop.py "
             "(needs AWS credentials + invoke quota). Default is offline/mock.")
    args = parser.parse_args(argv)

    live = args.live or os.environ.get("SENTINEL_DEMO_LIVE") == "1"
    return run_live() if live else run_offline()


if __name__ == "__main__":
    sys.exit(main())
