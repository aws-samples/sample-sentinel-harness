"""
Scenario 5 — Play Mode adversary-emulation with a per-step HITL gate
====================================================================
Layer 2 (Simulation) · a minimal long-running attack-SIMULATION runner where
*every* offensive step is human-confirmed.

A defensive adversary-emulation agent runs a SIMULATED ATT&CK-style kill chain
(recon -> initial-access -> execution -> persistence). Before EMULATING each
offensive technique the agent must call the `exec_technique` gate; the harness
PAUSES (stop_reason=tool_use) and hands control back. A human decision is
applied per step:
  * APPROVE -> resume the SAME session (two-message toolUse+toolResult) and
    record a SIMULATED no-op execution ("would execute technique T####").
  * REJECT  -> the plan HALTS (Play Mode invariant: no offensive action without
    an explicit human confirmation).

Plan state is checkpointed to JSON so a long run can resume mid-plan.

This scenario runs the plan TWICE to demonstrate both paths:
  1. auto-approve all steps -> full kill chain emulated (all steps gated + resumed)
  2. reject after the first step -> plan halts on the gate

SIMULATED / DEFENSIVE ONLY — nothing here attacks, scans, or touches any real
system. Generic content; runnable on a non-production dev account. Leave AWS
teardown to `sentinel cleanup`.
"""
import json, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from sentinel_harness import core as sh
from sentinel_harness import simulation as sim

RESULT = {"scenario": "play_mode", "steps": []}
def rec(step, ok, data):
    RESULT["steps"].append({"step": step, "ok": ok, "data": json.loads(json.dumps(data, default=str))})
    print(f"[{'OK' if ok else '..'}] {step}: {json.dumps(data, default=str)[:300]}")

NAME = "sentinel_playmode_sim"
EVIDENCE_DIR = os.path.join(os.path.dirname(__file__), "..", "evidence")
CKPT_APPROVE = os.path.join(EVIDENCE_DIR, "play_mode_checkpoint_approve.json")
CKPT_REJECT = os.path.join(EVIDENCE_DIR, "play_mode_checkpoint_reject.json")

# A short 3-step SIMULATED plan for the scenario.
PLAN = sim.DEFAULT_PLAN[:3]


def build():
    h = sh.create_harness(
        NAME, sim.PLAY_MODE_SYSTEM,
        model=sh.bedrock_model(sh.MODEL_SONNET),
        tools=[sim.exec_technique_gate()],
        max_iterations=12,
    )
    rec("create", True, {"harnessId": h["harnessId"]})
    sh.wait_ready(h["harnessId"]); rec("ready", True, {"id": h["harnessId"]})
    return h["arn"]


def run(arn):
    # --- Run 1: approve every step -> full kill chain emulated --------------
    r_approve = sim.PlayModeRunner(
        arn, plan=PLAN, plan_id="playmode_approve",
        checkpoint_path=CKPT_APPROVE,
        decision_fn=sim.auto_approve,
    )
    state_a = r_approve.run()
    v_a = r_approve.verdict()
    rec("run_approve", v_a["every_step_gated"] and v_a["approved_step_resumed"],
        {"verdict": v_a, "counts": state_a.counts()})

    # --- Run 2: reject after the first step -> plan halts on the gate -------
    r_reject = sim.PlayModeRunner(
        arn, plan=PLAN, plan_id="playmode_reject",
        checkpoint_path=CKPT_REJECT,
        decision_fn=sim.reject_after(1),   # approve step 0, reject step 1
    )
    state_r = r_reject.run()
    v_r = r_reject.verdict()
    rec("run_reject", v_r["reject_halts_plan"] and state_r.halted,
        {"verdict": v_r, "counts": state_r.counts(), "halted_reason": state_r.halted_reason})

    # --- Demonstrate checkpoint round-trip (resume a long run) --------------
    reloaded = sim.load_checkpoint(CKPT_APPROVE)
    ckpt_ok = reloaded.to_dict() == state_a.to_dict()
    rec("checkpoint_roundtrip", ckpt_ok, {"path": CKPT_APPROVE, "steps": len(reloaded.steps)})

    RESULT["verdict"] = {
        "every_step_gated": v_a["every_step_gated"],
        "approved_step_resumed": v_a["approved_step_resumed"],
        "reject_halts_plan": v_r["reject_halts_plan"],
        "checkpoint_roundtrip": ckpt_ok,
        "closed_loop": v_a["closed_loop"] and v_r["closed_loop"],
        "note": "Play Mode adversary emulation: every offensive exec_technique step "
                "paused on a human gate. Approvals resumed the same session via the "
                "two-message toolUse+toolResult contract and recorded a SIMULATED "
                "no-op execution; a rejection halted the plan. State checkpointed to "
                "JSON and round-tripped. No real system was touched.",
    }
    return RESULT


if __name__ == "__main__":
    arn = build(); run(arn)
    out = os.path.join(EVIDENCE_DIR, "play_mode_result.json")
    json.dump(RESULT, open(out, "w"), indent=2, ensure_ascii=False, default=str)
    print("\nsaved evidence/play_mode_result.json  ·  verdict:", RESULT.get("verdict"))
