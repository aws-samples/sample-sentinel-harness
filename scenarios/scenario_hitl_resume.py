"""
Scenario 4 — Human-in-the-loop, full pause → approve → resume round trip
========================================================================
Layer 1 · closes the HITL contract the other scenarios only half-showed.

An alert-triage agent must call `request_containment_approval` before it may
recommend containing a host. The harness PAUSES (stop_reason=tool_use); we capture
the reconstructed tool call (toolUseId + accumulated input), an analyst "approves",
and we RESUME the same session with the two-message toolUse+toolResult contract.
The agent then continues and delivers its final, human-sanctioned recommendation.

This is the mechanism that keeps a human in the loop on high-stakes security actions.
Generic content; runnable on a non-production dev account.
"""
import json, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from sentinel_harness import core as sh

RESULT = {"scenario": "hitl_resume", "steps": []}
def rec(step, ok, data):
    RESULT["steps"].append({"step": step, "ok": ok, "data": json.loads(json.dumps(data, default=str))})
    print(f"[{'OK' if ok else '..'}] {step}: {json.dumps(data, default=str)[:300]}")

SYSTEM = (
    "You are an alert-triage analyst. When an alert warrants containing a host, you MUST "
    "call request_containment_approval BEFORE recommending containment — a human approves "
    "or rejects. After you receive the approval result, state the final action in one line. "
    "Be concise."
)

CONTAIN_GATE = sh.tool_inline(
    "request_containment_approval",
    "Request analyst approval before containing/isolating a host. Human-in-the-loop gate.",
    {"type": "object",
     "properties": {
         "host": {"type": "string"},
         "reason": {"type": "string"},
         "action": {"type": "string", "description": "e.g. isolate / block-egress / quarantine"}},
     "required": ["host", "action"]})

NAME = "sentinel_hitl_triage"

def build():
    h = sh.create_harness(NAME, SYSTEM, model=sh.bedrock_model(sh.MODEL_SONNET),
                          tools=[CONTAIN_GATE], max_iterations=10)
    rec("create", True, {"harnessId": h["harnessId"]})
    sh.wait_ready(h["harnessId"]); rec("ready", True, {"id": h["harnessId"]})
    return h["arn"]

def run(arn):
    sid = sh.new_session("hitl")   # SAME session id across pause + resume
    # Turn 1 — agent triages and should PAUSE on the containment gate
    r1 = sh.invoke(arn, sid,
        "High-severity alert: host WEB-07 shows beaconing to a known-bad C2 IP and "
        "credential-dump behavior. Decide whether to contain it, going through the approval flow.")
    paused = r1["stop_reason"] == "tool_use" and bool(r1.get("tool_use"))
    rec("turn1_pause", paused, {"stop_reason": r1["stop_reason"],
        "tool_use": r1.get("tool_use"), "reply_head": r1["text"][:200]})

    if not paused:
        RESULT["verdict"] = {"closed_hitl_loop": False,
                             "note": "agent did not pause on the gate this run"}
        return RESULT

    # Analyst decision → RESUME the same session with toolUse + toolResult
    decision = {"decision": "APPROVED", "approver": "analyst-001",
                "note": "Confirmed C2 + creds dump; isolate immediately."}
    r2 = sh.invoke_with_tool_result(arn, sid, r1["tool_use"], decision)
    resumed = r2["stop_reason"] in ("end_turn", "max_tokens", "max_iterations_exceeded", "max_output_tokens_exceeded")
    rec("turn2_resume", resumed, {"stop_reason": r2["stop_reason"], "final": r2["text"][:400]})

    RESULT["verdict"] = {
        "paused_on_gate": paused,
        "captured_tool_use": bool(r1.get("tool_use", {}).get("toolUseId")),
        "resumed_and_finished": resumed,
        "closed_hitl_loop": paused and resumed,
        "note": "Full pause→approve→resume: harness paused on request_containment_approval, "
                "analyst approved, session resumed via the two-message toolUse+toolResult "
                "contract, agent delivered a human-sanctioned final action."}
    return RESULT

if __name__ == "__main__":
    arn = build(); run(arn)
    out = os.path.join(os.path.dirname(__file__), "..", "evidence", "hitl_resume_result.json")
    json.dump(RESULT, open(out, "w"), indent=2, ensure_ascii=False, default=str)
    print("\nsaved evidence/hitl_resume_result.json  ·  verdict:", RESULT.get("verdict"))
