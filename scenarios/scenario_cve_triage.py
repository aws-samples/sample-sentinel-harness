"""
Scenario 1 — CVE impact triage with a human-in-the-loop gate
============================================================
Layer 1 (Strategy Iteration) · research + Layer 3 cyber-skills.

Flow: CVE id -> deterministic CVSS/exposure math (code interpreter) -> asset-impact
hypothesis -> MANDATORY analyst review (inline_function) before any recommendation.
Managed memory (per-analyst actorId) records verdicts so the team doesn't re-triage
the same CVE twice.

Everything here is generic security-ops content — no organization-specific data.
Runnable on a non-production dev account; needs no real vulnerable assets.
"""
import json, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from sentinel_harness import core as sh

RESULT = {"scenario": "cve_triage", "steps": []}
def rec(step, ok, data):
    RESULT["steps"].append({"step": step, "ok": ok, "data": json.loads(json.dumps(data, default=str))})
    print(f"[{'OK' if ok else '..'}] {step}: {json.dumps(data, default=str)[:280]}")

SYSTEM = (
    "You are a CVE impact-triage analyst for a security operations team. Given a CVE: "
    "(1) state the vulnerability class and CVSS severity; "
    "(2) use the code interpreter to do any deterministic math (version-range checks, "
    "affected-asset ratios, score parsing) — never guess numbers; "
    "(3) form a hypothesis about internal asset impact and whether action is needed; "
    "(4) before giving ANY final remediation recommendation you MUST call "
    "request_human_review — security decisions are not made by the AI alone. "
    "Be concise and structured."
)

REVIEW_GATE = sh.tool_inline(
    "request_human_review",
    "Request analyst confirmation before issuing a final CVE remediation recommendation. "
    "Used to eliminate hallucination and keep a human in the loop.",
    {"type": "object",
     "properties": {
         "cve_id": {"type": "string"},
         "severity": {"type": "string"},
         "recommended_action": {"type": "string",
                                "description": "one of: patch / mitigate / monitor / no-action"},
         "affected_assets_hypothesis": {"type": "string"}},
     "required": ["cve_id", "severity", "recommended_action"]})

NAME = "sentinel_cve_triage"

def build():
    h = sh.create_harness(
        NAME, SYSTEM,
        model=sh.bedrock_model(sh.MODEL_SONNET),
        tools=[sh.tool_code_interpreter(), REVIEW_GATE],
        memory=sh.managed_memory(strategies=["SEMANTIC", "SUMMARIZATION"], expiry_days=90),
        max_iterations=15)
    rec("create", True, {"harnessId": h["harnessId"], "memory": h.get("memory")})
    sh.wait_ready(h["harnessId"]); rec("ready", True, {"id": h["harnessId"]})
    return h["arn"]

def run(arn):
    sid = sh.new_session("cve")
    analyst = "analyst-001"
    prompt = ("Assess CVE-2021-44228 (Log4Shell) impact. Use the code interpreter to compute: "
              "given 120 Java services, of which 35 run log4j 2.x below 2.17.0, what percentage "
              "are high-risk? Then run the human-review flow before recommending an action.")
    r = sh.invoke(arn, sid, prompt, actor_id=analyst)
    rec("triage", True, {"stop_reason": r["stop_reason"], "tools_used": r["tools_used"],
        "reply_head": r["text"][:400], "usage": (r["metadata"] or {}).get("usage")})

    RESULT["verdict"] = {
        "hit_human_review_gate": "request_human_review" in r["tools_used"],
        "did_deterministic_calc": "code_interpreter" in r["tools_used"],
        "note": "CVE triage -> deterministic compute -> mandatory human-review gate, "
                "all via harness config. Zero orchestration code."}
    return RESULT

if __name__ == "__main__":
    arn = build(); run(arn)
    out = os.path.join(os.path.dirname(__file__), "..", "evidence", "cve_triage_result.json")
    json.dump(RESULT, open(out, "w"), indent=2, ensure_ascii=False, default=str)
    print("\nsaved evidence/cve_triage_result.json  ·  verdict:", RESULT.get("verdict"))
