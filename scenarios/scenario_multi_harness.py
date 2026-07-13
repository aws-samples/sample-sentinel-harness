"""
Scenario 2 — Multi-harness parallelism + supervisor synthesis
=============================================================
Layer 1 (Strategy Iteration) · multi-role collaboration.

A single harness is single-agent + multi-tool by design. "Multi-agent parallelism"
is achieved by running MANY harnesses concurrently and having a supervisor harness
fan out and synthesize. This is the sanctioned pattern (borrowed from the AWS
pluggable-agentic-ai-framework sample: supervisor -> specialists).

Here: 3 specialist harnesses (research / detection / triage) run in parallel on the
same threat, then a supervisor harness merges them into one actionable brief.
We measure wall-clock speedup vs. a serial run.
"""
import json, os, sys, time, concurrent.futures as cf
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from sentinel_harness import core as sh

RESULT = {"scenario": "multi_harness_parallel", "steps": []}
def rec(step, data):
    RESULT["steps"].append({"step": step, "data": json.loads(json.dumps(data, default=str))})
    print(f"[..] {step}: {json.dumps(data, default=str)[:200]}")

SPECIALISTS = [
    ("sentinel_spec_research", "You are a threat-intel research specialist. For the given threat, "
        "give 2-3 sentences of ATT&CK tactic/technique highlights. Output only the highlights."),
    ("sentinel_spec_detection", "You are a detection engineer. For the given threat, give 2-3 sentences "
        "of one detection idea (data source + signal). Output only the idea."),
    ("sentinel_spec_triage", "You are an alert-triage specialist. For the given threat, give 2-3 sentences "
        "of TP/FP triage guidance and noise reduction. Output only the guidance."),
]
SUPERVISOR = ("You are a SecOps supervisor. You will receive three specialists' parallel outputs "
              "(research / detection / triage) on the same threat. Merge them into one actionable, "
              "<=6-sentence strategy-iteration brief, tagging each line with its source specialist.")

THREAT = ("A software supply-chain poisoning campaign: malicious npm packages that exfiltrate "
          "private keys, currently active against fintech/crypto targets.")

def build():
    specs = []
    for name, sysp in SPECIALISTS:
        h = sh.create_harness(name, sysp, model=sh.bedrock_model(sh.MODEL_HAIKU), max_iterations=3)
        specs.append({"name": name, "id": h["harnessId"], "arn": h["arn"]})
    sup = sh.create_harness("sentinel_supervisor", SUPERVISOR,
                            model=sh.bedrock_model(sh.MODEL_SONNET), max_iterations=4)
    for s in specs: sh.wait_ready(s["id"])
    sh.wait_ready(sup["harnessId"])
    RESULT["built"] = {"specialists": [s["name"] for s in specs], "supervisor": sup["harnessId"]}
    rec("built", RESULT["built"])
    return specs, sup["arn"]

def run(specs, sup_arn):
    def call(s):
        t0 = time.time()
        r = sh.invoke(s["arn"], sh.new_session("spec"), f"Threat: {THREAT}")
        return {"name": s["name"], "reply": r["text"].strip(), "sec": round(time.time() - t0, 1)}
    t_par = time.time()
    with cf.ThreadPoolExecutor(max_workers=3) as ex:
        outs = list(ex.map(call, specs))
    par_wall = round(time.time() - t_par, 1)
    serial = round(sum(o["sec"] for o in outs), 1)
    for o in outs: rec(f"specialist:{o['name']}", {"sec": o["sec"], "reply": o["reply"][:160]})
    speedup = round(serial / par_wall, 2) if par_wall else None
    rec("timing", {"parallel_wall_sec": par_wall, "sum_if_serial_sec": serial, "speedup": f"{speedup}x"})

    merged = "Three specialists on the same threat:\n" + "\n".join(f"[{o['name']}] {o['reply']}" for o in outs)
    r = sh.invoke(sup_arn, sh.new_session("sup"), merged)
    rec("supervisor_synthesis", {"reply": r["text"].strip()[:600]})

    RESULT["verdict"] = {"pattern": "multi-harness parallel + supervisor synthesis",
                         "parallel_speedup_vs_serial": f"{speedup}x",
                         "note": "The single-agent limit of one harness is overcome by running "
                                 "multiple harnesses in parallel and synthesizing with a supervisor."}
    return RESULT

if __name__ == "__main__":
    specs, sup = build(); run(specs, sup)
    out = os.path.join(os.path.dirname(__file__), "..", "evidence", "multi_harness_result.json")
    json.dump(RESULT, open(out, "w"), indent=2, ensure_ascii=False, default=str)
    print("\nsaved evidence/multi_harness_result.json  ·  verdict:", RESULT.get("verdict"))
