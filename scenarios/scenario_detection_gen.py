"""
Scenario 3 — Detection-rule generation with adversarial review + publish gate
==============================================================================
Layer 1 (Strategy Iteration) · detection engineering.

Mirrors the customer flow "auto-generate detection rule -> multi-round agent
cross-review -> human merge". Demonstrates the generation != evaluation principle:
a *generator* harness writes a Sigma rule, a separate *adversarial-reviewer* harness
attacks it (false-positive sources, logic gaps), then a human-in-the-loop publish
gate requires analyst sign-off before the rule goes live.

Two independent harnesses (generator + reviewer) = the cheapest, most reliable way
to catch a generator's own blind spots. All generic; runnable on a dev account.
"""
import json, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from sentinel_harness import core as sh

RESULT = {"scenario": "detection_gen_adversarial_review", "steps": []}
def rec(step, data):
    RESULT["steps"].append({"step": step, "data": json.loads(json.dumps(data, default=str))})
    print(f"[..] {step}: {json.dumps(data, default=str)[:240]}")

GEN_SYS = ("You are a detection engineer. Given a threat behavior, write ONE concise Sigma "
           "detection rule (YAML): title, logsource, detection (selection + condition), "
           "level. Keep it tight. Output only the YAML rule.")
REV_SYS = ("You are an adversarial detection reviewer.\n"
           "OUTPUT CONTRACT — follow exactly:\n"
           "1. Your VERY FIRST line MUST be either 'VERDICT: approve' or 'VERDICT: revise' "
           "(nothing before it). Decide the verdict first, then justify it.\n"
           "2. After that line, briefly list the concrete false-positive sources, logic gaps, "
           "and evasion bypasses that drove your verdict. Be skeptical and specific.\n"
           "Do NOT preface with 'I'll analyze...' or any thinking — start with the VERDICT line "
           "immediately. A reply whose first line is not 'VERDICT:' is a failed review.")

PUBLISH_GATE = sh.tool_inline(
    "request_publish_approval",
    "Request analyst sign-off before publishing a detection rule to production. "
    "Carries the rule and the reviewer verdict; the analyst may hand-merge edits.",
    {"type": "object",
     "properties": {"rule_title": {"type": "string"}, "reviewer_verdict": {"type": "string"},
                    "rule_yaml": {"type": "string"}},
     "required": ["rule_title", "reviewer_verdict"]})

THREAT = ("Detect an npm package running a postinstall script that reads private-key material "
          "(e.g. accessing ~/.ssh, wallet keystores, or environment secrets) during install.")

def parse_verdict(text: str) -> bool:
    """Robustly decide approval from a reviewer reply.

    Case-insensitive: find the LAST line containing 'verdict:'; approved iff that
    line says 'approve' and NOT 'revise'. Falls back to a whole-text scan (same
    approve-and-not-revise rule) if no explicit verdict line was emitted."""
    approved_line, scope = None, text
    for line in text.splitlines():
        if "verdict:" in line.lower():
            approved_line = line
    if approved_line is not None:
        scope = approved_line.lower()
    else:
        scope = text.lower()
    return "approve" in scope and "revise" not in scope

# Reviewer needs headroom to finish the analysis AND emit the final VERDICT line.
REVIEW_MAX_ITERATIONS = int(os.environ.get("SENTINEL_REVIEW_MAX_ITERATIONS", "8"))
REVIEW_MAX_TOKENS = int(os.environ.get("SENTINEL_REVIEW_MAX_TOKENS", "2000"))

def build():
    gen = sh.create_harness("sentinel_detect_gen", GEN_SYS,
                            model=sh.bedrock_model(sh.MODEL_SONNET), max_iterations=6)
    # Larger budget so the reviewer doesn't return only a preamble and drop the verdict line.
    rev = sh.create_harness("sentinel_detect_reviewer", REV_SYS,
                            model=sh.bedrock_model(sh.MODEL_SONNET),
                            max_iterations=REVIEW_MAX_ITERATIONS, max_tokens=REVIEW_MAX_TOKENS)
    # publisher harness holds the HITL publish gate. allowedTools scopes the LLM's tool choice
    # (built-ins included) to ONLY request_publish_approval, so the model can't fire a stray
    # built-in 'shell' tool. Note: allowedTools does NOT gate InvokeAgentRuntimeCommand — it
    # constrains what the model may call inside the loop, not the harness invocation itself.
    pub = sh.create_harness(
        "sentinel_detect_publisher",
        "You are a detection-publishing coordinator. Given a rule and a reviewer verdict, if the "
        "verdict approves, call request_publish_approval to get analyst sign-off before publishing. "
        "Never publish without the human gate. Use only the request_publish_approval tool.",
        model=sh.bedrock_model(sh.MODEL_SONNET), tools=[PUBLISH_GATE],
        allowed_tools=["request_publish_approval"], max_iterations=6)
    for h in (gen, rev, pub): sh.wait_ready(h["harnessId"])
    rec("built", {"gen": gen["harnessId"], "reviewer": rev["harnessId"], "publisher": pub["harnessId"]})
    return gen["arn"], rev["arn"], pub["arn"]

def run(gen_arn, rev_arn, pub_arn):
    # 1) generator writes a rule
    g = sh.invoke(gen_arn, sh.new_session("gen"), f"Threat behavior: {THREAT}")
    rule = g["text"].strip()
    rec("generated_rule", {"rule_head": rule[:300]})

    # 2) adversarial reviewer attacks it (separate harness = independent judgment).
    #    Pass maxTokens on the invoke too so a long attack list still leaves room for the
    #    trailing VERDICT line (invoke overrides win over create-time defaults).
    rv = sh.invoke(rev_arn, sh.new_session("rev"), f"Review this Sigma rule:\n{rule}",
                   maxTokens=REVIEW_MAX_TOKENS)
    verdict = rv["text"].strip()
    approved = parse_verdict(verdict)
    # verdict now leads the reply, so capture the HEAD (where the VERDICT line lives)
    rec("adversarial_review", {"verdict_head": verdict[:400], "approved_signal": approved})

    # 3) publish gate — the analyst sign-off is REQUIRED no matter the verdict: an
    #    approve still needs a human to authorize going live; a revise needs a human to
    #    see the reviewer's objections and decide. Either way nothing reaches production
    #    without request_publish_approval. allowed_tools on the INVOKE narrows the LLM to
    #    ONLY the gate so the built-in 'shell' can't fire (allowedTools scopes create AND
    #    invoke; it does NOT gate InvokeAgentRuntimeCommand — that needs the IAM action withheld).
    p = sh.invoke(pub_arn, sh.new_session("pub"),
                  f"Rule:\n{rule}\n\nReviewer verdict:\n{verdict}\n\nRegardless of the verdict, you MUST "
                  f"call request_publish_approval to get analyst sign-off before anything goes live. "
                  f"Pass the reviewer's verdict through so the analyst sees it.",
                  allowedTools=["request_publish_approval"])
    rec("publish_flow", {"stop_reason": p["stop_reason"], "tools_used": p["tools_used"],
        "reply_head": p["text"][:240]})

    emitted_verdict = "verdict:" in verdict.lower()
    hit_gate = "request_publish_approval" in p["tools_used"]
    used_no_shell = "shell" not in p["tools_used"]   # allowedTools kept the built-in shell off
    # Safety property: a rule reaches "published" ONLY through the human gate. If the
    # reviewer REVISES, the correct outcome is that publish is withheld (gate not called,
    # nothing goes live). If it APPROVES, the gate must fire. Either path is safe.
    if approved:
        publish_controlled = hit_gate            # approve → must route through the human gate
    else:
        publish_controlled = not hit_gate        # revise → correctly withheld, nothing published
    RESULT["verdict"] = {
        "generator_and_reviewer_are_separate_harnesses": True,
        "reviewer_emitted_parseable_verdict": emitted_verdict,
        "reviewer_verdict": "approve" if approved else "revise",
        "no_stray_shell_tool": used_no_shell,
        "publish_correctly_controlled": publish_controlled,
        "closed": emitted_verdict and publish_controlled and used_no_shell,
        "note": "generation != evaluation: an independent reviewer harness emits a parseable "
                "VERDICT (verdict-first so it survives truncation); allowedTools kept the built-in "
                "shell off; and nothing reaches production except through the human gate — an "
                "approve routes through request_publish_approval, a revise withholds publish. "
                "Kills self-approval bias."}
    return RESULT

if __name__ == "__main__":
    g, r, p = build(); run(g, r, p)
    out = os.path.join(os.path.dirname(__file__), "..", "evidence", "detection_gen_result.json")
    json.dump(RESULT, open(out, "w"), indent=2, ensure_ascii=False, default=str)
    print("\nsaved evidence/detection_gen_result.json  ·  verdict:", RESULT.get("verdict"))
