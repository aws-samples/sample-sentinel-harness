"""
Scenario — the agent-factory loop ("an agent builds an agent"), M1 north star
=============================================================================
This is the first LIVE proof of the self-iteration engine: a natural-language
request goes in, the **meta-agent** harness (Opus) decomposes it into a structured
harness spec, and the **harness_ops** deterministic tool turns that spec into a
brand-new, working harness on the real Amazon Bedrock AgentCore control plane —
which we then invoke to confirm it actually functions, and finally tear down.

What is real here (honesty matters — see docs/ROADMAP.md):
  * REAL: the meta-agent is a real harness, really invoked; it emits the spec.
  * REAL: harness_ops really calls core.create_harness / wait_ready / invoke /
    delete against the live GA control plane — a genuinely new harness is built,
    reaches READY, answers an invoke, and is deleted.
  * SCOPED: delegation here is in-process (the scenario calls the harness_ops
    handler directly) rather than over a Gateway MCP target. Wiring harness_ops as
    a Gateway tool so the agent-ops harness calls it autonomously is M4 infra; the
    self-iteration *mechanism* (spec -> build -> verify -> teardown) is proven now.

Flow:
  1. build the meta-agent harness from harnesses/meta-agent/ (loader-consumed).
  2. invoke it with a one-line request -> get a structured harness spec (JSON).
  3. harness_ops.create(spec) -> a NEW harness; wait_ready; invoke it to prove it works.
  4. harness_ops.delete(...) + delete the meta-agent -> clean account.

Env (12-factor; never hardcoded):
  AWS_PROFILE=<non-prod>  SENTINEL_REGION=us-east-1
  SENTINEL_EXECUTION_ROLE_ARN=arn:aws:iam::<acct>:role/<harness-role>
"""
from __future__ import annotations

import json
import os
import re
import sys
import time

# repo root on path so `sentinel_harness` + the tools tree import when run directly.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sentinel_harness import core as sh          # noqa: E402
from sentinel_harness import loader              # noqa: E402

# Import the deterministic lifecycle tool the same way a Gateway target would call it.
import importlib.util                            # noqa: E402
_HANDLER = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "tools", "harness_ops", "handler.py")
_spec = importlib.util.spec_from_file_location("harness_ops_handler", _HANDLER)
harness_ops = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(harness_ops)

RESULT = {"scenario": "agent_factory_loop", "steps": []}

# Evidence is committed to a PUBLIC repo — scrub the 12-digit AWS account id out of any
# ARN before it lands in the JSON (mirrors the <ACCOUNT_ID> convention in evidence/README).
_ACCT_RE = re.compile(r"(arn:aws[^:]*:[^:]*:[^:]*:)\d{12}(:)")


def _scrub(obj):
    """Recursively replace the account id in any ARN string with <ACCOUNT_ID>."""
    if isinstance(obj, str):
        return _ACCT_RE.sub(r"\1<ACCOUNT_ID>\2", obj)
    if isinstance(obj, dict):
        return {k: _scrub(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_scrub(v) for v in obj]
    return obj


def rec(step, data):
    data = _scrub(data)
    RESULT["steps"].append({"step": step, "data": data})
    print(f"[{step}] {json.dumps(data, ensure_ascii=False)[:200]}")


# The one-line development request that kicks off "build me an agent".
REQUEST = (
    "Build a harness that does fast triage of Log4Shell-class (JNDI/RCE) CVEs only: "
    "given a CVE id, return a short structured risk read (severity, exploited-in-wild, "
    "recommended action). Keep it cheap and fast."
)

# A strict instruction appended at invoke time so the meta-agent returns a parseable
# spec (belt-and-suspenders on top of its system prompt).
SPEC_INSTRUCTION = (
    "\n\nRespond with ONLY a single JSON object for the harness spec, no prose, with keys: "
    '{"harnessName": "<[a-zA-Z][a-zA-Z0-9_]{0,39}, no hyphens>", '
    '"system_prompt": "<the new agent\'s instructions>", '
    '"model": "haiku|sonnet|opus", "max_iterations": <int>, "timeout_seconds": <int>}. '
    "Choose haiku for cheap/fast. Do not include tools or allowedTools."
)

_MODEL_ALIAS = {"haiku": sh.MODEL_HAIKU, "sonnet": sh.MODEL_SONNET, "opus": sh.MODEL_OPUS}


def _extract_spec(text: str) -> dict:
    """Pull the JSON harness spec out of the meta-agent's reply (tolerant of fences /
    surrounding prose). Raises ValueError if no valid object with the needed keys."""
    # Prefer a fenced block, else the first {...} span.
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL) or \
        re.search(r"(\{.*\})", text, re.DOTALL)
    if not m:
        raise ValueError("meta-agent reply contained no JSON object")
    spec = json.loads(m.group(1))
    if not spec.get("harnessName") or not spec.get("system_prompt"):
        raise ValueError(f"spec missing required keys: {list(spec)}")
    return spec


def _ensure_absent(name: str, timeout: int = 180) -> None:
    """Delete any harness with this name and poll until it is gone.

    Harness names are unique server-side and deletion is ASYNC, so a fixed-name
    platform component (the meta-agent) must be torn down and confirmed absent before
    re-creating — otherwise a re-run races a still-DELETING harness and hits
    ConflictException. This makes the scenario idempotent across back-to-back runs."""
    existing = {h["harnessName"]: h for h in sh.list_harnesses()}
    if name not in existing:
        return
    try:
        sh.delete_harness(existing[name]["harnessId"])
    except Exception:  # noqa: BLE001 — may already be deleting; the poll below is the gate
        pass
    t0 = time.time()
    while time.time() - t0 < timeout:
        if name not in {h["harnessName"] for h in sh.list_harnesses()}:
            return
        time.sleep(6)
    raise TimeoutError(f"{name} still present after {timeout}s (stuck DELETING)")


def build_meta() -> str:
    """Create the meta-agent harness from its shipped declarative config."""
    _ensure_absent("sentinel_meta_agent")   # idempotent re-runs (async delete race)
    cfg = loader.load_harness_config("harnesses/meta-agent/harness.yaml")
    # The shipped meta-agent references logical tools wired via Gateway (not present in
    # this in-process scenario), so build it prompt-only: drop tools/allowedTools and let
    # it simply emit a spec as text. This keeps the scenario self-contained + honest.
    name = cfg.pop("name")
    system_prompt = cfg.pop("system_prompt")
    for k in ("tools", "allowed_tools"):
        cfg.pop(k, None)
    h = sh.create_harness(name, system_prompt, model=cfg.get("model"),
                          memory=cfg.get("memory"),
                          max_iterations=cfg.get("max_iterations"),
                          timeout_seconds=cfg.get("timeout_seconds"))
    sh.wait_ready(h["harnessId"])
    rec("meta_built", {"harnessId": h["harnessId"], "status": "READY"})
    return h["arn"], h["harnessId"]


def run(meta_arn: str):
    built_id = None
    try:
        # 1) meta-agent decomposes the request into a structured harness spec.
        r = sh.invoke(meta_arn, sh.new_session("meta"), REQUEST + SPEC_INSTRUCTION)
        rec("meta_emitted", {"stop_reason": r["stop_reason"],
                             "reply_head": r["text"][:200]})
        spec = _extract_spec(r["text"])
        # Normalize the model alias -> a real bedrockModelConfig.
        model_alias = str(spec.get("model", "haiku")).lower()
        rec("spec_parsed", {"harnessName": spec["harnessName"], "model": model_alias,
                            "prompt_len": len(spec["system_prompt"])})

        # 2) harness_ops builds the NEW harness from the agent-authored spec (real create).
        create_params = {
            "name": spec["harnessName"],
            "system_prompt": spec["system_prompt"],
            "model": sh.bedrock_model(_MODEL_ALIAS.get(model_alias, sh.MODEL_HAIKU)),
            "max_iterations": int(spec.get("max_iterations", 8)),
            "timeout_seconds": int(spec.get("timeout_seconds", 120)),
        }
        created = harness_ops.handler({"action": "create", "params": create_params}, None)
        rec("harness_ops_create", created)
        if not created.get("ok"):
            raise RuntimeError(f"harness_ops create failed: {created.get('message')}")
        built_id = created["harnessId"]

        # 3) wait_ready + invoke the agent-built harness to prove it actually works.
        wr = harness_ops.handler({"action": "wait_ready", "params": {"harness_id": built_id}}, None)
        rec("harness_ops_wait_ready", wr)
        inv = harness_ops.handler({"action": "invoke", "params": {
            "arn": created["arn"], "text": "Triage CVE-2021-44228. Give the short structured read."}}, None)
        # Record the FULL handler return (incl. error/message on failure) so a null
        # reply is diagnosable, not silent.
        rec("built_harness_invoke", {"ok": inv.get("ok"), "stop_reason": inv.get("stop_reason"),
                                     "error": inv.get("error"), "message": inv.get("message"),
                                     "tools_used": inv.get("tools_used"),
                                     "reply_head": (inv.get("text") or "")[:200]})

        # verdict: the whole loop closed on real infrastructure.
        RESULT["verdict"] = {
            "meta_agent_emitted_spec": bool(spec.get("harnessName")),
            "harness_ops_built_real_harness": created.get("ok") is True and bool(built_id),
            "built_harness_reached_ready": wr.get("status") == "READY",
            "built_harness_answered_invoke": inv.get("ok") is True and bool(inv.get("text")),
            "closed": all([
                bool(spec.get("harnessName")),
                created.get("ok") is True,
                wr.get("status") == "READY",
                inv.get("ok") is True and bool(inv.get("text")),
            ]),
            "note": "north star, live: a natural-language request -> the meta-agent harness "
                    "emits a structured harness spec -> the deterministic harness_ops tool "
                    "builds a genuinely new harness on the GA control plane, which reaches "
                    "READY and answers a real invoke. Delegation is in-process here (Gateway "
                    "MCP wiring is M4); the build/verify mechanism is real end-to-end.",
        }
    finally:
        # 4) teardown — always, even on failure. Clean account is a hard rule.
        if built_id:
            d = harness_ops.handler({"action": "delete", "params": {"harness_id": built_id}}, None)
            rec("harness_ops_delete", d)
    return RESULT


if __name__ == "__main__":
    meta_arn, meta_id = build_meta()
    try:
        run(meta_arn)
    finally:
        sh.delete_harness(meta_id)
        rec("meta_deleted", {"harnessId": meta_id})
    os.makedirs("evidence", exist_ok=True)
    with open("evidence/agent_factory_loop_result.json", "w", encoding="utf-8") as fh:
        json.dump(RESULT, fh, indent=2, ensure_ascii=False)
    print("\nsaved evidence/agent_factory_loop_result.json  ·  verdict:", RESULT.get("verdict", {}).get("closed"))
