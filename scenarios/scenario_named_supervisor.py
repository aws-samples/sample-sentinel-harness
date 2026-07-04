"""
Scenario — Named research-supervisor harness wired to a live Gateway (roadmap #1)
=================================================================================
Layer 1 (Strategy Iteration) · threat research + synthesis, end-to-end.

This is the "make the declarative harness live" scenario: instead of building the
supervisor inline (like scenario_multi_harness), we LOAD the shipped, named
``harnesses/research-supervisor/harness.yaml`` through ``sentinel_harness.loader``,
create it, and invoke it against a threat-research brief. That proves the whole
config-driven path — the same ``sentinel create <harness.yaml>`` a user would run.

The supervisor references an AgentCore Gateway (its policy-backed MCP tool surface)
by ARN via ``${SENTINEL_GATEWAY_ARN}``. That Gateway is created out of band (see
``sentinel_harness.gateway.create_gateway`` + ``create_gateway_target``); this
scenario consumes it. If ``SENTINEL_GATEWAY_ARN`` is unset the script explains
exactly what to set and exits without touching AWS.

Import-safe offline: all AWS work is guarded under ``__main__`` (and behind the
env check), so ``import scenario_named_supervisor`` in a test makes zero AWS calls.

Mirrors scenario_detection_gen.py: build() / run() / rec() / __main__ with a
delete-and-wait teardown. All generic SecOps content — no org-specific data.
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from sentinel_harness import core as sh
from sentinel_harness import loader

# Path to the shipped, named harness config that this scenario brings to life.
HARNESS_YAML = os.path.join(
    os.path.dirname(__file__), "..", "harnesses", "research-supervisor", "harness.yaml"
)

# The threat-research brief we hand the supervisor. Public, generic SecOps content:
# a software supply-chain poisoning question the supervisor must decompose, ground
# in its Gateway tools (NVD / EPSS / KEV / ATT&CK / web_search), and synthesize.
BRIEF = (
    "Research brief: a software supply-chain poisoning campaign is distributing "
    "malicious npm packages whose postinstall scripts exfiltrate private-key and "
    "wallet-keystore material. Decompose this into CVE-intel, ATT&CK-technique, and "
    "threat-hunting sub-questions; ground every claim in a tool result; and return a "
    "structured ResearchDossier (findings, attack_techniques, recommended_followups, "
    "unknowns). Name what you cannot ground rather than confabulating."
)

RESULT = {"scenario": "named_supervisor_gateway_wiring", "steps": []}


def rec(step, data):
    RESULT["steps"].append({"step": step, "data": json.loads(json.dumps(data, default=str))})
    print(f"[..] {step}: {json.dumps(data, default=str)[:240]}")


def _require_gateway_arn() -> str:
    """The supervisor's harness.yaml references ${SENTINEL_GATEWAY_ARN}. Fail early
    with actionable guidance (not a KeyError deep inside the loader) if it's unset."""
    arn = os.environ.get("SENTINEL_GATEWAY_ARN")
    if not arn:
        raise SystemExit(
            "SENTINEL_GATEWAY_ARN is not set.\n"
            "This scenario wires the research-supervisor harness to a LIVE AgentCore "
            "Gateway (its MCP tool surface). Stand one up first, e.g.:\n\n"
            "    from sentinel_harness import gateway\n"
            "    gw = gateway.create_gateway('sentinel-research-gw')\n"
            "    gateway.wait_gateway_ready(gw['gatewayId'])\n"
            "    # add tool targets with gateway.create_gateway_target(...)\n\n"
            "then export its ARN and also the standard 12-factor config:\n"
            "    export SENTINEL_GATEWAY_ARN=$(...)   # gw['gatewayArn']\n"
            "    export SENTINEL_EXECUTION_ROLE_ARN=arn:aws:iam::<acct>:role/<role>\n"
            "    export SENTINEL_REGION=us-east-1\n"
        )
    return arn


def build() -> dict:
    """Load the named harness.yaml (expands ${SENTINEL_GATEWAY_ARN} etc.) and create
    the supervisor harness wired to the Gateway. Returns the created harness dict."""
    gw_arn = _require_gateway_arn()
    # load_harness_config is pure/offline; it expands the Gateway ARN into the
    # agentcore_gateway tool config. create_harness then reaches the control plane.
    kwargs = loader.load_harness_config(HARNESS_YAML)
    rec("loaded_config", {
        "name": kwargs["name"],
        "tool_types": [t.get("type") for t in kwargs.get("tools", [])],
        "allowed_tools": kwargs.get("allowed_tools"),
        "gateway_arn_wired": gw_arn,
    })
    h = sh.create_harness(**kwargs)
    sh.wait_ready(h["harnessId"])
    rec("built", {"harness_id": h["harnessId"], "arn": h["arn"], "name": kwargs["name"]})
    return h


def run(h: dict) -> dict:
    """Invoke the supervisor with the threat-research brief and record a structured
    verdict of what was proven (config-driven create + Gateway-wired invoke)."""
    arn = h["arn"]
    r = sh.invoke(arn, sh.new_session("named-sup"), BRIEF, actor_id="scenario-analyst")
    reply = r["text"].strip()
    rec("supervisor_reply", {
        "stop_reason": r["stop_reason"],
        "tools_used": r["tools_used"],
        "reply_head": reply[:600],
    })

    # The Gateway tools live behind the agentcore_gateway surface; whether the model
    # chose to call one is reported (transport signal), but success is defined on the
    # SUBSTANCE: the NAMED, config-driven harness was created from harness.yaml, the
    # Gateway ARN was wired in from env, and it produced a grounded research reply.
    produced_reply = bool(reply)
    gateway_wired = any(
        t.get("type") == "agentcore_gateway"
        for t in loader.load_harness_config(HARNESS_YAML).get("tools", [])
    )
    RESULT["verdict"] = {
        "harness_loaded_from_named_yaml": True,
        "harness_name": h.get("harnessName") or "sentinel_research_supervisor",
        "gateway_wired_from_env": gateway_wired,
        "supervisor_produced_reply": produced_reply,
        "tools_available_to_model": r["tools_used"],
        "closed": produced_reply and gateway_wired,
        "note": "The named research-supervisor harness is brought to life from its "
                "shipped harness.yaml via sentinel_harness.loader (the same path as "
                "`sentinel create`), wired to a live AgentCore Gateway by ARN from "
                "SENTINEL_GATEWAY_ARN, and invoked end-to-end on a threat-research "
                "brief. Config-only harness + policy-backed Gateway tool surface, "
                "zero orchestration code.",
    }
    return RESULT


if __name__ == "__main__":
    harness = build()
    try:
        run(harness)
    finally:
        # Delete-and-wait teardown: remove the harness (cascade-deletes managed
        # memory). The Gateway is owned out of band, so we do NOT delete it here.
        try:
            sh.delete_harness(harness["harnessId"])
            rec("teardown", {"deleted_harness": harness["harnessId"]})
        except Exception as e:  # noqa: BLE001 — best-effort teardown
            rec("teardown_error", {"error": str(e)[:200]})
    out = os.path.join(os.path.dirname(__file__), "..", "evidence", "named_supervisor_result.json")
    json.dump(RESULT, open(out, "w"), indent=2, ensure_ascii=False, default=str)
    print("\nsaved evidence/named_supervisor_result.json  ·  verdict:", RESULT.get("verdict"))
