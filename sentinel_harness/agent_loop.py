"""
sentinel-harness · agent-authored orchestration driver
=======================================================
Closes the last north-star gap: in ``scenario_self_improve_loop`` (M12) and the C1
controller (M13.7) the improve→score→gate→promote DECISIONS were authored by
Python — a runner script or the deterministic controller. This module inverts
that: the **agent authors the loop** by emitting tool calls from inside its
harness (``stop_reason == "tool_use"``), and the driver here only **executes and
guards** — it dispatches each call to a deterministic handler, resumes the
session with the two-message HITL contract, and enforces the promotion policy
*outside* the agent, so a confused or adversarial agent can never promote by
assertion.

.. warning::
   **Deterministic, offline-first, fail-closed.** The driver never reads a clock,
   opens a socket, or calls AWS itself — the session I/O is two INJECTED
   callables (``invoke_fn`` / ``resume_fn``), so the SAME driver runs (a) fully
   offline in CI against a scripted fake agent, and (b) live with
   ``core.invoke`` / ``core.invoke_with_tool_results`` over a real
   self-improving harness. Same tool-call stream → identical decision trace.

The trust model (why the guards live here, not in the prompt)
-------------------------------------------------------------
The self-improving harness's system prompt already tells it "promote only when
passing and approved" — but a prompt is advice, not enforcement. The driver is
the enforcement point:

- **Promotion is witness-gated.** A promotion tool call is executed ONLY if the
  driver itself has WITNESSED, in this session, (1) an evaluation result that
  clears ``autonomy.evaluate_gate`` (pass bar + safety veto + regression guard)
  and (2) a human approval via the HITL gate. An agent that "skips ahead" gets a
  structured refusal as its tool result — visible to the agent, recorded in the
  trace — never a silent success.
- **The eval score is read from the HANDLER's return, never the agent's words.**
  The agent cannot claim a score; only the ``run_evaluation`` handler's actual
  output updates the witnessed gate state.
- **Hard caps.** ``max_tool_calls`` bounds the total dispatched calls; an agent
  that spins terminates with ``stopped_by == "cap"`` — never an infinite loop.
- **Allowlist.** Only tools in the dispatch table (plus the HITL gate) exist; an
  unknown tool call gets a structured error result, not a crash and not an
  execution.

Wiring (live)
-------------
::

    from sentinel_harness import agent_loop, core

    session = core.new_session("agent_loop")
    result = agent_loop.run_agent_loop(
        invoke_fn=lambda: core.invoke(arn, session, task),
        resume_fn=lambda answers: core.invoke_with_tool_results(arn, session, answers),
        dispatch={"run_evaluation": run_eval_handler, "harness_ops": harness_ops_handler},
        hitl_tool="request_promotion_approval",
        approve_fn=analyst_decision,
        threshold=0.7,
    )

Nothing here is customer- or company-specific.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from . import autonomy

# --------------------------------------------------------------------------- #
# Injected-callable shapes (documentation — not enforced at runtime)          #
# --------------------------------------------------------------------------- #
# invoke_fn() -> the FIRST core.invoke-shaped result:
#   {"text", "stop_reason", "tool_use", "tool_uses", ...}
InvokeFn = Callable[[], Dict[str, Any]]
# resume_fn(answers) -> the NEXT core.invoke-shaped result, where answers is a
# list of (tool_use, result_json_str) pairs — one per paused gate, ALL answered
# (core.invoke_with_tool_results' contract).
ResumeFn = Callable[[List[Any]], Dict[str, Any]]
# A tool handler: (input_dict) -> JSON-able dict (the tool result).
ToolHandler = Callable[[Dict[str, Any]], Dict[str, Any]]
# approve_fn(tool_input) -> bool — the human decision at the HITL gate.
HitlApproveFn = Callable[[Dict[str, Any]], bool]
# is_promotion(tool_name, tool_input) -> bool — which calls are promotion attempts.
PromotionPredicate = Callable[[str, Dict[str, Any]], bool]


def default_is_promotion(tool_name: str, tool_input: Dict[str, Any]) -> bool:
    """The shipped promotion shapes: ``harness_ops`` with any endpoint-creating action.

    ``create_endpoint`` (first promotion), ``update_endpoint`` (v2+ re-promotion),
    and ``promote_endpoint`` (idempotent create-or-update) are all promotion paths.
    The driver witness-gates all of them. Inject your own predicate for a different
    promotion surface."""
    return (tool_name == "harness_ops"
            and tool_input.get("action") in ("create_endpoint", "update_endpoint", "promote_endpoint"))


@dataclass(frozen=True)
class ToolCallRecord:
    """One dispatched (or refused) tool call — the auditable per-call record."""

    seq: int
    tool: str
    action: str                    # tool_input["action"] if present, else ""
    outcome: str                   # executed | refused_promotion | hitl | unknown_tool | handler_error
    detail: str = ""


@dataclass(frozen=True)
class AgentLoopResult:
    """Full outcome of one agent-authored session — an audit record.

    ``promoted`` is the bottom line; ``stopped_by`` says why the loop ended
    (``end_turn`` — the agent finished; ``cap`` — hit ``max_tool_calls``;
    ``session_error`` — invoke/resume raised). The witnessed gate state and the
    per-call trace show exactly what the driver saw and enforced."""

    promoted: bool
    stopped_by: str
    tool_calls_used: int
    trace: List[ToolCallRecord]
    final_text: str
    witnessed_pass: bool           # driver saw an eval clear every machine gate
    witnessed_approval: bool       # driver saw the human approve at the HITL gate
    refused_promotions: int        # promotion attempts the driver refused
    final_gate_reason: str = ""
    notes: List[str] = field(default_factory=list)


def result_to_dict(result: AgentLoopResult) -> Dict[str, Any]:
    """Serialize an :class:`AgentLoopResult` to a JSON-able dict (evidence)."""
    return {
        "promoted": result.promoted,
        "stopped_by": result.stopped_by,
        "tool_calls_used": result.tool_calls_used,
        "witnessed_pass": result.witnessed_pass,
        "witnessed_approval": result.witnessed_approval,
        "refused_promotions": result.refused_promotions,
        "final_gate_reason": result.final_gate_reason,
        "final_text": result.final_text,
        "trace": [
            {"seq": r.seq, "tool": r.tool, "action": r.action,
             "outcome": r.outcome, "detail": r.detail}
            for r in result.trace
        ],
        "notes": result.notes,
    }


def _tool_result_json(payload: Dict[str, Any]) -> str:
    """Serialize a tool result for the resume contract (compact, deterministic)."""
    return json.dumps(payload, sort_keys=True, default=str)


def run_agent_loop(
    invoke_fn: InvokeFn,
    resume_fn: ResumeFn,
    dispatch: Dict[str, ToolHandler],
    *,
    eval_tool: str = "run_evaluation",
    hitl_tool: str = "request_promotion_approval",
    approve_fn: Optional[HitlApproveFn] = None,
    is_promotion: PromotionPredicate = default_is_promotion,
    threshold: float,
    incumbent_best: Optional[float] = None,
    require_strict_improvement: bool = False,
    max_tool_calls: int = 20,
) -> AgentLoopResult:
    """Run one agent-authored improvement session, guarding every tool call.

    Parameters
    ----------
    invoke_fn / resume_fn:
        The session I/O seam (``core.invoke`` / ``core.invoke_with_tool_results``
        closures live; scripted fakes offline). ``resume_fn`` receives the FULL
        answer list — one ``(tool_use, result_json)`` per paused gate.
    dispatch:
        ``{tool_name: handler}`` — the deterministic handlers the agent may
        drive (e.g. ``run_evaluation``, ``harness_ops``). This is the allowlist;
        an unknown tool gets a structured error result, never an execution.
    eval_tool:
        The scoring tool's name. Its handler's ACTUAL return (never the agent's
        claim) feeds :func:`autonomy.evaluate_gate` to update the witnessed
        gate state.
    hitl_tool:
        The inline_function human gate. Answered via ``approve_fn`` — a missing
        ``approve_fn`` means the human REFUSED (fail-closed, same policy as the
        C1 controller).
    is_promotion:
        Predicate marking which calls are promotion attempts (default:
        ``harness_ops`` + ``action=create_endpoint``). Those execute ONLY when
        the driver has witnessed a passing eval AND a human approval.
    threshold / incumbent_best / require_strict_improvement:
        The machine-gate policy, evaluated by ``autonomy.evaluate_gate`` — the
        SAME veto/guard the rest of the platform uses.
    max_tool_calls:
        Hard cap on dispatched calls (>=1). The anti-spin guarantee.

    Returns
    -------
    An :class:`AgentLoopResult` audit record. Deterministic given deterministic
    injected callables.
    """
    if max_tool_calls < 1:
        raise ValueError("max_tool_calls must be >= 1")
    if not (0.0 <= threshold <= 1.0):
        raise ValueError("threshold must be in [0, 1]")

    trace: List[ToolCallRecord] = []
    witnessed_pass = False
    witnessed_approval = False
    refused_promotions = 0
    promoted = False
    final_gate_reason = ""
    calls_used = 0
    seq = 0

    try:
        result = invoke_fn()
    except Exception as exc:  # noqa: BLE001 — session boundary: audit, don't crash
        return AgentLoopResult(
            promoted=False, stopped_by="session_error", tool_calls_used=0,
            trace=[], final_text="", witnessed_pass=False,
            witnessed_approval=False, refused_promotions=0,
            final_gate_reason=f"invoke failed: {exc}",
            notes=["Session error on the first invoke — nothing executed."],
        )

    stopped_by = "end_turn"
    while result.get("stop_reason") == "tool_use":
        pending = result.get("tool_uses") or (
            [result["tool_use"]] if result.get("tool_use") else []
        )
        if not pending:
            # A tool_use stop with no reconstructed call — treat as done, not a spin.
            stopped_by = "end_turn"
            break

        answers: List[Any] = []
        hit_cap = False
        for tu in pending:
            if calls_used >= max_tool_calls:
                hit_cap = True
                # Answer the remaining gates with a refusal so the resume contract
                # (answer EVERY pending gate) still holds while we terminate.
                answers.append((tu, _tool_result_json(
                    {"ok": False, "error": "tool_call_cap",
                     "message": f"driver cap of {max_tool_calls} tool calls reached"}), "error"))
                continue
            calls_used += 1
            seq += 1
            name = tu.get("name", "")
            tool_input = tu.get("input", {}) or {}
            action = str(tool_input.get("action", ""))

            # 1) The HITL gate — the human answers, and the driver WITNESSES it.
            if name == hitl_tool:
                decision = bool(approve_fn(tool_input)) if approve_fn is not None else False
                witnessed_approval = decision
                trace.append(ToolCallRecord(
                    seq=seq, tool=name, action=action, outcome="hitl",
                    detail=f"human {'APPROVED' if decision else 'REJECTED'}"))
                answers.append((tu, _tool_result_json(
                    {"approved": decision,
                     "message": "approved by analyst" if decision else "rejected by analyst"})))
                continue

            # 2) Promotion attempts — witness-gated OUTSIDE the agent.
            if is_promotion(name, tool_input):
                if not (witnessed_pass and witnessed_approval):
                    refused_promotions += 1
                    missing = []
                    if not witnessed_pass:
                        missing.append("no witnessed passing evaluation")
                    if not witnessed_approval:
                        missing.append("no witnessed human approval")
                    detail = "; ".join(missing)
                    trace.append(ToolCallRecord(
                        seq=seq, tool=name, action=action,
                        outcome="refused_promotion", detail=detail))
                    answers.append((tu, _tool_result_json(
                        {"ok": False, "error": "promotion_refused",
                         "message": f"driver refused promotion: {detail}. "
                                    "Score via the evaluation tool and obtain human "
                                    "approval before promoting."}), "error"))
                    continue
                # Both witnessed — fall through to real execution below.

            # 3) Allowlist — unknown tools are refused with a structured error.
            handler = dispatch.get(name)
            if handler is None:
                trace.append(ToolCallRecord(
                    seq=seq, tool=name, action=action, outcome="unknown_tool",
                    detail=f"not in dispatch allowlist {sorted(dispatch)}"))
                answers.append((tu, _tool_result_json(
                    {"ok": False, "error": "unknown_tool",
                     "message": f"tool {name!r} is not available"}), "error"))
                continue

            # 4) Execute the deterministic handler.
            try:
                out = handler(tool_input)
            except Exception as exc:  # noqa: BLE001 — a handler bug must not kill the session
                trace.append(ToolCallRecord(
                    seq=seq, tool=name, action=action, outcome="handler_error",
                    detail=f"{type(exc).__name__}: {exc}"))
                answers.append((tu, _tool_result_json(
                    {"ok": False, "error": "handler_error",
                     "message": f"{type(exc).__name__}: {exc}"}), "error"))
                continue

            outcome = "executed"
            detail = ""
            # 5) The eval tool's ACTUAL return updates the witnessed gate state.
            if name == eval_tool and isinstance(out, dict):
                gate = autonomy.evaluate_gate(
                    out, threshold=threshold, incumbent_best=incumbent_best,
                    require_strict_improvement=require_strict_improvement,
                )
                witnessed_pass = gate["promotable_pre_human"]
                final_gate_reason = gate["reason"]
                detail = ("gate PASSED" if witnessed_pass else "gate failed") + f": {gate['reason']}"
            elif is_promotion(name, tool_input):
                promoted = True
                detail = "promotion executed (witnessed pass + approval)"

            trace.append(ToolCallRecord(
                seq=seq, tool=name, action=action, outcome=outcome, detail=detail))
            answers.append((tu, _tool_result_json(out)))

        try:
            result = resume_fn(answers)
        except Exception as exc:  # noqa: BLE001 — session boundary: audit, don't crash
            stopped_by = "session_error"
            final_gate_reason = final_gate_reason or f"resume failed: {exc}"
            break

        if hit_cap:
            stopped_by = "cap"
            break

    return AgentLoopResult(
        promoted=promoted,
        stopped_by=stopped_by,
        tool_calls_used=calls_used,
        trace=trace,
        final_text=str(result.get("text", "")),
        witnessed_pass=witnessed_pass,
        witnessed_approval=witnessed_approval,
        refused_promotions=refused_promotions,
        final_gate_reason=final_gate_reason,
        notes=[
            "Agent-authored: every step came from the agent's tool_use stream; "
            "the driver only dispatched and guarded (witness-gated promotion, "
            "allowlist, hard cap).",
            "The witnessed eval score comes from the handler's actual return, "
            "never the agent's claim.",
        ],
    )
