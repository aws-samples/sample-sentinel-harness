"""
sentinel-harness · deployment cost / latency / ops benchmark model
==================================================================
Turn the repo's recurring claim — *"a managed AgentCore Harness beats a
self-run agent loop on cost, latency floor, and operational toil"* — from
narrative into a **reproducible, defensible number**.

.. warning::
   **This is a DETERMINISTIC OFFLINE MODEL, not a live meter.** It computes what
   three deployment modes *would* cost/latency/toil for a given workload from
   published, dated unit-price constants (see ``benchmark_models.py``). It runs
   ZERO AWS, makes ZERO network calls, and reads no clock — same workload in →
   same figures out. It is a *sizing / procurement* tool: swap in your own
   verified prices and workload and it recomputes. It does **not** claim to have
   billed a real account; the one live token/latency signal the platform emits
   is ``observability.emit_token_metric`` (that is the measured half; this is the
   modelled half that puts the measured tokens into a cost/ops context).

Why this module exists
----------------------
A security team evaluating "AgentCore Harness vs. keep running our own agent
loop on EKS" asks three procurement questions the rest of the repo answered only
qualitatively:

  1. **Cost** — for N scenario-invokes/month at T tokens each, what do we pay
     under each mode (model tokens + the compute that hosts the agent loop)?
  2. **Latency floor** — what is the non-model overhead each mode adds to a
     single invoke (cold-start / queue / scheduler / managed dispatch)?
  3. **Operational toil** — how many engineer-hours/month does each mode cost to
     *keep running* (patching, scaling, on-call, capacity)?

The three modes (see ``benchmark_models.MODES``)
------------------------------------------------
- ``raw_bedrock`` — you call Bedrock ``InvokeModel`` directly and hand-write the
  agent loop (retries, memory, tool routing, HITL) in your own always-on process.
  Cheapest raw compute, maximum glue code and toil, you own the loop.
- ``self_hosted_eks`` — the agent loop runs on a standing EKS cluster you operate
  (the customer's real "32-core / 64 GB, 50–60 DAG Airflow" shape). Fixed monthly
  compute whether or not it is busy; highest toil (cluster ops + on-call).
- ``agentcore_harness`` — the managed two-plane Harness runs the loop. You pay
  model tokens + a thin managed per-invoke dispatch; **idle costs nothing**
  (Runtime bills only while serving, terminates idle), and the loop/scaling/HITL
  are the platform's toil, not yours.

Determinism & honesty
----------------------
Every figure is ``workload × a dated unit-price constant``. No randomness, no
clock, no I/O. The constants live in ``benchmark_models.py`` with a source note
and an ``AS_OF`` date; they are deliberately conservative and clearly labelled
"verify before quoting". This module is the pure arithmetic over them.

Nothing here is customer- or company-specific: the default workload is a generic
SecOps sizing; the EKS shape mirrors a *published* commodity instance, not any
real deployment.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from .benchmark_models import (
    HOURS_PER_MONTH,
    MODEL_PRICES,
    MODES,
    ModeModel,
    Workload,
)

# --------------------------------------------------------------------------- #
# Result shapes                                                               #
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class CostBreakdown:
    """Monthly USD cost for one mode, split so a reviewer can audit each part.

    ``model_usd`` is identical across modes for the same workload+model (you pay
    Bedrock the same per token however you host the loop) — the differentiator is
    ``compute_usd`` (what hosts the loop) and, downstream, the ops-hours."""

    mode: str
    model_usd: float
    compute_usd: float
    total_usd: float


@dataclass(frozen=True)
class ModeResult:
    """Everything the benchmark computes for a single deployment mode."""

    mode: str
    label: str
    cost: CostBreakdown
    latency_overhead_ms: float          # non-model latency floor per invoke
    ops_hours_per_month: float          # engineer-hours to keep it running
    owns_agent_loop: bool               # do YOU maintain the loop glue code?


@dataclass(frozen=True)
class BenchmarkReport:
    """The full comparison over all modes for one workload.

    ``baseline`` is the most expensive total (so savings read as "vs. worst
    case"); ``cheapest`` is the min total. ``results`` is sorted cheapest-first."""

    workload: Workload
    model_id: str
    results: List[ModeResult]
    cheapest_mode: str
    baseline_mode: str
    savings_vs_baseline_usd: float
    savings_vs_baseline_pct: float
    notes: List[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Core arithmetic (pure, deterministic)                                       #
# --------------------------------------------------------------------------- #
def model_cost_usd(workload: Workload, model_id: str) -> float:
    """Monthly Bedrock token cost for the workload under ``model_id``.

    ``invokes_per_month × (input_tokens × in_price + output_tokens × out_price)``,
    prices are USD per 1K tokens (``MODEL_PRICES``). Identical across deployment
    modes — hosting the loop elsewhere does not change what Bedrock charges per
    token — which is exactly why the *compute* and *ops* axes are the real
    differentiators the report highlights."""
    if model_id not in MODEL_PRICES:
        raise KeyError(
            f"unknown model_id {model_id!r}; known: {sorted(MODEL_PRICES)}"
        )
    price = MODEL_PRICES[model_id]
    per_invoke = (
        workload.input_tokens / 1000.0 * price.input_per_1k
        + workload.output_tokens / 1000.0 * price.output_per_1k
    )
    return per_invoke * workload.invokes_per_month


def compute_cost_usd(workload: Workload, mode: ModeModel) -> float:
    """Monthly compute cost of *hosting the agent loop* under ``mode``.

    Two shapes, chosen by ``mode.billing``:

    - ``"standing"`` (raw_bedrock process, self_hosted_eks): a fixed always-on
      box — ``hourly_usd × HOURS_PER_MONTH`` — paid whether busy or idle. This is
      the crux of the customer's Airflow pain: a 32c/64G cluster bills 24×7 for a
      bursty SecOps workload.
    - ``"per_invoke"`` (agentcore_harness): pay only per served invoke
      (``per_invoke_usd × invokes_per_month``); **idle is free** (Runtime
      terminates idle, bills only while serving). For a bursty workload this is
      dramatically less than a standing box — the modelled version of the repo's
      "idle costs nothing" claim."""
    if mode.billing == "standing":
        return mode.hourly_usd * HOURS_PER_MONTH
    if mode.billing == "per_invoke":
        return mode.per_invoke_usd * workload.invokes_per_month
    raise ValueError(f"unknown billing shape {mode.billing!r} for mode {mode.key!r}")


def run_benchmark(workload: Workload, model_id: str) -> BenchmarkReport:
    """Compute the full three-mode comparison for ``workload`` + ``model_id``.

    Deterministic: builds one :class:`ModeResult` per mode in ``MODES``, then
    ranks by total monthly USD. Savings are reported *cheapest vs. the most
    expensive mode* so a procurement reader sees the worst-case gap the managed
    mode closes. Same inputs → byte-identical report."""
    results: List[ModeResult] = []
    for mode in MODES:
        model_usd = model_cost_usd(workload, model_id)
        compute_usd = compute_cost_usd(workload, mode)
        # Round the parts first, then sum the ROUNDED parts for the total, so
        # model_usd + compute_usd == total_usd to 2-decimal (cent) precision
        # (independently rounding the sum can drift by a cent — a property test
        # caught that). NOTE: these are IEEE-754 floats, so exact `==` on the
        # stored parts vs the stored total is NOT guaranteed (0.06 may store as
        # 0.060000000000000005); compare with a cent tolerance / round(...,2),
        # not bare ==. The dollar figures are correct to the cent.
        model_r = round(model_usd, 2)
        compute_r = round(compute_usd, 2)
        results.append(
            ModeResult(
                mode=mode.key,
                label=mode.label,
                cost=CostBreakdown(
                    mode=mode.key,
                    model_usd=model_r,
                    compute_usd=compute_r,
                    total_usd=round(model_r + compute_r, 2),
                ),
                latency_overhead_ms=mode.latency_overhead_ms,
                ops_hours_per_month=mode.ops_hours_per_month,
                owns_agent_loop=mode.owns_agent_loop,
            )
        )

    results.sort(key=lambda r: r.cost.total_usd)
    cheapest = results[0]
    baseline = max(results, key=lambda r: r.cost.total_usd)
    savings = baseline.cost.total_usd - cheapest.cost.total_usd
    pct = (savings / baseline.cost.total_usd * 100.0) if baseline.cost.total_usd else 0.0

    notes = [
        "Deterministic model over dated unit prices — verify prices before quoting "
        "(see benchmark_models.AS_OF).",
        "model_usd is identical across modes; the differentiators are compute_usd "
        "(who hosts the loop) and ops_hours_per_month (who keeps it running).",
    ]
    return BenchmarkReport(
        workload=workload,
        model_id=model_id,
        results=results,
        cheapest_mode=cheapest.mode,
        baseline_mode=baseline.mode,
        savings_vs_baseline_usd=round(savings, 2),
        savings_vs_baseline_pct=round(pct, 1),
        notes=notes,
    )


# --------------------------------------------------------------------------- #
# Rendering                                                                   #
# --------------------------------------------------------------------------- #
def report_to_dict(report: BenchmarkReport) -> Dict:
    """Serialize a :class:`BenchmarkReport` to a plain JSON-able dict (evidence)."""
    return {
        "workload": {
            "name": report.workload.name,
            "invokes_per_month": report.workload.invokes_per_month,
            "input_tokens": report.workload.input_tokens,
            "output_tokens": report.workload.output_tokens,
        },
        "model_id": report.model_id,
        "modes": [
            {
                "mode": r.mode,
                "label": r.label,
                "model_usd": r.cost.model_usd,
                "compute_usd": r.cost.compute_usd,
                "total_usd": r.cost.total_usd,
                "latency_overhead_ms": r.latency_overhead_ms,
                "ops_hours_per_month": r.ops_hours_per_month,
                "owns_agent_loop": r.owns_agent_loop,
            }
            for r in report.results
        ],
        "cheapest_mode": report.cheapest_mode,
        "baseline_mode": report.baseline_mode,
        "savings_vs_baseline_usd": report.savings_vs_baseline_usd,
        "savings_vs_baseline_pct": report.savings_vs_baseline_pct,
        "notes": report.notes,
    }


def report_to_markdown(report: BenchmarkReport) -> str:
    """Render a procurement-ready Markdown table + headline for the report.

    Pure string building (no I/O). The table columns mirror the three procurement
    questions: monthly cost (split model/compute/total), per-invoke latency floor,
    and monthly ops-hours; a trailing column flags who owns the loop glue code."""
    w = report.workload
    lines: List[str] = []
    lines.append(f"# Deployment benchmark — {w.name}")
    lines.append("")
    lines.append(
        f"Workload: **{w.invokes_per_month:,} invokes/mo** · "
        f"{w.input_tokens:,} in + {w.output_tokens:,} out tokens/invoke · "
        f"model `{report.model_id}`."
    )
    lines.append("")
    lines.append(
        "| Mode | Model $/mo | Compute $/mo | **Total $/mo** | Latency floor | Ops hrs/mo | Owns loop? |"
    )
    lines.append(
        "|---|--:|--:|--:|--:|--:|:--:|"
    )
    for r in report.results:
        cheapest = " ✅" if r.mode == report.cheapest_mode else ""
        lines.append(
            f"| {r.label}{cheapest} | ${r.cost.model_usd:,.2f} | ${r.cost.compute_usd:,.2f} | "
            f"**${r.cost.total_usd:,.2f}** | {r.latency_overhead_ms:,.0f} ms | "
            f"{r.ops_hours_per_month:,.1f} | {'you' if r.owns_agent_loop else 'platform'} |"
        )
    lines.append("")
    lines.append(
        f"**Headline:** `{report.cheapest_mode}` is the cheapest at "
        f"**${report.results[0].cost.total_usd:,.2f}/mo**, saving "
        f"**${report.savings_vs_baseline_usd:,.2f}/mo "
        f"({report.savings_vs_baseline_pct:.1f}%)** vs. the most expensive mode "
        f"(`{report.baseline_mode}`)."
    )
    lines.append("")
    for n in report.notes:
        lines.append(f"> {n}")
    lines.append("")
    return "\n".join(lines)
