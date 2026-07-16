"""
sentinel-harness · benchmark unit-price & workload constants
============================================================
The dated, sourced, deliberately-conservative constants the deterministic
:mod:`sentinel_harness.benchmark` model computes over. Kept in a separate module
so a reviewer can audit — and a deployer can override — every number in one
place without touching the arithmetic.

.. warning::
   **VERIFY BEFORE QUOTING.** These are point-in-time, rounded, public list
   prices for *sizing*, not a billing guarantee. Real prices vary by region,
   commitment (Savings Plans / RIs), and negotiated rate. Change a constant here
   and the whole report recomputes; nothing downstream hardcodes a price.

``AS_OF`` records when these were last checked. All money is USD.

No customer- or company-specific data: the EKS shape is a *published* commodity
instance size; the workload default is a generic SecOps sizing.
"""
from __future__ import annotations

from dataclasses import dataclass

# When the unit prices below were last verified against public list pricing.
AS_OF = "2026-07"

# A calendar month modelled as 730 hours (365 × 24 / 12) — the standard AWS
# convention for turning an hourly rate into a monthly one.
HOURS_PER_MONTH = 730.0


# --------------------------------------------------------------------------- #
# Model token prices (USD per 1K tokens)                                      #
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class ModelPrice:
    """Per-1K-token input/output list price for one Bedrock model id."""

    input_per_1k: float
    output_per_1k: float


# Conservative, rounded public list prices (Bedrock, us-east-1, on-demand).
# VERIFY BEFORE QUOTING — see AS_OF. Keys are generic family names, not the
# version-pinned invoke ids (those live in core's SENTINEL_MODEL_* env).
MODEL_PRICES = {
    # Haiku-class: high-volume triage.
    "haiku": ModelPrice(input_per_1k=0.0008, output_per_1k=0.004),
    # Sonnet-class: rules / orchestration.
    "sonnet": ModelPrice(input_per_1k=0.003, output_per_1k=0.015),
    # Opus-class: deep research / meta-agent.
    "opus": ModelPrice(input_per_1k=0.015, output_per_1k=0.075),
}


# --------------------------------------------------------------------------- #
# Deployment-mode models                                                       #
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class ModeModel:
    """The compute/latency/ops model for one deployment mode.

    ``billing`` selects how :func:`benchmark.compute_cost_usd` prices the compute
    that hosts the agent loop:

    - ``"standing"`` uses ``hourly_usd × HOURS_PER_MONTH`` (always-on box).
    - ``"per_invoke"`` uses ``per_invoke_usd × invokes`` (idle is free).

    ``latency_overhead_ms`` is the NON-model latency floor a single invoke pays
    under this mode (cold start / scheduler / managed dispatch) — the model's own
    token-generation time is equal across modes and excluded. ``ops_hours_per_month``
    is the engineer-time to keep the mode running (patch/scale/on-call).
    ``owns_agent_loop`` flags whether YOU maintain the loop glue code."""

    key: str
    label: str
    billing: str                 # "standing" | "per_invoke"
    hourly_usd: float            # used when billing == "standing"
    per_invoke_usd: float        # used when billing == "per_invoke"
    latency_overhead_ms: float
    ops_hours_per_month: float
    owns_agent_loop: bool


# The three modes the report compares. Numbers are conservative sizing estimates
# (VERIFY BEFORE QUOTING); the RELATIVE shape (standing vs. idle-free, who owns
# the loop) is the durable, defensible point, not the exact dollar.
MODES = (
    ModeModel(
        key="raw_bedrock",
        label="Raw Bedrock + DIY loop",
        billing="standing",
        # A small always-on process (e.g. one 2 vCPU / 4 GB container) hosting the
        # hand-written agent loop. Cheap compute, but you own every line of glue.
        hourly_usd=0.10,
        per_invoke_usd=0.0,
        latency_overhead_ms=50.0,     # your own warm process: low dispatch overhead
        ops_hours_per_month=24.0,     # you maintain retries/memory/HITL/scaling code
        owns_agent_loop=True,
    ),
    ModeModel(
        key="self_hosted_eks",
        label="Self-hosted EKS cluster",
        billing="standing",
        # The customer's real pain shape: a standing 32 vCPU / 64 GB cluster
        # (~m6i.8xlarge-class) that bills 24×7 for a bursty SecOps workload,
        # plus cluster ops. Highest fixed cost + highest toil.
        hourly_usd=1.60,
        per_invoke_usd=0.0,
        latency_overhead_ms=20.0,     # warm cluster: lowest per-invoke floor...
        ops_hours_per_month=40.0,     # ...but cluster ops + on-call dominate toil
        owns_agent_loop=True,
    ),
    ModeModel(
        key="agentcore_harness",
        label="AgentCore Harness (managed)",
        billing="per_invoke",
        hourly_usd=0.0,
        # Thin managed per-invoke dispatch; idle is free (Runtime terminates idle).
        per_invoke_usd=0.002,
        latency_overhead_ms=120.0,    # managed dispatch/cold-path adds a floor...
        ops_hours_per_month=2.0,      # ...but platform owns loop/scaling/HITL toil
        owns_agent_loop=False,
    ),
)


# --------------------------------------------------------------------------- #
# Workload                                                                     #
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Workload:
    """A monthly SecOps agent workload to price.

    ``invokes_per_month`` × (``input_tokens`` + ``output_tokens``) per invoke is
    the token volume; the same shape drives per-invoke compute for the managed
    mode. ``name`` is a human label for the report header.

    All three numeric fields must be NON-NEGATIVE. A negative sizing produces
    negative-dollar / negative-percent nonsense (baseline=max of negatives flips
    the savings math), so it is rejected at construction (audited)."""

    name: str
    invokes_per_month: int
    input_tokens: int
    output_tokens: int

    def __post_init__(self) -> None:
        for field_name in ("invokes_per_month", "input_tokens", "output_tokens"):
            val = getattr(self, field_name)
            if not isinstance(val, int) or isinstance(val, bool) or val < 0:
                raise ValueError(
                    f"Workload.{field_name} must be a non-negative int, got {val!r}"
                )


# A generic, bursty SecOps default: ~200 triage-style invokes/day.
DEFAULT_WORKLOAD = Workload(
    name="generic SecOps triage",
    invokes_per_month=6000,
    input_tokens=4000,
    output_tokens=800,
)
