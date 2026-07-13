"""
sentinel-harness · M6 feedback engine (event-driven strategy self-iteration)
=============================================================================
Layer 3 (cyber-skills) · the FEEDBACK LOOP that closes the loop between
alert-triage *dispositions* and the *detection strategy* that produced them.

WHY this module exists
----------------------
M1/M2 gave the harness a self-improving detection loop; M5 gave it a mock world
and an end-to-end alert-triage POC that emits a disposition
(``true_positive`` / ``false_positive`` / ``benign``). M6 is the missing edge:
those dispositions must FEED BACK into the strategy so noisy rules get their
allowlist tightened and dead rules get regenerated — automatically, on the
event stream, not by a human eyeballing a dashboard.

This is the deterministic, offline heart of that loop:

1. :func:`record_disposition` folds a batch of :class:`FeedbackEvent`\\ s into a
   per-rule *ledger* (tp/fp counts + an ``fp_rate``). Conceptually this is the
   "write the analyst verdicts to Memory ``facts/{tenant}``" step — modeled
   deterministically here. A ``memory_writer`` callable can be injected to
   actually persist it (see :func:`managed_memory_writer` for the documented
   hook that WOULD call ``core.managed_memory`` under a per-``actorId``
   ``facts/{tenant}`` namespace). The default is a pure in-memory store, so the
   whole engine is offline-testable with ZERO AWS.
2. :func:`detect_triggers` turns that ledger into concrete improvement TASKS
   using explicit thresholds: a rule that is mostly false-positive over enough
   events emits a ``whitelist_optimization`` task; a rule that produced ONLY
   false positives (a dead/misfiring rule) emits a ``rule_regeneration`` task.

Honesty / what is real vs. stubbed
----------------------------------
- The feedback ENGINE, the fp_rate math, the trigger thresholds and the task
  generation are REAL deterministic offline logic (same input -> same output).
- The ``whitelist_optimization`` task is a real, directly-actionable artifact
  (it names the exact FP alert cohort to suppress).
- The ``rule_regeneration`` task is a *request* to the EXISTING M1/M2
  self-improving loop (harnesses/self-improving + tools/run_evaluation +
  scenarios/scenario_detection_gen). Running that loop is live-capable; here it
  is driven in-process/offline for the POC. This module does NOT itself call an
  LLM, stand up AWS, or claim to regenerate a rule live — it only emits the task.

Egress & secrets posture
-------------------------
- Egress is CONTROLLED: the default path has ZERO network / AWS / LLM I/O. It
  reads only its in-memory inputs. The AWS-backed persistence path is opt-in via
  an injected ``memory_writer`` (never the default).
- No secrets, no hardcoded account ids / ARNs. All identifiers are the
  clearly-fictional mock-world ids (RFC 5737 IPs, ``example.test`` hosts).
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

__all__ = [
    "FeedbackEvent",
    "TenantFactStore",
    "record_disposition",
    "detect_triggers",
    "detect_score_decay",
    "managed_memory_writer",
    "DISPOSITIONS",
    "FP_DISPOSITION",
    "TP_DISPOSITION",
    "SCORE_DECAY_TRIGGER",
    "REGENERATION_TASK_TYPE",
    "REGENERATION_TARGET",
]

# The three dispositions the M5 alert-triage POC emits. ``benign`` is a
# *non-actionable* real event (expected, allowlisted) — for feedback purposes it
# counts as a false positive of the *detection* (the rule should not have paged),
# so it feeds the same fp_rate as an explicit false_positive.
TP_DISPOSITION = "true_positive"
FP_DISPOSITION = "false_positive"
BENIGN_DISPOSITION = "benign"
DISPOSITIONS = (TP_DISPOSITION, FP_DISPOSITION, BENIGN_DISPOSITION)

# A disposition is "noise" (feeds fp_rate) unless it is a confirmed true positive.
_NOISE = (FP_DISPOSITION, BENIGN_DISPOSITION)

# --- eval-score-decay trigger vocabulary (M12) ---------------------------
# The trigger *type* recorded on a score-decay task, distinguishing WHY the
# regeneration was requested (a decayed eval score) from the disposition-driven
# only-FP regeneration in :func:`detect_triggers`. Both emit the SAME task
# ``type`` / ``target`` so the M1/M2 loop consumes them identically.
SCORE_DECAY_TRIGGER = "eval_score_decay"
# The task shape mirrors the existing ``rule_regeneration`` trigger in
# :func:`detect_triggers` (same ``type`` string, same self-improving-loop target)
# so a decayed harness is handed off through the identical regeneration path.
REGENERATION_TASK_TYPE = "rule_regeneration"
REGENERATION_TARGET = "m1_m2_self_improving_loop"


# --------------------------------------------------------------------------
# The event: one analyst/agent disposition of one fired alert.
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class FeedbackEvent:
    """A single triage disposition fed back into the detection strategy.

    Mirrors the verdict the M5 alert-triage POC produces for one alert. Frozen
    so an event is an immutable fact once recorded (safe to hash / dedupe).

    Parameters
    ----------
    alert_id:
        The fired alert's id (e.g. ``"alert-1010"``). Required.
    rule_name:
        The detection rule that produced the alert (the feedback grouping key,
        e.g. ``"Known-Good CDN Traffic"``). Required.
    disposition:
        One of :data:`DISPOSITIONS` — the analyst/agent verdict.
    host:
        The mock host the alert named (``example.test`` world). Optional.
    indicators:
        The indicators (IPs/domains/hashes) the alert carried — the raw material
        a ``whitelist_optimization`` task turns into suppression predicates.
    ts:
        ISO-8601 timestamp string of the disposition. Carried through verbatim;
        never parsed for clock logic (determinism).
    analyst:
        Who/what dispositioned it (an analyst id or the triage agent). Optional.
    """

    alert_id: str
    rule_name: str
    disposition: str
    host: Optional[str] = None
    indicators: List[str] = field(default_factory=list)
    ts: Optional[str] = None
    analyst: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.alert_id:
            raise ValueError("FeedbackEvent requires a non-empty alert_id")
        if not self.rule_name:
            raise ValueError("FeedbackEvent requires a non-empty rule_name")
        if self.disposition not in DISPOSITIONS:
            raise ValueError(
                f"disposition must be one of {DISPOSITIONS}, got {self.disposition!r}"
            )

    def to_fact(self) -> Dict[str, Any]:
        """Serialize to a plain JSON-able fact (the shape written to Memory)."""
        return {
            "alert_id": self.alert_id,
            "rule_name": self.rule_name,
            "disposition": self.disposition,
            "host": self.host,
            "indicators": list(self.indicators),
            "ts": self.ts,
            "analyst": self.analyst,
        }


# --------------------------------------------------------------------------
# Tenant-namespaced fact store: the offline stand-in for Memory facts/{tenant}.
# --------------------------------------------------------------------------
class TenantFactStore:
    """A tiny tenant-namespaced verdict store (offline default, injectable).

    Models AgentCore managed Memory's ``actorId`` isolation: every tenant's
    facts live under their own ``facts/{tenant}`` namespace and never leak into
    another tenant's ledger. The default implementation is a pure in-memory dict
    so tests are 100% offline; a real deployment injects a ``writer`` that
    persists into managed Memory (see :func:`managed_memory_writer`).

    The store is *append-only* per namespace, mirroring how memory facts
    accumulate — this makes recording deterministic and inspectable.
    """

    def __init__(self, writer: Optional[Callable[[str, Dict[str, Any]], None]] = None) -> None:
        # namespace -> list of appended facts (insertion order preserved).
        self._facts: Dict[str, List[Dict[str, Any]]] = {}
        # Optional side-effecting persistence hook. None => pure in-memory.
        self._writer = writer

    @staticmethod
    def namespace(tenant: str) -> str:
        """The per-tenant fact namespace, mirroring Memory ``facts/{tenant}``."""
        if not tenant:
            raise ValueError("tenant must be a non-empty string")
        return f"facts/{tenant}"

    def append(self, tenant: str, fact: Dict[str, Any]) -> None:
        """Append one fact under the tenant namespace, then fan out to writer."""
        ns = self.namespace(tenant)
        self._facts.setdefault(ns, []).append(fact)
        if self._writer is not None:
            # Injected persistence (e.g. a managed-Memory write). Never called on
            # the default offline path.
            self._writer(ns, fact)

    def facts(self, tenant: str) -> List[Dict[str, Any]]:
        """Return a COPY of the facts recorded for one tenant (never shared)."""
        return list(self._facts.get(self.namespace(tenant), []))


def managed_memory_writer(actor_id: str, *, strategies: Optional[List[str]] = None) -> Callable[[str, Dict[str, Any]], None]:
    """Documented (opt-in) hook that WOULD persist a fact into managed Memory.

    This is the bridge to :func:`sentinel_harness.core.managed_memory`. It is
    imported lazily so this module stays import-safe and ZERO-AWS on the default
    path; constructing the writer does not touch AWS, and the returned callable
    is only wired in when a caller explicitly injects it into
    :func:`record_disposition`.

    In a live deployment the returned callable would create/reference a managed
    Memory (``core.managed_memory([SEMANTIC, SUMMARIZATION])``) and write each
    fact under the ``facts/{tenant}`` slice of the harness's per-``actorId``
    namespace — the same isolation boundary the rest of the harness uses. We do
    NOT perform that write here (no network in this repo's default path); the
    callable is a labeled seam, not a live client.
    """

    def _write(namespace: str, fact: Dict[str, Any]) -> None:  # pragma: no cover - live seam
        # Lazy import keeps the default offline path free of any AWS surface.
        from . import core  # noqa: F401  (imported for the documented live seam)

        # A real implementation would resolve the managed-memory config and
        # persist `fact` under actor_id/{namespace}. Intentionally left as a
        # labeled hook: this module never runs a live write in the POC.
        _ = (core.managed_memory(strategies), actor_id, namespace, fact)

    return _write


# --------------------------------------------------------------------------
# Step 1 — record dispositions into a per-rule ledger (the Memory-write step).
# --------------------------------------------------------------------------
def record_disposition(
    events: List[FeedbackEvent],
    *,
    tenant: str = "default",
    store: Optional[TenantFactStore] = None,
    memory_writer: Optional[Callable[[str, Dict[str, Any]], None]] = None,
) -> Dict[str, Any]:
    """Fold triage dispositions into a deterministic per-rule feedback ledger.

    This is the "write verdicts to Memory ``facts/{tenant}``" step, modeled
    deterministically: every event is appended to the tenant-namespaced
    :class:`TenantFactStore` (so verdicts persist per ``actorId``), and the same
    events are aggregated into a per-``rule_name`` ledger with ``tp_count`` /
    ``fp_count`` and an ``fp_rate``.

    Parameters
    ----------
    events:
        The batch of :class:`FeedbackEvent`\\ s to record.
    tenant:
        The tenant / ``actorId`` slice to namespace facts under.
    store:
        An injectable :class:`TenantFactStore`. Defaults to a fresh in-memory
        store (offline). Pass a shared store to accumulate across batches.
    memory_writer:
        Optional persistence callable ``(namespace, fact) -> None`` used only if
        ``store`` is not given — lets a caller opt into real Memory writes (e.g.
        :func:`managed_memory_writer`) without changing the default offline path.

    Returns
    -------
    A ledger dict::

        {
            "tenant": "default",
            "namespace": "facts/default",
            "total_events": 5,
            "rules": {
                "Known-Good CDN Traffic": {
                    "rule_name": "Known-Good CDN Traffic",
                    "tp_count": 0,
                    "fp_count": 3,
                    "total": 3,
                    "fp_rate": 1.0,
                    "fp_alert_ids": ["alert-1010", ...],
                    "fp_indicators": ["192.0.2.10", ...],
                    "dispositions": {"true_positive": 0, "false_positive": 2, "benign": 1},
                },
                ...
            },
        }

    Determinism: pure function of ``events`` (rule keys and id/indicator lists
    are order-preserving + de-duplicated). No clock, no randomness, no network.
    """
    if store is None:
        store = TenantFactStore(writer=memory_writer)
    elif memory_writer is not None:
        raise ValueError("pass either `store` or `memory_writer`, not both")

    rules: Dict[str, Dict[str, Any]] = {}
    total = 0
    for ev in events:
        if not isinstance(ev, FeedbackEvent):  # defensive: no silent coercion
            raise TypeError(f"expected FeedbackEvent, got {type(ev).__name__}")
        total += 1
        # Persist the raw verdict under facts/{tenant} (the Memory-write step).
        store.append(tenant, ev.to_fact())

        r = rules.get(ev.rule_name)
        if r is None:
            r = {
                "rule_name": ev.rule_name,
                "tp_count": 0,
                "fp_count": 0,
                "total": 0,
                "fp_rate": 0.0,
                "fp_alert_ids": [],
                "fp_indicators": [],
                "dispositions": {d: 0 for d in DISPOSITIONS},
            }
            rules[ev.rule_name] = r

        r["total"] += 1
        r["dispositions"][ev.disposition] += 1
        if ev.disposition == TP_DISPOSITION:
            r["tp_count"] += 1
        else:  # false_positive or benign -> detection noise
            r["fp_count"] += 1
            if ev.alert_id not in r["fp_alert_ids"]:
                r["fp_alert_ids"].append(ev.alert_id)
            for ind in ev.indicators:
                if ind and ind not in r["fp_indicators"]:
                    r["fp_indicators"].append(ind)

    # fp_rate = noise / total, computed once per rule after aggregation.
    for r in rules.values():
        r["fp_rate"] = (r["fp_count"] / r["total"]) if r["total"] else 0.0

    return {
        "tenant": tenant,
        "namespace": TenantFactStore.namespace(tenant),
        "total_events": total,
        "rules": rules,
    }


# --------------------------------------------------------------------------
# Step 2 — turn the ledger into concrete improvement TASKS (the event core).
# --------------------------------------------------------------------------
def detect_triggers(
    ledger: Dict[str, Any],
    *,
    fp_threshold: float = 0.5,
    min_events: int = 3,
) -> List[Dict[str, Any]]:
    """Emit deterministic strategy-improvement tasks from a feedback ledger.

    This is the EVENT-DRIVEN core (not just a memory write): it inspects each
    rule's ledger and, on explicit thresholds, emits an improvement task.

    Trigger policy (deterministic)
    ------------------------------
    For each rule with at least ``min_events`` recorded dispositions:

    - ``fp_rate >= fp_threshold``  ->  a ``whitelist_optimization`` task naming
      the exact FP alert cohort + indicators to suppress. This is the
      directly-actionable "tighten the allowlist" artifact.
    - the rule produced ONLY false positives (``tp_count == 0`` and
      ``fp_count == total``)  ->  ALSO a ``rule_regeneration`` task: a request
      to the M1/M2 self-improving loop to regenerate the rule, because a
      whitelist patch cannot fix a rule that never fires a true positive.

    A rule under ``min_events`` emits NOTHING (guard against acting on thin
    evidence). A healthy rule (fp_rate below threshold) emits NOTHING.

    Tasks are returned sorted by rule_name for a stable, deterministic order.

    Returns
    -------
    A list of task dicts::

        {"type": "whitelist_optimization", "rule_name": ..., "fp_events": [...],
         "fp_indicators": [...], "fp_rate": 1.0, "sample_size": 3,
         "rationale": "..."}
        {"type": "rule_regeneration", "rule_name": ..., "reason": "...",
         "sample_size": 3, "target": "m1_m2_self_improving_loop"}
    """
    if not (0.0 <= fp_threshold <= 1.0):
        raise ValueError(f"fp_threshold must be in [0, 1], got {fp_threshold}")
    if min_events < 1:
        raise ValueError(f"min_events must be >= 1, got {min_events}")

    tasks: List[Dict[str, Any]] = []
    rules = ledger.get("rules", {})
    for rule_name in sorted(rules):
        r = rules[rule_name]
        total = r.get("total", 0)
        if total < min_events:
            continue  # too few events — do not act on thin evidence

        fp_rate = r.get("fp_rate", 0.0)
        tp_count = r.get("tp_count", 0)
        fp_count = r.get("fp_count", 0)

        # --- Noisy rule: tighten the allowlist. ---
        if fp_rate >= fp_threshold:
            tasks.append(
                {
                    "type": "whitelist_optimization",
                    "rule_name": rule_name,
                    "fp_events": list(r.get("fp_alert_ids", [])),
                    "fp_indicators": list(r.get("fp_indicators", [])),
                    "fp_rate": fp_rate,
                    "sample_size": total,
                    "rationale": (
                        f"Rule '{rule_name}' produced {fp_count}/{total} "
                        f"false-positive/benign dispositions (fp_rate="
                        f"{_pct(fp_rate)} >= threshold {_pct(fp_threshold)}). "
                        "Suppress the listed alert cohort / indicators via an "
                        "allowlist predicate to cut analyst noise."
                    ),
                }
            )

        # --- Dead/misfiring rule: regenerate via the M1/M2 loop. ---
        # Only-FP over enough events => a whitelist patch cannot save it; the
        # detection itself must be regenerated.
        if tp_count == 0 and fp_count == total:
            tasks.append(
                {
                    "type": "rule_regeneration",
                    "rule_name": rule_name,
                    "reason": (
                        f"Rule '{rule_name}' produced only false positives "
                        f"({fp_count}/{total}, zero true positives) — its "
                        "detection hit-rate has collapsed. Hand off to the "
                        "M1/M2 self-improving loop to regenerate the rule "
                        "(offline-driven in this POC; live-capable)."
                    ),
                    "sample_size": total,
                    "target": "m1_m2_self_improving_loop",
                }
            )

    return tasks


def _pct(x: float) -> str:
    """Format a rate as a stable percentage string (deterministic, no rounding drift)."""
    # Round half-up to one decimal via a fixed epsilon so 0.5 -> "50.0%" exactly.
    return f"{math.floor(x * 1000 + 0.5) / 10:.1f}%"


# --------------------------------------------------------------------------
# Step 2b (M12) — drift-triggered regeneration from a decayed EVAL SCORE.
# --------------------------------------------------------------------------
def _validate_score(name: str, value: float) -> float:
    """Coerce+range-check one eval score into the [0, 1] convention (offline)."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{name} must be a real number in [0, 1], got {value!r}")
    v = float(value)
    if math.isnan(v) or not (0.0 <= v <= 1.0):
        raise ValueError(f"{name} must be in [0, 1], got {value!r}")
    return v


def detect_score_decay(
    harness_id: str,
    *,
    scores: Optional[List[float]] = None,
    latest: Optional[float] = None,
    baseline: Optional[float] = None,
    decay_threshold: float = 0.1,
    min_score: Optional[float] = None,
    pass_bar: float = 0.7,
) -> Optional[Dict[str, Any]]:
    """Emit a regeneration task when a PROMOTED harness's eval score decays.

    The disposition-driven :func:`detect_triggers` closes the loop on *alert
    noise*; this closes it on *eval-quality drift*. A harness is promoted to
    production at some baseline eval score (the M1/M2 ``score->revise->promote``
    loop, mirrored offline in ``scenario_self_improve_loop``). If a later
    re-score shows the score has decayed past a threshold — or fallen below an
    absolute floor — a whitelist patch is irrelevant: the *detection itself*
    must be regenerated. This function emits exactly that hand-off, using the
    SAME ``rule_regeneration`` task shape (``type`` + ``target``) the existing
    only-FP path emits, tagged with ``trigger="eval_score_decay"`` so a consumer
    can tell WHY the regeneration was requested.

    Score model
    -----------
    Eval scores follow the repo's convention: a float in ``[0, 1]`` with a
    ``pass_bar`` (default ``0.7``, matching ``scenario_self_improve_loop``).
    The baseline / latest score are resolved deterministically:

    - ``baseline``: the explicit promoted-at score if given; else ``scores[0]``
      (the oldest = the score the harness was promoted at).
    - ``latest``: the explicit latest score if given; else ``scores[-1]`` (the
      newest re-score).

    Provide EITHER a ``scores`` history (oldest -> newest) OR an explicit
    ``latest`` + ``baseline`` pair (or any mix — explicit values win).

    Trigger policy (deterministic)
    ------------------------------
    ``decay = baseline - latest`` (rounded to 10 dp to kill float drift). A task
    is emitted when EITHER:

    - ``decay >= decay_threshold`` — the score dropped by at least the allowed
      margin from its promoted baseline (inclusive boundary, mirroring
      ``fp_rate >= fp_threshold``); OR
    - ``min_score`` is set and ``latest < min_score`` — the score fell below an
      absolute quality floor regardless of how gentle the slope was.

    A stable / improved score (``decay`` below threshold and at/above any floor)
    emits ``None``. Pure function of its arguments: no clock, no randomness, no
    network, no AWS.

    Returns
    -------
    ``None`` when healthy, or a task dict mirroring the ``rule_regeneration``
    shape::

        {"type": "rule_regeneration", "rule_name": ..., "harness_id": ...,
         "trigger": "eval_score_decay", "baseline_score": 0.9,
         "latest_score": 0.6, "decay": 0.3, "decay_threshold": 0.1,
         "min_score": None, "below_floor": False, "sample_size": 3,
         "reason": "...", "target": "m1_m2_self_improving_loop"}
    """
    if not harness_id:
        raise ValueError("detect_score_decay requires a non-empty harness_id")
    if not (0.0 < decay_threshold <= 1.0):
        raise ValueError(f"decay_threshold must be in (0, 1], got {decay_threshold}")
    if not (0.0 <= pass_bar <= 1.0):
        raise ValueError(f"pass_bar must be in [0, 1], got {pass_bar}")

    hist: List[float] = []
    if scores is not None:
        if not isinstance(scores, (list, tuple)):
            raise TypeError("scores must be a list/tuple of numbers")
        hist = [_validate_score("scores[i]", s) for s in scores]

    # Resolve baseline: explicit wins, else the promoted-at (oldest) score.
    if baseline is not None:
        base = _validate_score("baseline", baseline)
    elif hist:
        base = hist[0]
    else:
        raise ValueError("provide `baseline` or a non-empty `scores` history")

    # Resolve latest: explicit wins, else the newest re-score.
    if latest is not None:
        cur = _validate_score("latest", latest)
    elif hist:
        cur = hist[-1]
    else:
        raise ValueError("provide `latest` or a non-empty `scores` history")

    floor = _validate_score("min_score", min_score) if min_score is not None else None

    # Round to 10 dp so 0.9 - 0.6 compares as exactly 0.3 (deterministic boundary).
    decay = round(base - cur, 10)
    decayed_past_threshold = decay >= decay_threshold
    below_floor = floor is not None and cur < floor
    if not (decayed_past_threshold or below_floor):
        return None  # stable / improved score -> no regeneration

    # Deterministic, human-readable rationale naming the concrete cause(s).
    causes: List[str] = []
    if decayed_past_threshold:
        causes.append(
            f"decayed by {_pct(decay)} from its promoted baseline "
            f"({base:.3f} -> {cur:.3f}, threshold {_pct(decay_threshold)})"
        )
    if below_floor:
        causes.append(f"fell below the {floor:.3f} quality floor (latest {cur:.3f})")

    return {
        "type": REGENERATION_TASK_TYPE,
        "rule_name": harness_id,
        "harness_id": harness_id,
        "trigger": SCORE_DECAY_TRIGGER,
        "baseline_score": base,
        "latest_score": cur,
        "decay": decay,
        "decay_threshold": decay_threshold,
        "min_score": floor,
        "below_floor": below_floor,
        "pass_bar": pass_bar,
        "sample_size": len(hist),
        "reason": (
            f"Promoted harness '{harness_id}' eval score " + " and ".join(causes)
            + ". A whitelist patch cannot restore eval quality — hand off to the "
            "M1/M2 self-improving loop to regenerate the detection "
            "(offline-driven in this POC; live-capable)."
        ),
        "target": REGENERATION_TARGET,
    }
