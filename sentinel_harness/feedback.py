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
    "managed_memory_writer",
    "DISPOSITIONS",
    "FP_DISPOSITION",
    "TP_DISPOSITION",
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
