"""mockdata — the single-source-of-truth FICTIONAL SecOps world.

.. warning::
   **CLEARLY-LABELED MOCK DATA for POC / testing only.** Not real threat intel,
   not a real SIEM, no real company/person/host. All network artifacts use the
   IANA documentation ranges (RFC 5737 IPs ``192.0.2.0/24`` /
   ``198.51.100.0/24`` / ``203.0.113.0/24``, ``example.test`` / ``example.com``
   domains, fabricated-but-valid-length SHA-256 hashes). See ``README.md``.

This package is the one place the four alert-triage data-plane tools
(``siem_query``, ``asset_lookup``, ``enrich_ioc``, ``create_ticket``) read
their world from, so every tool agrees on the same hosts, indicators, and
events. The whole world is deterministic literal data (see ``world.py``); this
module only re-exports it behind a tiny, typed accessor API.

API
---
- :func:`load_world` -> the full world dict (fresh deep copy each call).
- :func:`hosts`      -> list of host records.
- :func:`alerts`     -> list of SIEM alert/event records.
- :func:`iocs`       -> list of indicator-of-compromise records.
- :func:`tickets_seed` -> list of seed ticket records (so ``create_ticket``
  can show a monotonic id sequence).

Every accessor returns a fresh copy (via :func:`load_world`), so a caller may
mutate what it gets back without corrupting the shared source or another tool's
read — that is what keeps repeated queries deterministic.

Two worlds, on purpose
----------------------
- :func:`load_world` (``world.py``) — the CANONICAL SMALL world the alert-triage
  narrative reads (size-capped by tests so it stays legible).
- :func:`load_enterprise` / :func:`exposure_surface` (``enterprise.py``) — a DEEP
  ~50-host, five-tier world for ATTACK-PATH reasoning. ``exposure_surface`` returns
  exactly the shape ``tools/asset_lookup`` emits and ``build_attack_paths`` consumes,
  so the real reasoner traverses it directly. Kept separate so deepening the attack
  surface never touches the canonical world's locked invariants.
"""

from __future__ import annotations

from typing import Any, Dict, List

from .accounts import accounts, finding_types
from .enterprise import (
    crown_jewels,
    exposure_surface,
    load_enterprise,
)
from .world import load_world

__all__ = [
    "load_world",
    "hosts",
    "alerts",
    "iocs",
    "tickets_seed",
    "accounts",
    "finding_types",
    "load_enterprise",
    "exposure_surface",
    "crown_jewels",
]


def hosts() -> List[Dict[str, Any]]:
    """Return the fictional enterprise's host inventory (fresh copy).

    Host ids/facts (notably ``web-01`` carrying ``CVE-2021-44228``) mirror
    ``tools/asset_lookup/handler.py`` so the asset plane and this world stay
    consistent.
    """
    return load_world()["hosts"]


def alerts() -> List[Dict[str, Any]]:
    """Return the SIEM-style alert/event stream (fresh copy).

    Includes the Log4Shell spine (``alert-1001``) plus a mix of
    true-positive-looking and explicitly benign/false-positive events.
    """
    return load_world()["alerts"]


def iocs() -> List[Dict[str, Any]]:
    """Return the indicator-of-compromise set (fresh copy).

    Includes the C2 IP (``ioc-c2-01`` / ``203.0.113.66``) that ties the
    Log4Shell alert to ``web-01``.
    """
    return load_world()["iocs"]


def tickets_seed() -> List[Dict[str, Any]]:
    """Return the pre-existing seed tickets (fresh copy).

    Two tickets so ``create_ticket`` can demonstrate a monotonic id sequence
    (the next issued id would be ``SEC-1003``). The full sequence hint lives
    under ``load_world()["ticket_sequence"]``.
    """
    return load_world()["tickets"]
