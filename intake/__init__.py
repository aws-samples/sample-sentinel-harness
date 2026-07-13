"""
sentinel-harness · intake package
==================================
Diverse-intake front door for the meta-agent self-iteration engine (ROADMAP §3
key #4 / §4 M1). Everything an operator throws at the platform — a plain
natural-language ask, free-form meeting/spec notes, or the framework's own error
traceback — is normalized here into ONE clean request string the meta-agent can
decompose into a harness spec.

This layer is a **deterministic normalizer, not an agent**: pure Python, offline,
no LLM, no network. Keeping it deterministic is deliberate — the meta-agent (an
Opus harness) does the reasoning; the intake adapter must be cheap, testable, and
reproducible so the same input always yields the same request text.
"""
from __future__ import annotations

from .adapter import IntakeResult, normalize

__all__ = ["IntakeResult", "normalize"]
