"""
litellm.gateway — a standalone LiteLLM inference-gateway skeleton
=================================================================
A single model entry-point (``complete``) plus a structured request/response
**audit** hook, provider-agnostic via ``LiteLLMModel``. This is a *skeleton* in
the same spirit as the specialists under ``specialists/*``: the heavy ``litellm``
dependency is import-guarded so this package is always importable and inspectable
offline (audit-record shape, entry-point contract), and the real model call is
only touched when you actually invoke it inside a container with ``litellm``
installed.

Nothing in this package is customer- or company-specific.
"""
from __future__ import annotations

from .proxy import (  # noqa: F401
    DEFAULT_MODEL_ID,
    InferenceGateway,
    audit_record,
    build_audit_record,
    complete,
)

__all__ = [
    "InferenceGateway",
    "complete",
    "audit_record",
    "build_audit_record",
    "DEFAULT_MODEL_ID",
]
