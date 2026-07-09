"""
threat-hunt · in-process A2A serving + client harness (offline, mockable model)
================================================================================
Mirrors ``specialists/cve-intel/local_a2a.py`` exactly, but wires the
**threat-hunt** agent-card + a deterministic mocked model through the SHARED A2A
contract harness (:mod:`specialists._a2a_contract`). It proves the A2A protocol
end-to-end **without any network, creds, or model call**: card discovery,
``message/send`` round-trip, and clean JSON-RPC error handling.

Why this exists (vs. ``agent_a2a.build_app``)
---------------------------------------------
``agent_a2a.build_app`` wraps a real Strands ``Agent`` in ``A2AServer`` and binds
a socket — it needs the heavy specialist stack (strands / litellm / uvicorn) and
a live model. That is the *production* path and stays exactly as documented. For
a **contract test** we exercise the A2A envelope shape deterministically, with
ZERO network and ZERO model spend: the transport is a plain in-process function
call (no socket) and the model is a **callable seam** ``(text) -> dict``.

Unlike the cve-intel echo (which cannot ground its fields without a tool), the
threat-hunt default model is genuinely useful offline: it delegates to the REAL,
pure-python :func:`agent_a2a.build_hunt_plan` core — the same deterministic
observable/ATT&CK mapping a live run would call as a Gateway tool. So the echo
returns a real hunt plan (``grounded=True``) with NO LLM and NO network. The LLM
layer only narrates around this core in production.

Production seam (documented, NOT exercised in tests)
----------------------------------------------------
:func:`strands_model_callable` (re-exported from the shared harness) adapts a real
Strands ``Agent`` into the same callable signature; wiring it into
:class:`LocalA2AServer` gives an in-process A2A front end backed by the real
model — but that path imports the heavy stack and does live inference, so tests
never touch it.

Nothing in this file is customer- or company-specific.
"""
from __future__ import annotations

import importlib.util
import os
from typing import Callable

# Load the sibling skeleton and the shared contract by explicit path under UNIQUE
# module names so importing this never collides with the bare ``agent_a2a`` /
# ``_a2a_contract`` names other specialists share (a shared sys.modules entry
# would cross-poison sibling specialists' tests).
_HERE = os.path.dirname(os.path.abspath(__file__))
_AGENT_A2A_PATH = os.path.join(_HERE, "agent_a2a.py")
_CONTRACT_PATH = os.path.join(os.path.dirname(_HERE), "_a2a_contract.py")

_agent_spec = importlib.util.spec_from_file_location(
    "threat_hunt_agent_a2a_impl", _AGENT_A2A_PATH
)
agent_a2a = importlib.util.module_from_spec(_agent_spec)  # type: ignore[arg-type]
_agent_spec.loader.exec_module(agent_a2a)  # type: ignore[union-attr]

_contract_spec = importlib.util.spec_from_file_location(
    "threat_hunt_a2a_contract_impl", _CONTRACT_PATH
)
_contract = importlib.util.module_from_spec(_contract_spec)  # type: ignore[arg-type]
_contract_spec.loader.exec_module(_contract)  # type: ignore[union-attr]

# Re-export the identity so callers don't reach around us into agent_a2a.
SPECIALIST_NAME = agent_a2a.SPECIALIST_NAME
agent_card = agent_a2a.agent_card

# Re-export the shared contract surface so a test targeting this module has the
# exact same API as cve-intel's local_a2a (error codes, client, helpers).
A2AError = _contract.A2AError
LocalA2AClient = _contract.LocalA2AClient
verdict_from_response = _contract.verdict_from_response
extract_message_text = _contract.extract_message_text
strands_model_callable = _contract.strands_model_callable
JSONRPC_PARSE_ERROR = _contract.JSONRPC_PARSE_ERROR
JSONRPC_INVALID_REQUEST = _contract.JSONRPC_INVALID_REQUEST
JSONRPC_METHOD_NOT_FOUND = _contract.JSONRPC_METHOD_NOT_FOUND
JSONRPC_INVALID_PARAMS = _contract.JSONRPC_INVALID_PARAMS
JSONRPC_INTERNAL_ERROR = _contract.JSONRPC_INTERNAL_ERROR


def echo_model_callable(message_text: str) -> dict:
    """Default deterministic fake model — the offline stand-in for the real LLM.

    Delegates to the REAL, pure-python :func:`agent_a2a.build_hunt_plan` core (the
    same deterministic observable/ATT&CK mapping a live run calls as a Gateway
    tool), so the round-trip returns a genuinely useful hunt plan with NO LLM and
    NO network. ``grounded`` is ``True`` because every technique/observable comes
    from that deterministic mapping — not confabulated. This is the honest offline
    representation: the *mapping* is real; only the LLM narration is absent.

    Raises :class:`A2AError` (INVALID_PARAMS) on an empty/whitespace hypothesis so
    the server returns a clean A2A error instead of a bogus plan.
    """
    if not isinstance(message_text, str) or not message_text.strip():
        raise A2AError(
            JSONRPC_INVALID_PARAMS,
            "empty hypothesis; expected a hunting hypothesis in natural language",
        )
    plan = agent_a2a.build_hunt_plan(message_text)
    matched = plan.get("matched")
    summary = (
        f"Deterministic offline hunt plan for hypothesis "
        f"({'matched TTPs: ' + ', '.join(plan.get('matched_ttps', [])) if matched else 'generic reconnaissance (no TTP match)'})."
    )
    # Return the real plan enriched with the A2A envelope fields, grounded in the
    # deterministic core.
    return {
        **plan,
        "summary": summary,
        "grounded": True,
        # Provenance marker so a consumer can tell a mocked verdict from a live one.
        "engine": "echo-mock",
    }


class LocalA2AServer(_contract.LocalA2AServer):
    """threat-hunt in-process A2A server: card discovery + ``message/send``.

    Thin wrapper over :class:`specialists._a2a_contract.LocalA2AServer` that
    defaults the card provider to this specialist's :func:`agent_card` and the
    model to the deterministic :func:`echo_model_callable`. Same construction
    signature as cve-intel's ``LocalA2AServer`` so a parametrized contract test
    treats every specialist uniformly.
    """

    def __init__(self, *, model_callable: Callable[[str], dict] | None = None, url: str | None = None):
        super().__init__(
            card_provider=agent_card,
            model_callable=model_callable or echo_model_callable,
            url=url,
        )
