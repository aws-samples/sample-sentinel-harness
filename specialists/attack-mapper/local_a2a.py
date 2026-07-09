"""
attack-mapper · in-process A2A serving + client harness (offline, mockable model)
=================================================================================
Mirrors ``specialists/cve-intel/local_a2a.py`` exactly, but wires the
**attack-mapper** agent-card + a deterministic mocked model through the SHARED
A2A contract harness (:mod:`specialists._a2a_contract`). It proves the A2A
protocol end-to-end **without any network, creds, or model call**: card
discovery, ``message/send`` round-trip, and clean JSON-RPC error handling.

Why this exists (vs. ``agent_a2a.build_app``)
---------------------------------------------
``agent_a2a.build_app`` wraps a real Strands ``Agent`` in ``A2AServer`` and binds
a socket — it needs the heavy specialist stack (strands / litellm / uvicorn) and
a live model. That is the *production* path and stays exactly as documented. For
a **contract test** we exercise the A2A envelope shape deterministically, with
ZERO network and ZERO model spend: the transport is a plain in-process function
call (no socket) and the model is a **callable seam** ``(text) -> dict``.

The default (:func:`echo_model_callable`) is a deterministic fake that echoes a
*structurally valid* attack-mapper verdict envelope. It performs NO inference and
touches NO network. Because a live attack-mapper grounds its ``chains`` in the
``asset_lookup`` Gateway tool (an exposure surface the mock has no access to
offline), the echo returns an empty ``chains`` list and ``grounded=False`` — the
honest representation of "the protocol worked; no real surface was gathered". The
REAL ranking core (:func:`agent_a2a.build_attack_paths`) is exercised by its own
offline unit tests, not confabulated here.

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
    "attack_mapper_agent_a2a_impl", _AGENT_A2A_PATH
)
agent_a2a = importlib.util.module_from_spec(_agent_spec)  # type: ignore[arg-type]
_agent_spec.loader.exec_module(agent_a2a)  # type: ignore[union-attr]

_contract_spec = importlib.util.spec_from_file_location(
    "attack_mapper_a2a_contract_impl", _CONTRACT_PATH
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

    Echoes a *structurally valid* attack-mapper verdict envelope (same schema the
    :data:`agent_a2a.SYSTEM_PROMPT` mandates). It performs NO inference and touches
    NO network — every value is derived purely from the input, so the round-trip
    is fully deterministic and reproducible.

    ``chains`` is empty and ``grounded`` is ``False`` because a live attack-mapper
    grounds its chains in the ``asset_lookup`` tool's exposure surface, which a
    fake has no access to offline — this is the honest representation of "the
    protocol worked; no real surface was gathered". The deterministic ranking core
    (:func:`agent_a2a.build_attack_paths`) is exercised by its own unit tests.

    Raises :class:`A2AError` (INVALID_PARAMS) on an empty/whitespace query so the
    server returns a clean A2A error instead of a bogus verdict.
    """
    if not isinstance(message_text, str) or not message_text.strip():
        raise A2AError(
            JSONRPC_INVALID_PARAMS,
            "empty query; expected an environment/asset description to map attack paths",
        )
    query = message_text.strip()
    return {
        "query": query,
        "chains": [],
        "summary": (
            "Deterministic offline echo for attack-path query "
            "(mock model; no asset_lookup grounding)."
        ),
        "grounded": False,
        # Provenance marker so a consumer can tell a mocked verdict from a live one.
        "engine": "echo-mock",
    }


class LocalA2AServer(_contract.LocalA2AServer):
    """attack-mapper in-process A2A server: card discovery + ``message/send``.

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
