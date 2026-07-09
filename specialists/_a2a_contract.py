"""
Shared in-process A2A JSON-RPC contract (offline, mockable model)
=================================================================
This module is the **reusable A2A envelope harness** every specialist reuses to
prove the A2A protocol end-to-end WITHOUT any network, creds, or model call. It
is the extraction of the transport-agnostic pieces that were first written for
``specialists/cve-intel/local_a2a.py`` (which remains the source-of-truth
reference) so sibling specialists (``attack-mapper``, ``threat-hunt``) do not
each re-implement the same JSON-RPC ``message/send`` server/client and error
codes.

What it provides
----------------
- :class:`A2AError` — internal signal carrying a JSON-RPC error code + message.
- The JSON-RPC 2.0 reserved error codes A2A inherits.
- :func:`extract_message_text` — pull/concatenate the ``text`` parts out of an
  A2A message, raising a clean :class:`A2AError` on malformed input.
- :class:`LocalA2AServer` — an in-process A2A server: **given an agent-card
  provider + a model-callable**, it serves card discovery and routes a
  ``message/send`` request to the model, returning a structured A2A response.
  No socket, no HTTP. Malformed input NEVER raises out of :meth:`handle` — it
  comes back as a JSON-RPC ``error`` object.
- :class:`LocalA2AClient` — the matching in-process client (builds spec-shaped
  requests, hands them to the server's ``handle``).
- :func:`verdict_from_response` — pull the machine-readable ``data`` verdict out
  of a successful response.
- :func:`strands_model_callable` — the PRODUCTION seam (documented, not
  exercised in tests) that adapts a real Strands ``Agent`` into the model
  callable signature.

Design: the model is a **callable seam** ``(message_text: str) -> dict``. In a
contract test each specialist injects a deterministic offline fake (built around
its own pure reasoner — ``build_attack_paths`` / ``build_hunt_plan`` / a CVE
echo), so the round-trip is fully deterministic and touches NO network. Swapping
in :func:`strands_model_callable` gives you the same in-process A2A front end
backed by the real model — but that path imports the heavy stack and does live
inference, so tests never touch it.

A2A wire shape
--------------
    request  = {"jsonrpc": "2.0", "id": "1", "method": "message/send",
                "params": {"message": {"role": "user",
                                        "parts": [{"kind": "text", "text": "..."}]}}}
    response = {"jsonrpc": "2.0", "id": "1",
                "result": {"role": "agent", "parts": [{"kind": "data", "data": {...}}, ...],
                           "kind": "message", "messageId": "..."}}

Nothing in this file is customer- or company-specific.
"""
from __future__ import annotations

import uuid
from typing import Callable

# JSON-RPC error codes (subset). -326xx are the JSON-RPC 2.0 reserved range that
# A2A inherits; we use them so a real A2A client parses our errors normally.
JSONRPC_PARSE_ERROR = -32700
JSONRPC_INVALID_REQUEST = -32600
JSONRPC_METHOD_NOT_FOUND = -32601
JSONRPC_INVALID_PARAMS = -32602
JSONRPC_INTERNAL_ERROR = -32603

# A model callable maps the flattened message text to a specialist verdict dict.
ModelCallable = Callable[[str], dict]
# A card provider builds the agent-card; it accepts a ``url`` keyword (the A2A
# endpoint, resolved at bind time) and returns the pure-data card dict.
CardProvider = Callable[..., dict]


class A2AError(Exception):
    """Internal signal carrying a JSON-RPC error code + message.

    Never propagates out of :meth:`LocalA2AServer.handle`; it is caught there and
    serialized into a JSON-RPC ``error`` object. Using an exception internally
    keeps the request-parsing code linear instead of threaded with error returns.
    """

    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def extract_message_text(message: dict) -> str:
    """Concatenate the text of all ``text`` parts in an A2A message.

    Raises :class:`A2AError` (INVALID_PARAMS) if the message is not a dict, has no
    ``parts`` list, or contains no usable text part — malformed input must become a
    clean error, never an exception that escapes the server.
    """
    if not isinstance(message, dict):
        raise A2AError(JSONRPC_INVALID_PARAMS, "params.message must be an object")
    parts = message.get("parts")
    if not isinstance(parts, list) or not parts:
        raise A2AError(JSONRPC_INVALID_PARAMS, "params.message.parts must be a non-empty list")
    texts: list[str] = []
    for part in parts:
        if isinstance(part, dict) and part.get("kind") == "text" and isinstance(part.get("text"), str):
            texts.append(part["text"])
    if not texts:
        raise A2AError(JSONRPC_INVALID_PARAMS, "params.message.parts has no text part")
    return "\n".join(texts)


def strands_model_callable(agent) -> ModelCallable:  # pragma: no cover
    """PRODUCTION SEAM (documented, not exercised in tests).

    Adapt a real Strands ``Agent`` (from a specialist's ``build_agent``) into the
    ``(message_text) -> dict`` model-callable signature this harness expects. This
    is what you'd inject to run the in-process A2A front end against the *real*
    model. It does live inference and JSON-parses the model's envelope, so the
    contract test never calls it (doing so would require the heavy stack + creds +
    network). Left here so the seam is explicit rather than implied.
    """
    import json

    def _call(message_text: str) -> dict:
        result = agent(message_text)
        text = getattr(result, "message", None) or str(result)
        try:
            return json.loads(text)
        except (TypeError, ValueError) as exc:
            raise A2AError(
                JSONRPC_INTERNAL_ERROR,
                f"model did not return parseable JSON envelope: {exc}",
            ) from exc

    return _call


class LocalA2AServer:
    """In-process A2A server: card discovery + ``message/send``, no socket.

    Construct with a ``card_provider`` (the specialist's ``agent_card`` function)
    and a ``model_callable`` seam. :meth:`handle` takes a JSON-RPC request dict and
    returns a JSON-RPC response dict — the exact envelopes a networked A2A client
    would exchange, minus the transport. This is what makes the protocol provable
    offline: swap the transport, keep the contract.

    ``model_callable`` is REQUIRED — the shared harness is model-agnostic, so each
    specialist injects its own deterministic offline fake. Sibling ``local_a2a``
    modules wrap this class to default the callable to their echo model.
    """

    def __init__(
        self,
        *,
        card_provider: CardProvider,
        model_callable: ModelCallable,
        url: str | None = None,
    ):
        if not callable(card_provider):
            raise TypeError("card_provider must be callable")
        if not callable(model_callable):
            raise TypeError("model_callable must be callable")
        self._card_provider = card_provider
        self._model = model_callable
        self._url = url

    # -- discovery ---------------------------------------------------------- #
    def agent_card(self) -> dict:
        """Serve the canonical agent-card (from the specialist), url resolved.

        This is what a real server publishes at
        ``/.well-known/agent-card.json``; we return the dict directly.
        """
        return self._card_provider(url=self._url)

    # -- message/send ------------------------------------------------------- #
    def handle(self, request: dict) -> dict:
        """Process a JSON-RPC request; ALWAYS returns a well-formed response.

        Any malformed request (not a dict, wrong jsonrpc version, unknown method,
        bad params, or a model-callable that raises :class:`A2AError`) comes back
        as a JSON-RPC ``error`` object — this method does not raise for bad input.
        """
        req_id = request.get("id") if isinstance(request, dict) else None
        try:
            if not isinstance(request, dict):
                raise A2AError(JSONRPC_INVALID_REQUEST, "request must be a JSON object")
            if request.get("jsonrpc") != "2.0":
                raise A2AError(JSONRPC_INVALID_REQUEST, "jsonrpc must be '2.0'")
            method = request.get("method")
            if method != "message/send":
                raise A2AError(JSONRPC_METHOD_NOT_FOUND, f"unsupported method: {method!r}")
            params = request.get("params")
            if not isinstance(params, dict):
                raise A2AError(JSONRPC_INVALID_PARAMS, "params must be an object")
            text = extract_message_text(params.get("message"))
            verdict = self._model(text)  # may raise A2AError (e.g. unusable input)
            return self._ok(req_id, verdict)
        except A2AError as err:
            return self._err(req_id, err.code, err.message)
        except Exception as exc:  # defensive: an unexpected callable bug is still a clean error
            return self._err(req_id, JSONRPC_INTERNAL_ERROR, f"internal error: {exc}")

    # -- envelope builders -------------------------------------------------- #
    @staticmethod
    def _ok(req_id, verdict: dict) -> dict:
        """Wrap a verdict dict in an A2A agent Message result.

        The verdict is carried both as a machine-readable ``data`` part (what a
        supervisor parses) and a ``text`` part (its ``summary``, for humans / text
        transports) — mirroring how a real A2A agent returns mixed-modality parts.
        """
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "role": "agent",
                "parts": [
                    {"kind": "data", "data": verdict},
                    {"kind": "text", "text": verdict.get("summary", "")},
                ],
                "kind": "message",
                "messageId": uuid.uuid4().hex,
            },
        }

    @staticmethod
    def _err(req_id, code: int, message: str) -> dict:
        return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


class LocalA2AClient:
    """In-process A2A client bound to a :class:`LocalA2AServer`.

    Builds spec-shaped ``message/send`` requests and hands them to the server's
    ``handle`` — no socket, no HTTP. Lets a test drive the full round-trip exactly
    as a networked client would, so the *envelope contract* is what's under test,
    not the transport.
    """

    def __init__(self, server: LocalA2AServer):
        self._server = server
        self._counter = 0

    def get_agent_card(self) -> dict:
        """Discovery call — fetch the served agent-card."""
        return self._server.agent_card()

    def send_message(self, text: str, *, message_id: str | None = None) -> dict:
        """Send a text message via ``message/send`` and return the raw response."""
        self._counter += 1
        request = {
            "jsonrpc": "2.0",
            "id": str(self._counter),
            "method": "message/send",
            "params": {
                "message": {
                    "role": "user",
                    "parts": [{"kind": "text", "text": text}],
                    "messageId": message_id or uuid.uuid4().hex,
                    "kind": "message",
                }
            },
        }
        return self._server.handle(request)

    def send_raw(self, request: dict) -> dict:
        """Send an arbitrary (possibly malformed) request — for error-path tests."""
        return self._server.handle(request)


def verdict_from_response(response: dict) -> dict | None:
    """Convenience: pull the ``data`` verdict out of a successful A2A response.

    Returns ``None`` if the response is an error or has no data part — so callers
    can branch on success without re-walking the envelope by hand.
    """
    result = response.get("result") if isinstance(response, dict) else None
    if not isinstance(result, dict):
        return None
    for part in result.get("parts", []):
        if isinstance(part, dict) and part.get("kind") == "data":
            return part.get("data")
    return None
