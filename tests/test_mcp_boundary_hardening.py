"""INV-MCP-6 — every exposed tool survives arbitrary peer input, refuses empty input, and stays offline.

`mcp_server` hands an **untrusted peer's arbitrary dict** straight to 17 tool handlers. Round 28
(INV-MCP-4) fixed what leaks OUT of that boundary — exception text carrying credentials. It never
asked what happens when hostile input goes IN.

Three properties were measured and all three hold. None of them was checked by anything:

1. **No uncaught exception, and always parseable JSON.** 289 hand-picked malformed events plus 250
   hypothesis-generated ones across all 17 tools: zero escapes. This matters because
   `_invoke_tool` catches `Exception` — not `BaseException` — so a handler raising `SystemExit`
   or `KeyboardInterrupt` on bad input would kill the server for every subsequent call, not just
   the offending one.

2. **An empty event is REFUSED, not silently accepted.** 17/17 return a refusal rather than
   `ok: True` or a result with no success field at all. A tool that answers "fine" when the peer
   supplied nothing is a fail-open: the model believes work was done.

3. **No network egress in default (non-`*_LIVE`) mode**, even when the event carries a
   metadata-service URL, `file:///etc/passwd`, or an attacker-controlled `base_url`. 119
   combinations, zero connection attempts.

`tests/test_r17_egress_mechanized.py` guards egress STRUCTURALLY — that live paths import the
shared guard and do not re-implement the IP parser. This module is the behavioural complement:
structure says the guard is wired, behaviour says a hostile event cannot get past it.

A note on how to block the network in a test
--------------------------------------------
The blocking must be installed **after** all imports. Replacing `socket.socket` before importing
`boto3` breaks `ssl`, whose module body does `class SSLSocket(socket)` — it fails with
`TypeError: function() argument 'code' must be code, not str`, which looks nothing like a
networking problem. Learned by doing it wrong.

ZERO network, ZERO AWS — enforced rather than asserted: the socket layer is severed and any
attempt to use it fails the test.
"""
from __future__ import annotations

import json
import os
import socket

import pytest

os.environ.setdefault("SENTINEL_EXECUTION_ROLE_ARN", "arn:aws:iam::000000000000:role/test")
os.environ.setdefault("SENTINEL_REGION", "us-east-1")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")

# Imported at module scope, BEFORE any socket patching — see the module docstring.
from sentinel_harness.mcp_server import _discover_tools, _invoke_tool  # noqa: E402


def _live_tools() -> dict:
    return {name: info["module"] for name, info in _discover_tools().items()
            if info["module"] is not None}


_TOOLS = _live_tools()
_TOOL_NAMES = sorted(_TOOLS)


# Malformed events a peer can send through the protocol. The MCP layer's input schema is
# deliberately permissive (`_tool_input_schema` requires nothing), so all of these reach a handler.
_MALFORMED = (
    {},
    {"action": None},
    {"action": []},
    {"action": {"nested": "dict"}},
    {"action": "\x00\x01\x02"},
    {"action": "x" * 10_000},
    {"params": None},
    {"params": "not-a-dict"},
    {"params": [1, 2, 3]},
    {"action": "unknown_action_xyz"},
    {"__proto__": {"polluted": True}},
    {"action": "audit", "rules": None},
    {"rules_dir": None},
    {"": ""},
    {"a" * 500: "b" * 500},
)

# Events trying to induce egress. Each names a target that must never be reached.
_HOSTILE_TARGETS = (
    {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"},
    {"endpoint": "http://169.254.169.254/"},
    {"base_url": "http://127.0.0.1:8080/admin"},
    {"target": "file:///etc/passwd"},
    {"action": "query", "url": "http://attacker.example/exfil"},
    {"indicator": "1.2.3.4", "url": "http://metadata.google.internal/"},
    {"cve_id": "CVE-2021-44228", "api_base": "http://evil.example/"},
)


class NetworkAttempted(RuntimeError):
    """Raised in place of any real socket operation."""


@pytest.fixture
def no_network(monkeypatch):
    """Sever the socket layer for the duration of a test.

    `socket.socket.connect` is patched rather than `socket.socket` itself: replacing the CLASS
    breaks `ssl` (which subclasses it at import time) if anything imports late. Patching the
    method leaves every class hierarchy intact while making an actual connection impossible.
    """
    def _blocked(*args, **kwargs):
        raise NetworkAttempted(f"a real connection was attempted: {args[:2]}")

    monkeypatch.setattr(socket, "create_connection", _blocked)
    monkeypatch.setattr(socket, "getaddrinfo", _blocked)
    monkeypatch.setattr(socket.socket, "connect", _blocked)
    monkeypatch.setattr(socket.socket, "connect_ex", _blocked)
    return _blocked


def test_the_tool_surface_is_non_trivial():
    """Positive control. Every parametrised test below iterates `_TOOL_NAMES`; an empty surface
    would make the whole module vacuously green — the failure mode this repo records most."""
    assert len(_TOOL_NAMES) >= 15, (
        f"only {len(_TOOL_NAMES)} tools discovered: {_TOOL_NAMES}. Either governance changed or "
        "discovery is broken; both must fail loudly rather than shrink the fuzz surface."
    )


@pytest.mark.parametrize("tool", _TOOL_NAMES)
def test_no_malformed_event_escapes_as_an_uncaught_exception(tool):
    """`_invoke_tool` catches `Exception`, NOT `BaseException`.

    A handler that raised `SystemExit` or `MemoryError` on hostile input would terminate the
    server process — killing the session for every subsequent call, not just the offending one.
    So this catches `BaseException` and fails on anything that gets out.

    The response must also always be parseable JSON: the peer receives it as text, and an
    unparseable body is indistinguishable from a protocol fault.
    """
    module = _TOOLS[tool]
    for index, event in enumerate(_MALFORMED):
        try:
            output = _invoke_tool(tool, module, event)
        except BaseException as exc:  # noqa: BLE001 - the whole point
            pytest.fail(
                f"{tool} let a {type(exc).__name__} escape `_invoke_tool` on malformed event "
                f"#{index} ({event!r:.80}): {exc}\n\n"
                "`_invoke_tool` only catches `Exception`, so a BaseException kills the MCP "
                "server for every later call too."
            )
        try:
            json.loads(output)
        except json.JSONDecodeError as exc:
            pytest.fail(
                f"{tool} returned unparseable JSON on malformed event #{index}: {exc}\n"
                f"{output[:300]}"
            )


@pytest.mark.parametrize("tool", _TOOL_NAMES)
def test_an_empty_event_is_refused_not_silently_accepted(tool):
    """An empty event means the peer supplied nothing. The safe answer is a refusal.

    A handler returning `ok: True` — or a body with no success indicator at all — tells the model
    that work was done. That is a fail-open on the one surface an untrusted peer reaches, and it
    is INV-BOUNDARY-5's rule: "we could not tell" must never render as the permissive answer.
    """
    parsed = json.loads(_invoke_tool(tool, _TOOLS[tool], {}))
    assert isinstance(parsed, dict), f"{tool} returned {type(parsed).__name__}, not an object"

    ok = parsed.get("ok")
    has_error = bool(parsed.get("error") or parsed.get("message"))

    assert ok is not True, (
        f"{tool} reports ok=True for an EMPTY event — it claims success on input the peer never "
        f"supplied:\n{json.dumps(parsed)[:400]}"
    )
    assert ok is False or has_error, (
        f"{tool} gives no success flag and no error for an empty event, so a caller cannot tell "
        f"whether anything happened:\n{json.dumps(parsed)[:400]}"
    )


@pytest.mark.parametrize("tool", _TOOL_NAMES)
def test_a_hostile_target_never_reaches_the_network_in_default_mode(tool, no_network):
    """The behavioural half of the egress contract.

    `test_r17_egress_mechanized.py` proves the live paths import the shared guard and do not
    re-implement the IP parser — a STRUCTURAL claim. This proves a hostile event cannot get past
    it: with `*_LIVE` unset (the default), no event carrying a metadata-service URL,
    `file:///etc/passwd`, or an attacker-controlled `base_url` produces a connection attempt.

    Enforced rather than asserted: the socket layer is severed, so an attempt raises.
    """
    module = _TOOLS[tool]
    for index, event in enumerate(_HOSTILE_TARGETS):
        try:
            output = _invoke_tool(tool, module, event)
        except NetworkAttempted as exc:
            pytest.fail(
                f"{tool} attempted a real connection on hostile event #{index} ({event!r:.80}) "
                f"with no *_LIVE flag set: {exc}"
            )
        # A handler that catches the block internally and reports it must not have tried either.
        assert "a real connection was attempted" not in output, (
            f"{tool} reached the socket layer on hostile event #{index} and swallowed the "
            f"failure into its response:\n{output[:300]}"
        )


def test_the_network_block_actually_blocks(no_network):
    """Control for the fixture. A block that does not block would make the test above pass for
    every tool while proving nothing — a scan finding nothing is indistinguishable from a broken
    scan.
    """
    with pytest.raises(NetworkAttempted):
        socket.create_connection(("example.com", 80))
    with pytest.raises(NetworkAttempted):
        socket.getaddrinfo("example.com", 80)


def test_the_permissive_input_schema_is_deliberate():
    """The premise of this whole module, recorded rather than assumed.

    `_tool_input_schema` requires NOTHING — `event` is optional and untyped — so validation is the
    handler's job and every malformed event above really does reach one. If the schema ever gains
    `required` fields, some of these cases would be rejected by the protocol layer instead, and
    this module would be testing the schema rather than the handlers. That is a fine change to
    make; it just has to be made knowingly.
    """
    from sentinel_harness.mcp_server import _tool_input_schema

    schema = _tool_input_schema("probe")
    assert "required" not in schema, (
        "the MCP input schema now declares required fields, so the protocol layer rejects some "
        "malformed events before they reach a handler. Update this module's premise: it exists "
        "because validation was entirely the handler's responsibility."
    )
    assert schema.get("type") == "object", schema

# --------------------------------------------------------------------------- #
# The boundary's own contract, tested by INJECTION                            #
# --------------------------------------------------------------------------- #
class _Raiser:
    """A stand-in tool module whose handler always raises the given exception."""

    def __init__(self, exc: BaseException):
        self._exc = exc

    def handler(self, event, context):  # noqa: D102 - matches the tool contract
        raise self._exc


@pytest.mark.parametrize("exc", [
    ValueError("bad field"),
    KeyError("missing"),
    TypeError("wrong type"),
    RuntimeError("upstream failed"),
    AttributeError("no such attribute"),
    ZeroDivisionError("division by zero"),
])
def test_a_raising_handler_is_converted_to_structured_json(exc):
    """`_invoke_tool`'s `except Exception` is a real defence, and the tests above cannot reach it.

    Mutation-testing showed "make `_invoke_tool` catch only ZeroDivisionError" SURVIVING the whole
    malformed-event sweep. Investigating rather than patching the test: across 17 tools x 15
    malformed events — **255 combinations — not one handler raised.** Every shipped handler
    validates its own input and returns a structured refusal, so that `except` branch never
    executed and removing it changed nothing observable.

    That is good news about the handlers and a hole in my assertions. The `except` is the only
    barrier the day any handler grows an unhandled path, so the contract is tested by INJECTION —
    a stub that certainly raises — rather than by hoping a real handler does.
    """
    output = _invoke_tool("probe", _Raiser(exc), {"any": "event"})
    parsed = json.loads(output)
    assert parsed.get("error") == type(exc).__name__, (
        f"the boundary did not report the exception TYPE, which is the part a caller can act "
        f"on: {parsed}"
    )
    assert "Traceback" not in output, f"a traceback reached the peer: {output[:300]}"


def test_the_boundary_catches_broadly_enough_to_be_a_barrier():
    """The premise of the test above, checked against the source.

    Narrowing `except Exception` to a specific type would leave the boundary porous while every
    behavioural test still passed — precisely the mutation that survived. So the breadth of the
    catch is asserted directly.

    `BaseException` is deliberately NOT required: catching `KeyboardInterrupt` / `SystemExit`
    would make the server unkillable and swallow a deliberate shutdown. The contract is "catch
    every ordinary error", not "catch everything".
    """
    import inspect

    from sentinel_harness import mcp_server

    source = inspect.getsource(mcp_server._invoke_tool)
    assert "except Exception" in source, (
        "`_invoke_tool` no longer catches `Exception` broadly. A narrower catch lets an "
        "unexpected error escape to the protocol layer, and no behavioural test can see it "
        "while every shipped handler validates its own input (255 malformed combinations, zero "
        f"raises). Source:\n{source}"
    )
    assert "except BaseException" not in source, (
        "`_invoke_tool` now catches `BaseException`, which swallows KeyboardInterrupt and "
        "SystemExit — the server would resist a deliberate shutdown."
    )
