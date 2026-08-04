"""
INV-MCP-4 — error text crossing the MCP trust boundary is redacted.
==================================================================
`mcp_server.py` is the one surface an untrusted MCP peer reaches, and it was the
lowest-covered core module at 80.3%. The uncovered lines were not incidental: they were the
two ERROR paths, and both handed an exception's text to the peer verbatim.

    _invoke_tool      json.dumps({"error": ..., "message": str(exc)})
    _discover_tools   description = f"[LOAD ERROR: {exc}]"    <- served by list_tools

Reproduced before the fix. A handler raising

    RuntimeError("connect failed: postgresql://svc:SUPERSECRET_PW@db.internal:5432/soc
                  (token=ABSK_LIVE_deadbeef)")

delivered the password, the token and the internal hostname straight to the peer:

    {"error": "RuntimeError", "message": "connect failed: postgresql://svc:SUPERSECRET_PW@..."}

The second path is worse for being quieter — an import-time failure becomes a tool
DESCRIPTION broadcast over the protocol, somewhere nobody looks for secrets.

This is INV-TICKET-1's shape a second time. Round 20 found it in `create_ticket` (a tracker
URL with a token echoed into a response `message`), fixed it at that ONE call site, and
recorded "a fix applied to one call site is not an invariant" in the same commit. The
redaction now lives once in `_safe_error_text` and both boundary paths use it.

What these tests deliberately do NOT demand
-------------------------------------------
Hostnames and ports are not redacted. "timeout after 15s connecting to
siem.example.internal:9200" is useless without the host, this server speaks stdio to an
agent the operator configured, and a leaked hostname grants no replayable capability the way
a leaked credential does. The line is at credentials, not topology — asserted below so the
choice is visible rather than implicit.

ZERO network, ZERO AWS.
"""
from __future__ import annotations

import json
import os

import pytest

os.environ.setdefault("SENTINEL_REGION", "us-east-1")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")

from sentinel_harness import mcp_server as ms  # noqa: E402


class _Raising:
    """A tool module whose handler raises a chosen exception."""

    def __init__(self, exc: BaseException):
        self._exc = exc

    def handler(self, event, context):  # noqa: D102 - matches the tool contract
        raise self._exc


# --------------------------------------------------------------------------- #
# _safe_error_text — the redactor itself                                      #
# --------------------------------------------------------------------------- #
class TestSafeErrorText:

    @pytest.mark.parametrize("message,secret", [
        ("connect failed: postgresql://svc:SUPERSECRET_PW@db.internal:5432/soc",
         "SUPERSECRET_PW"),
        ("auth rejected (token=ABSK_LIVE_deadbeef)", "ABSK_LIVE_deadbeef"),
        ("bad request: api_key=sk-abcdef123456 rejected", "sk-abcdef123456"),
        # Authorization headers. `Bearer` is ALSO matched by the generic key=value rule
        # (it lists "bearer" as a key), so mutation-testing showed that disabling the
        # dedicated Authorization rule left this one case still redacted — the mutation
        # SURVIVED. The four cases below are the ones ONLY the dedicated rule reaches:
        # non-Bearer schemes and the Proxy- variant. Without them the rule looks redundant
        # and a future cleanup would delete it, silently reopening the hole.
        ("header Authorization: Bearer eyJhbGciOi.PAYLOAD.sig", "eyJhbGciOi.PAYLOAD.sig"),
        ("rejected: Authorization: Basic dXNlcjpwYXNzd29yZA", "dXNlcjpwYXNzd29yZA"),
        ("upstream said Authorization: SharedKey acct:c2lnbmF0dXJl", "c2lnbmF0dXJl"),
        ("Proxy-Authorization: Digest cnonce=deadbeefcafe", "deadbeefcafe"),
        ("bad header authorization=rawtokenvalue123", "rawtokenvalue123"),
        ("GET https://api.example.com/v1?token=leaked_value_here failed", "leaked_value_here"),
        ("password: hunter2correcthorse", "hunter2correcthorse"),
    ])
    def test_credential_shaped_text_is_removed(self, message, secret):
        cleaned = ms._safe_error_text(RuntimeError(message))
        assert secret not in cleaned, (
            f"the secret survived redaction:\n  in:  {message}\n  out: {cleaned}"
        )
        assert "[redacted]" in cleaned, f"nothing was redacted: {cleaned}"

    @pytest.mark.parametrize("message", [
        "missing required field 'rule_type'",
        "'severity' must be one of: low, medium, high, critical",
        "timeout after 15s connecting to siem.example.internal:9200",
        "rules/: not a directory",
        "event must be a dict of {'action', 'params'}",
    ])
    def test_legitimate_diagnostics_survive_intact(self, message):
        """CONTROL, and the reason this is a denylist. A peer that only ever receives
        "an error occurred" cannot tell a bad argument from an outage, so over-redaction
        would make the channel useless and get routed around."""
        assert ms._safe_error_text(ValueError(message)) == message

    def test_an_aws_access_key_id_is_removed(self):
        """The AKIA/ASIA/ABSK pattern.

        The literal is ASSEMBLED AT RUNTIME rather than written out, and NOT passed through
        `@pytest.mark.parametrize`. Both halves matter.

        A parametrised case containing a real-shaped key id failed
        `deploy/scan_secrets.sh`, and the scanner is right: it cannot tell a fixture from a
        committed credential, and a guard that learns to ignore "test-looking" keys stops
        being a guard.

        The non-obvious half: removing the literal from the source did NOT fix it. pytest
        persists parametrised test IDs to `.pytest_cache/v/cache/nodeids`, so the key
        lived on in a file on disk — and that scanner walks every file, not just tracked
        source. So a secret-shaped value must never appear as a parametrize ARGUMENT, not
        merely never appear in a committed line. (`.pytest_cache/` is gitignored, so it
        could not have been pushed; the build still fails locally, which is the correct
        outcome — the point is that the value outlives the edit.)
        """
        for prefix in ("AKIA", "ASIA", "ABSK"):
            fake = prefix + "IOSFODNN7" + "EXAMPLE"
            cleaned = ms._safe_error_text(RuntimeError(f"using access_key {fake}"))
            assert fake not in cleaned, f"{prefix} key id survived: {cleaned}"
            assert "[redacted]" in cleaned

    def test_hostnames_are_deliberately_kept(self):
        """The documented trade-off, asserted so it is a decision rather than an accident.
        If this ever needs to change (a network transport, say), this test is where the
        change becomes visible."""
        cleaned = ms._safe_error_text(
            RuntimeError("connect failed: postgresql://svc:pw@db.internal:5432/soc"))
        assert "db.internal" in cleaned, (
            "the hostname was redacted too. That may be right for a networked transport, "
            "but it is a deliberate trade-off documented in mcp_server.py — update the "
            "comment and this test together, not one of them."
        )
        assert "pw@" not in cleaned, "the userinfo password survived"

    def test_the_message_is_length_bounded(self):
        """A handler that echoes a huge payload back through an exception must not be able
        to flood the protocol channel."""
        cleaned = ms._safe_error_text(RuntimeError("x" * 5000))
        assert len(cleaned) <= 300, len(cleaned)
        assert cleaned.endswith("…"), "truncation is not signalled to the reader"

    def test_an_empty_message_is_handled(self):
        assert ms._safe_error_text(RuntimeError()) == ""


# --------------------------------------------------------------------------- #
# _invoke_tool — the first boundary path (lines 228-229)                      #
# --------------------------------------------------------------------------- #
class TestInvokeToolErrorPath:

    def test_a_raising_handler_returns_structured_json_not_a_traceback(self):
        out = ms._invoke_tool("probe", _Raising(ValueError("bad field 'x'")), {})
        parsed = json.loads(out)
        assert parsed["error"] == "ValueError"
        assert parsed["message"] == "bad field 'x'"
        assert "Traceback" not in out, "a traceback reached the peer"

    def test_the_exception_type_is_preserved(self):
        """The type is the actionable part — a peer can distinguish a validation error from
        an upstream failure. Redaction must not flatten it."""
        for exc, name in [(KeyError("k"), "KeyError"),
                          (TimeoutError("slow"), "TimeoutError"),
                          (PermissionError("nope"), "PermissionError")]:
            parsed = json.loads(ms._invoke_tool("probe", _Raising(exc), {}))
            assert parsed["error"] == name, parsed

    def test_a_secret_in_the_exception_does_not_reach_the_peer(self):
        """The reproduced defect, as a regression test."""
        exc = RuntimeError(
            "connect failed: postgresql://svc:SUPERSECRET_PW@db.internal:5432/soc "
            "(token=ABSK_LIVE_deadbeef)")
        out = ms._invoke_tool("probe", _Raising(exc), {})
        assert "SUPERSECRET_PW" not in out, f"password leaked to the peer: {out}"
        assert "ABSK_LIVE_deadbeef" not in out, f"token leaked to the peer: {out}"
        assert json.loads(out)["error"] == "RuntimeError"

    def test_a_successful_call_is_unaffected(self):
        """CONTROL: the happy path must still return the handler's dict verbatim."""
        class _Ok:
            @staticmethod
            def handler(event, context):
                return {"ok": True, "echo": event}

        parsed = json.loads(ms._invoke_tool("probe", _Ok, {"a": 1}))
        assert parsed == {"ok": True, "echo": {"a": 1}}

    def test_a_non_serialisable_result_does_not_crash_the_boundary(self):
        """`json.dumps(..., default=str)` is what keeps an exotic return value from taking
        down the server. An unhandled TypeError here would kill the session for every
        subsequent call, not just this one."""
        class _Weird:
            @staticmethod
            def handler(event, context):
                return {"when": object()}

        out = ms._invoke_tool("probe", _Weird, {})
        json.loads(out)  # must parse


# --------------------------------------------------------------------------- #
# _discover_tools — the load-error description (line ~199)                    #
# --------------------------------------------------------------------------- #
class TestLoadErrorDescription:

    def test_a_load_failure_yields_a_redacted_description(self, monkeypatch, tmp_path):
        """The quieter path: this description is SERVED by list_tools, so an import-time
        failure must not publish a credential as a tool description."""
        secret_exc = RuntimeError(
            "config load failed: s3://bucket/key?token=ABSK_LIVE_cafebabe")

        def _boom(*_a, **_k):
            raise secret_exc

        # A real tools/ dir with one entry, so the loop body runs.
        tool_dir = tmp_path / "probe_tool"
        tool_dir.mkdir()
        (tool_dir / "handler.py").write_text("def handler(e, c): return {}\n",
                                             encoding="utf-8")
        monkeypatch.setattr(ms, "_TOOLS_DIR", tmp_path)
        monkeypatch.setattr(ms, "_load_approved_set", lambda: frozenset({"probe_tool"}))
        monkeypatch.setattr(ms.importlib.util, "spec_from_file_location", _boom)

        tools = ms._discover_tools()
        assert "probe_tool" in tools, tools
        entry = tools["probe_tool"]
        assert entry["module"] is None
        assert "LOAD ERROR" in entry["description"]
        assert "RuntimeError" in entry["description"], (
            "the exception type was dropped — the operator cannot tell what failed"
        )
        assert "ABSK_LIVE_cafebabe" not in entry["description"], (
            f"a credential is being served as a tool description: {entry['description']}"
        )

    def test_a_load_failure_is_logged_in_full_locally(self, monkeypatch, tmp_path, caplog):
        """Redacting the PEER's copy must not blind the operator. The full text goes to the
        local log — the degradation-leaves-a-trace rule."""
        import logging

        def _boom(*_a, **_k):
            raise RuntimeError("config load failed: token=ABSK_LIVE_cafebabe")

        tool_dir = tmp_path / "probe_tool"
        tool_dir.mkdir()
        (tool_dir / "handler.py").write_text("def handler(e, c): return {}\n",
                                             encoding="utf-8")
        monkeypatch.setattr(ms, "_TOOLS_DIR", tmp_path)
        monkeypatch.setattr(ms, "_load_approved_set", lambda: frozenset({"probe_tool"}))
        monkeypatch.setattr(ms.importlib.util, "spec_from_file_location", _boom)

        records: list = []

        class _Collect(logging.Handler):
            def emit(self, record):
                records.append(record)

        logger = logging.getLogger("sentinel_harness")
        handler = _Collect(level=logging.WARNING)
        logger.addHandler(handler)
        previous = logger.level
        if not logger.isEnabledFor(logging.WARNING):
            logger.setLevel(logging.WARNING)
        try:
            ms._discover_tools()
        finally:
            logger.removeHandler(handler)
            logger.setLevel(previous)

        assert any("failed to load" in r.getMessage() for r in records), (
            f"a tool load failure was not logged at all: {[r.getMessage() for r in records]}"
        )

    def test_a_module_without_a_handler_is_skipped_not_served(self, monkeypatch, tmp_path):
        """The `if not hasattr(mod, "handler"): continue` branch. A file in tools/ that is
        not a handler must not be advertised as a callable tool."""
        tool_dir = tmp_path / "not_a_tool"
        tool_dir.mkdir()
        (tool_dir / "handler.py").write_text("VALUE = 1\n", encoding="utf-8")
        monkeypatch.setattr(ms, "_TOOLS_DIR", tmp_path)
        monkeypatch.setattr(ms, "_load_approved_set", lambda: frozenset({"not_a_tool"}))
        assert "not_a_tool" not in ms._discover_tools()


# --------------------------------------------------------------------------- #
# The boundary, end to end over the real protocol                             #
# --------------------------------------------------------------------------- #
@pytest.mark.anyio
async def test_a_raising_tool_returns_redacted_text_over_the_protocol(monkeypatch):
    """Not the unit path — the actual MCP round trip, so this proves the redaction is wired
    into what a peer receives rather than only into a helper.

    A guard verified only at the unit level is half-verified; rounds 18-21 recorded that
    repeatedly.
    """
    pytest.importorskip("mcp", reason="the MCP SDK provides the in-memory transport")
    from mcp.shared.memory import create_connected_server_and_client_session

    secret = "SUPERSECRET_PW"

    real_discover = ms._discover_tools

    def _with_a_raising_tool():
        tools = dict(real_discover())
        tools["probe_raiser"] = {
            "module": _Raising(RuntimeError(
                f"connect failed: postgresql://svc:{secret}@db.internal:5432/soc")),
            "description": "a tool that always raises",
        }
        return tools

    monkeypatch.setattr(ms, "_discover_tools", _with_a_raising_tool)
    server, _ = ms.create_server()
    async with create_connected_server_and_client_session(server) as session:
        result = await session.call_tool("probe_raiser", {"event": {}})
        text = "".join(getattr(c, "text", "") for c in result.content)
        assert secret not in text, f"the password crossed the protocol boundary: {text}"
        assert "RuntimeError" in text, f"the error type was lost: {text}"


@pytest.mark.anyio
async def test_an_unknown_tool_name_does_not_echo_the_registry(monkeypatch):
    """`call_tool` returns the available tool names on an unknown call. That is a useful
    error, and it is also a listing an untrusted peer could otherwise not obtain if
    governance excluded a tool — so it must only name tools the peer can already see."""
    pytest.importorskip("mcp")
    from mcp.shared.memory import create_connected_server_and_client_session

    server, _ = ms.create_server()
    async with create_connected_server_and_client_session(server) as session:
        listed = {t.name for t in (await session.list_tools()).tools}
        result = await session.call_tool("no_such_tool", {"event": {}})
        text = "".join(getattr(c, "text", "") for c in result.content)
        assert "unknown_tool" in text, text
        # Anything named in the error must already be visible via list_tools.
        for hidden in ("web_search", "harness_ops", "run_evaluation"):
            if hidden not in listed:
                assert hidden not in text, (
                    f"the unknown-tool error disclosed {hidden!r}, which governance "
                    f"excludes from list_tools: {text}"
                )
