"""
`cve-intel` — the wiring functions its siblings already test.
============================================================
Coverage showed an asymmetry across four structurally identical specialists:

    specialists/attack-mapper/agent_a2a.py       100%
    specialists/threat-hunt/agent_a2a.py         100%
    specialists/adversarial-reviewer/agent_a2a.py 100%
    specialists/cve-intel/agent_a2a.py            60%   <-- 166-171, 216-237

The gap was NOT "cve-intel is harder to test". `tests/test_attack_mapper.py` reaches the
same three functions by injecting a fake `strands` / `mcp` module tree with
`monkeypatch.setitem(sys.modules, ...)`, so the lazily-imported heavy deps resolve to stubs
and the live paths execute with no network. `cve-intel`'s three existing test files never
use that technique: they test `_load_gateway_tools`' empty-URL early return, then
`monkeypatch.setattr(agent_a2a, "_load_gateway_tools", lambda url: [])` whenever they need
`build_agent` — which is precisely why lines 166-171 (the live MCP path), 216-237
(`build_app`'s route registration) and `serve` never ran.

So this is "a fix applied to one call site is not an invariant" — the shape this repo keeps
recording — landing on a TESTING TECHNIQUE rather than on production code. A proven way to
exercise a hard-to-reach path existed for one specialist and was never carried to its
siblings.

What the uncovered code actually claims
--------------------------------------
`_load_gateway_tools`' docstring: "an explicitly set but unreachable Gateway surfaces as an
MCP client error at build time rather than being silently dropped." That is a fail-LOUD
contract on the tool surface an agent is granted — if it degraded quietly, a specialist
would come up with no tools and look healthy. Nothing verified it.

`build_app` registers the `/ping` liveness endpoint the AgentCore Runtime polls. If that
route were missing the container would be killed as unhealthy, and no test called the
function.

ZERO network, ZERO AWS: every heavy dependency is a stub injected into `sys.modules`.
"""
from __future__ import annotations

import importlib.util
import os
import sys
import types

import pytest

# Hermetic: no real region / profile / credential resolution.
os.environ.setdefault("SENTINEL_REGION", "us-east-1")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")

# Load from an explicit path under a UNIQUE module name. Every specialist ships a module
# called `agent_a2a`, so a bare import would collide with the siblings' and whichever test
# imported first would win the sys.modules cache — the reason the existing specialist tests
# all do this too.
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_MODULE_PATH = os.path.join(REPO_ROOT, "specialists", "cve-intel", "agent_a2a.py")
_UNIQUE_NAME = "cve_intel_agent_a2a_wiring"
_spec = importlib.util.spec_from_file_location(_UNIQUE_NAME, _MODULE_PATH)
agent_a2a = importlib.util.module_from_spec(_spec)
sys.modules[_UNIQUE_NAME] = agent_a2a
_spec.loader.exec_module(agent_a2a)


# --------------------------------------------------------------------------- #
# Stub module trees for the lazily-imported heavy deps                        #
# --------------------------------------------------------------------------- #
def _install_mcp_stubs(monkeypatch, *, client_cls):
    """Inject a fake `mcp.client.streamable_http` + `strands.tools.mcp`.

    Both are imported INSIDE `_load_gateway_tools`, so patching `sys.modules` before the
    call is what makes the live branch reachable offline.
    """
    strands_mod = types.ModuleType("strands")
    tools_mod = types.ModuleType("strands.tools")
    mcp_sub = types.ModuleType("strands.tools.mcp")
    mcp_sub.MCPClient = client_cls
    mcp_pkg = types.ModuleType("mcp")
    mcp_client_pkg = types.ModuleType("mcp.client")
    streamable_mod = types.ModuleType("mcp.client.streamable_http")
    streamable_mod.streamablehttp_client = lambda url: ("conn", url)

    for name, mod in [
        ("strands", strands_mod), ("strands.tools", tools_mod),
        ("strands.tools.mcp", mcp_sub), ("mcp", mcp_pkg),
        ("mcp.client", mcp_client_pkg),
        ("mcp.client.streamable_http", streamable_mod),
    ]:
        monkeypatch.setitem(sys.modules, name, mod)


# --------------------------------------------------------------------------- #
# _load_gateway_tools — the live MCP path (lines 166-171)                      #
# --------------------------------------------------------------------------- #
class TestLoadGatewayTools:

    def test_no_url_returns_no_tools_without_importing_mcp(self, monkeypatch):
        """The early return must not touch the heavy deps at all. Asserted by making any
        import of them explode: a specialist with no Gateway configured has to come up on a
        machine where `mcp` is not installed."""
        class _Explode:
            def __getattr__(self, _name):
                raise AssertionError("the empty-URL path imported the MCP client")

        monkeypatch.setitem(sys.modules, "mcp", _Explode())
        assert agent_a2a._load_gateway_tools(None) == []
        assert agent_a2a._load_gateway_tools("") == []

    def test_a_configured_url_starts_a_client_and_returns_its_tools(self, monkeypatch):
        """The live branch, offline. Ports the technique `test_attack_mapper.py` has used
        all along."""
        events = {}

        class _Client:
            def __init__(self, factory):
                events["factory"] = factory

            def start(self):
                events["started"] = True

            def list_tools_sync(self):
                return ["nvd_lookup", "epss_kev"]

        _install_mcp_stubs(monkeypatch, client_cls=_Client)
        tools = agent_a2a._load_gateway_tools("https://gw.example/mcp")
        assert tools == ["nvd_lookup", "epss_kev"]
        assert events["started"] is True, "the MCP client was never started"
        assert callable(events["factory"]), "the client got no connection factory"

    def test_the_factory_carries_the_configured_url(self, monkeypatch):
        """A client pointed at the wrong Gateway would silently load another tenant's tool
        surface, so the URL must reach the connection factory verbatim."""
        seen = {}

        class _Client:
            def __init__(self, factory):
                seen["conn"] = factory()

            def start(self):
                pass

            def list_tools_sync(self):
                return []

        _install_mcp_stubs(monkeypatch, client_cls=_Client)
        agent_a2a._load_gateway_tools("https://gw.example/mcp")
        assert seen["conn"] == ("conn", "https://gw.example/mcp")

    def test_an_unreachable_gateway_raises_rather_than_degrading(self, monkeypatch):
        """The docstring's contract, tested: "an explicitly set but unreachable Gateway
        surfaces as an MCP client error at build time rather than being silently dropped."

        This is the assertion that matters most in the file. A quiet degradation would bring
        the specialist up with ZERO tools while looking healthy — an agent that cannot do
        its job and reports no error.
        """
        class _Unreachable:
            def __init__(self, factory):
                pass

            def start(self):
                raise ConnectionError("gateway unreachable: connection refused")

            def list_tools_sync(self):  # pragma: no cover - start() raises first
                return []

        _install_mcp_stubs(monkeypatch, client_cls=_Unreachable)
        with pytest.raises(ConnectionError, match="unreachable"):
            agent_a2a._load_gateway_tools("https://gw.example/mcp")

    def test_a_gateway_returning_no_tools_is_not_an_error(self, monkeypatch):
        """CONTROL for the assertion above: an empty tool list from a REACHABLE Gateway is
        a legitimate answer. If this raised, the fail-loud rule would have become
        fail-on-everything and operators would route around it."""
        class _Empty:
            def __init__(self, factory):
                pass

            def start(self):
                pass

            def list_tools_sync(self):
                return []

        _install_mcp_stubs(monkeypatch, client_cls=_Empty)
        assert agent_a2a._load_gateway_tools("https://gw.example/mcp") == []


# --------------------------------------------------------------------------- #
# build_app — the /ping liveness route (lines 216-237)                        #
# --------------------------------------------------------------------------- #
def _stub_a2a_serving(monkeypatch, *, with_to_fastapi=True):
    """Inject stub `fastapi` + `strands.multiagent.a2a` and return the recorder.

    FastAPI is STUBBED rather than required. My first version used the real package with
    `TestClient`, and all six of these tests SKIPPED — `fastapi` is not in this repo's test
    extra (only `starlette`/`httpx`, pulled in by `mcp`). Six skips would have left
    `build_app` and `serve` at exactly the coverage they had before, while the run reported
    "6 passed". Skip is not pass.

    Stubbing is also the better test: calling `app.routes["/ping"]()` exercises MY route
    function, where a `TestClient` round trip would mostly exercise FastAPI's. This is the
    helper `tests/test_attack_mapper.py` has used all along to keep that specialist at 100%
    — carrying it here is the actual fix for the asymmetry.
    """
    rec: dict = {}

    class _FastAPI:
        def __init__(self):
            self.routes = {}

        def get(self, route):
            def _decorator(fn):
                self.routes[route] = fn
                return fn

            return _decorator

    fastapi_mod = types.ModuleType("fastapi")
    fastapi_mod.FastAPI = _FastAPI

    class _A2AServer:
        def __init__(self, *, agent, host, port):
            rec.update(agent=agent, host=host, port=port)

        if with_to_fastapi:
            def to_fastapi_app(self):
                app = _FastAPI()
                rec["from_a2a"] = True
                return app

    strands_mod = types.ModuleType("strands")
    multiagent_mod = types.ModuleType("strands.multiagent")
    a2a_mod = types.ModuleType("strands.multiagent.a2a")
    a2a_mod.A2AServer = _A2AServer

    monkeypatch.setitem(sys.modules, "fastapi", fastapi_mod)
    monkeypatch.setitem(sys.modules, "strands", strands_mod)
    monkeypatch.setitem(sys.modules, "strands.multiagent", multiagent_mod)
    monkeypatch.setitem(sys.modules, "strands.multiagent.a2a", a2a_mod)
    return rec, _FastAPI


class TestBuildApp:

    def test_registers_the_ping_liveness_route(self, monkeypatch):
        """The AgentCore Runtime polls `/ping`. A container whose app lacks that route is
        killed as unhealthy — and no test called this function before."""
        rec, _ = _stub_a2a_serving(monkeypatch, with_to_fastapi=True)
        sentinel_agent = object()
        app = agent_a2a.build_app(host="127.0.0.1", port=1234, agent=sentinel_agent)

        assert rec["agent"] is sentinel_agent
        assert (rec["host"], rec["port"]) == ("127.0.0.1", 1234)
        assert rec.get("from_a2a") is True, "the A2AServer's own app was not used"
        assert "/ping" in app.routes, f"no /ping route registered: {sorted(app.routes)}"
        assert app.routes["/ping"]() == {"status": "healthy", "agent": "cve-intel"}

    def test_builds_its_own_agent_when_none_is_given(self, monkeypatch):
        """`build_app()` with no agent must construct one — the container CMD path."""
        built = {}

        def _fake_build_agent(**_kw):
            agent = object()
            built["agent"] = agent
            return agent

        monkeypatch.setattr(agent_a2a, "build_agent", _fake_build_agent)
        rec, _ = _stub_a2a_serving(monkeypatch)
        agent_a2a.build_app()
        assert "agent" in built, "build_app did not build an agent"
        assert rec["agent"] is built["agent"]

    def test_falls_back_to_a_bare_fastapi_app(self, monkeypatch):
        """The `hasattr(a2a, "to_fastapi_app")` branch: an A2AServer version without that
        method must still yield an app carrying `/ping`, or the liveness contract breaks on
        a dependency upgrade."""
        rec, _FastAPI = _stub_a2a_serving(monkeypatch, with_to_fastapi=False)
        app = agent_a2a.build_app(host="0.0.0.0", port=9000, agent=object())  # noqa: S104
        assert isinstance(app, _FastAPI)
        assert "from_a2a" not in rec, "the A2A app path was taken unexpectedly"
        assert app.routes["/ping"]() == {"status": "healthy", "agent": "cve-intel"}

    def test_the_ping_route_names_THIS_specialist(self, monkeypatch):
        """The liveness envelope carries the agent name. Three specialists share this code
        shape, so a copy-paste would make one report another's name and a health dashboard
        would attribute an outage to the wrong service."""
        _stub_a2a_serving(monkeypatch)
        app = agent_a2a.build_app(agent=object())
        assert app.routes["/ping"]()["agent"] == "cve-intel" == agent_a2a.SPECIALIST_NAME


# --------------------------------------------------------------------------- #
# serve — the blocking container entrypoint                                   #
# --------------------------------------------------------------------------- #
class TestServe:

    def test_hands_the_app_and_the_bind_address_to_uvicorn(self, monkeypatch):
        """`serve` is the container entrypoint. It never ran in a test, so a wrong
        host/port pair — or an app built for one address and served on another — would only
        surface in a deployed container."""
        called = {}
        uvicorn_mod = types.ModuleType("uvicorn")

        def _run(app, host=None, port=None, **_kw):
            called.update(app=app, host=host, port=port)

        uvicorn_mod.run = _run
        monkeypatch.setitem(sys.modules, "uvicorn", uvicorn_mod)

        sentinel_app = object()

        def _fake_build_app(**kw):
            called["built_with"] = kw
            return sentinel_app

        monkeypatch.setattr(agent_a2a, "build_app", _fake_build_app)

        agent_a2a.serve(host="0.0.0.0", port=9000)  # noqa: S104 - the container binds all
        assert called["app"] is sentinel_app
        assert (called["host"], called["port"]) == ("0.0.0.0", 9000)  # noqa: S104
        assert called["built_with"] == {"host": "0.0.0.0", "port": 9000}, (  # noqa: S104
            "the app was built for a different address than it is served on: "
            f"{called['built_with']}"
        )

    def test_uses_the_module_defaults_when_called_bare(self, monkeypatch):
        called = {}
        uvicorn_mod = types.ModuleType("uvicorn")
        uvicorn_mod.run = lambda app, host=None, port=None, **_kw: called.update(
            host=host, port=port)
        monkeypatch.setitem(sys.modules, "uvicorn", uvicorn_mod)
        monkeypatch.setattr(agent_a2a, "build_app", lambda **kw: object())

        agent_a2a.serve()
        assert called["host"] == agent_a2a.DEFAULT_HOST
        assert called["port"] == agent_a2a.DEFAULT_PORT


# --------------------------------------------------------------------------- #
# The asymmetry itself, kept from coming back                                 #
# --------------------------------------------------------------------------- #
def test_every_specialist_has_its_wiring_functions_exercised():
    """Guard the guard, and the general case.

    Four specialists ship the same three wiring functions. Three of them were at 100% and
    one at 60% purely because a working test technique had been applied to some and not
    others. This asserts each specialist EXPOSES the surface; the coverage doc + its drift
    guard (test_coverage_doc.py) is what keeps the figures honest.

    Deliberately structural rather than a coverage assertion: re-measuring coverage inside a
    unit test would be slow and circular. This catches the cheaper failure — a specialist
    losing or renaming a wiring function so the tests silently stop covering it.
    """
    specialists = ["attack-mapper", "threat-hunt", "adversarial-reviewer", "cve-intel"]
    required = ("build_agent", "build_app", "serve", "agent_card", "_load_gateway_tools")
    missing: dict = {}
    for name in specialists:
        path = os.path.join(REPO_ROOT, "specialists", name, "agent_a2a.py")
        assert os.path.isfile(path), f"specialist {name} has no agent_a2a.py"
        source = open(path, encoding="utf-8").read()
        gaps = [fn for fn in required if f"def {fn}(" not in source]
        if gaps:
            missing[name] = gaps
    assert not missing, (
        f"specialist(s) missing wiring functions: {missing}. If a specialist genuinely "
        "diverges, say so here — an unlisted difference is how one of the four ended up "
        "60% covered while its siblings were at 100%."
    )
