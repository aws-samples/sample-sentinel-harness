"""
Offline tests for the Gateway wiring + named-supervisor scenario (roadmap #1)
=============================================================================
Validate the Gateway control-plane wrappers and the end-to-end scenario WITHOUT
any AWS calls or network:

  * create_gateway sends authorizerType / roleArn / protocolType correctly, only
    attaches authorizerConfiguration for CUSTOM_JWT, and rejects bad combinations;
  * wait_gateway_ready polls GetGateway and treats the right statuses as terminal;
  * the target builders produce the exact ``{"mcp": {...}}`` targetConfiguration
    envelope the service model requires (verified via boto3 introspection);
  * create_gateway_target passes targetConfiguration through verbatim;
  * name validation is enforced locally;
  * cleanup_gateways deletes only prefix-matched gateways using ``items``;
  * scenario_named_supervisor imports with ZERO AWS calls (all AWS work is guarded).

HARD RULE: ZERO AWS calls. Dummy env is set before import (client construction is
offline) and the control-plane client is monkeypatched so nothing leaves the process.
"""
from __future__ import annotations

import os
import sys

import pytest

# Repo root on path so `scenarios` (a scripts dir, not an installed package) imports.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# --- Hermetic import: no real region/profile/credentials resolution. ---
os.environ.setdefault("SENTINEL_REGION", "us-east-1")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("SENTINEL_EXECUTION_ROLE_ARN", "arn:aws:iam::000000000000:role/test-harness-role")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")

from sentinel_harness import core as sh  # noqa: E402
from sentinel_harness import gateway as gw  # noqa: E402

ROLE = os.environ["SENTINEL_EXECUTION_ROLE_ARN"]


# --------------------------------------------------------------------------- #
# Fake control client — captures request kwargs, never leaves the process     #
# --------------------------------------------------------------------------- #
class _FakeControl:
    def __init__(self, *, statuses=None, gateways=None):
        self.calls: list = []
        self._statuses = list(statuses or [])
        self._gateways = gateways or {"items": []}
        self.deleted: list = []

    def create_gateway(self, **kw):
        self.calls.append(("create_gateway", kw))
        return {"gatewayId": "gw-123", "gatewayArn": "arn:aws:test:gateway/gw-123",
                "status": "CREATING", "name": kw["name"]}

    def get_gateway(self, **kw):
        self.calls.append(("get_gateway", kw))
        st = self._statuses.pop(0) if self._statuses else "READY"
        return {"gatewayId": kw["gatewayIdentifier"], "status": st, "statusReasons": ["because"]}

    def create_gateway_target(self, **kw):
        self.calls.append(("create_gateway_target", kw))
        return {"targetId": "tgt-1", "status": "CREATING", **kw}

    def list_gateways(self, **kw):
        self.calls.append(("list_gateways", kw))
        return self._gateways

    def delete_gateway(self, **kw):
        self.calls.append(("delete_gateway", kw))
        self.deleted.append(kw["gatewayIdentifier"])
        return {}


@pytest.fixture()
def fake_control(monkeypatch):
    fc = _FakeControl()
    monkeypatch.setattr(sh, "_control", fc)
    monkeypatch.setattr(sh, "EXECUTION_ROLE_ARN", ROLE)
    # gateway.py imported _control/_role by value at import time via `from .core import`,
    # so patch the names in the gateway module namespace too.
    monkeypatch.setattr(gw, "_control", fc)
    monkeypatch.setattr(gw, "_role", lambda: ROLE)
    return fc


# --------------------------------------------------------------------------- #
# create_gateway request shape                                                #
# --------------------------------------------------------------------------- #
def test_create_gateway_defaults_aws_iam(fake_control):
    out = gw.create_gateway("sentinel-research-gw")
    (op, kw), = fake_control.calls
    assert op == "create_gateway"
    assert kw["name"] == "sentinel-research-gw"
    assert kw["roleArn"] == ROLE
    assert kw["protocolType"] == "MCP"
    assert kw["authorizerType"] == "AWS_IAM"
    # AWS_IAM must NOT carry an authorizerConfiguration (the service rejects one).
    assert "authorizerConfiguration" not in kw
    assert out["gatewayArn"] == "arn:aws:test:gateway/gw-123"


def test_create_gateway_explicit_role_and_search_type(fake_control):
    role = "arn:aws:iam::000000000000:role/other"
    gw.create_gateway("gw2", role_arn=role, search_type="SEMANTIC", description="d")
    _, kw = fake_control.calls[0]
    assert kw["roleArn"] == role
    assert kw["description"] == "d"
    assert kw["protocolConfiguration"] == {"mcp": {"searchType": "SEMANTIC"}}


def test_create_gateway_custom_jwt_attaches_config(fake_control):
    cfg = {"customJWTAuthorizer": {"discoveryUrl": "https://issuer/.well-known/openid-configuration",
                                   "allowedAudience": ["sentinel"]}}
    gw.create_gateway("gw-jwt", authorizer_type="CUSTOM_JWT", authorizer_config=cfg)
    _, kw = fake_control.calls[0]
    assert kw["authorizerType"] == "CUSTOM_JWT"
    assert kw["authorizerConfiguration"] == cfg


def test_create_gateway_custom_jwt_without_config_raises(fake_control):
    with pytest.raises(ValueError, match="CUSTOM_JWT"):
        gw.create_gateway("gw-jwt", authorizer_type="CUSTOM_JWT")


def test_create_gateway_config_on_aws_iam_raises(fake_control):
    with pytest.raises(ValueError, match="only valid with"):
        gw.create_gateway("gw", authorizer_config={"x": 1})


def test_create_gateway_bad_authorizer_type_raises(fake_control):
    with pytest.raises(ValueError, match="AWS_IAM, CUSTOM_JWT, or NONE"):
        gw.create_gateway("gw", authorizer_type="OAUTH")


def test_create_gateway_missing_role_raises(monkeypatch):
    fc = _FakeControl()
    monkeypatch.setattr(gw, "_control", fc)
    # Delegate to the real _role() which raises when the env var is missing.
    monkeypatch.setattr(sh, "EXECUTION_ROLE_ARN", None)
    monkeypatch.setattr(gw, "_role", sh._role)
    with pytest.raises(RuntimeError, match="SENTINEL_EXECUTION_ROLE_ARN"):
        gw.create_gateway("gw")


# --------------------------------------------------------------------------- #
# name validation                                                             #
# --------------------------------------------------------------------------- #
# The live CreateGateway rule is ([0-9a-zA-Z][-]?){1,48}: NO underscores, NO
# trailing/leading hyphen, max 48 chars. (These cases match the real API constraint
# that a live ValidationException surfaced — not the harness name rule.)
@pytest.mark.parametrize("name", [
    "has space", "", "bad!char", "-dash-start", "dash-end-",
    "under_score",   # underscores are rejected by the real API
    "x" * 49,        # 49 > 48-char ceiling
])
def test_create_gateway_invalid_name_raises(fake_control, name):
    with pytest.raises(ValueError, match="must match"):
        gw.create_gateway(name)


@pytest.mark.parametrize("name", ["a", "9leading", "sentinel-research-gw", "Gw1", "x" * 48])
def test_valid_names_accepted(fake_control, name):
    gw.create_gateway(name)  # should not raise


# --------------------------------------------------------------------------- #
# wait_gateway_ready polling                                                  #
# --------------------------------------------------------------------------- #
def test_wait_gateway_ready_polls_until_ready(monkeypatch):
    fc = _FakeControl(statuses=["CREATING", "CREATING", "READY"])
    monkeypatch.setattr(gw, "_control", fc)
    monkeypatch.setattr(gw.time, "sleep", lambda *_: None)  # no real waiting
    out = gw.wait_gateway_ready("gw-123", timeout=100)
    assert out["status"] == "READY"
    assert sum(1 for c in fc.calls if c[0] == "get_gateway") == 3


def test_wait_gateway_ready_raises_on_failed(monkeypatch):
    fc = _FakeControl(statuses=["CREATING", "FAILED"])
    monkeypatch.setattr(gw, "_control", fc)
    monkeypatch.setattr(gw.time, "sleep", lambda *_: None)
    with pytest.raises(RuntimeError, match="FAILED"):
        gw.wait_gateway_ready("gw-123", timeout=100)


def test_wait_gateway_ready_raises_on_update_unsuccessful(monkeypatch):
    fc = _FakeControl(statuses=["UPDATE_UNSUCCESSFUL"])
    monkeypatch.setattr(gw, "_control", fc)
    monkeypatch.setattr(gw.time, "sleep", lambda *_: None)
    with pytest.raises(RuntimeError, match="UPDATE_UNSUCCESSFUL"):
        gw.wait_gateway_ready("gw-123", timeout=100)


def test_wait_gateway_ready_times_out(monkeypatch):
    fc = _FakeControl(statuses=["CREATING"] * 50)
    monkeypatch.setattr(gw, "_control", fc)
    monkeypatch.setattr(gw.time, "sleep", lambda *_: None)
    # timeout=0 => the while condition is immediately false, so we never poll.
    with pytest.raises(TimeoutError):
        gw.wait_gateway_ready("gw-123", timeout=0)


# --------------------------------------------------------------------------- #
# target builders — the exact {"mcp": {...}} envelope                         #
# --------------------------------------------------------------------------- #
def test_lambda_mcp_target_with_inline_tools():
    tools = [{"name": "nvd_lookup", "description": "x", "inputSchema": {"type": "object"}}]
    tc = gw.lambda_mcp_target("arn:aws:lambda:us-east-1:000000000000:function:f", inline_tools=tools)
    assert tc == {"mcp": {"lambda": {
        "lambdaArn": "arn:aws:lambda:us-east-1:000000000000:function:f",
        "toolSchema": {"inlinePayload": tools}}}}


def test_lambda_mcp_target_with_explicit_schema():
    schema = {"s3": {"uri": "s3://bucket/schema.json"}}
    tc = gw.lambda_mcp_target("arn:lambda", tool_schema=schema)
    assert tc["mcp"]["lambda"]["toolSchema"] == schema


def test_lambda_mcp_target_requires_schema():
    with pytest.raises(ValueError, match="toolSchema"):
        gw.lambda_mcp_target("arn:lambda")


def test_lambda_mcp_target_requires_arn():
    with pytest.raises(ValueError, match="Lambda ARN"):
        gw.lambda_mcp_target("", inline_tools=[])


def test_openapi_http_target_inline():
    tc = gw.openapi_http_target('{"openapi":"3.0.0"}')
    assert tc == {"mcp": {"openApiSchema": {"inlinePayload": '{"openapi":"3.0.0"}'}}}


def test_openapi_http_target_url_alias_is_inline():
    tc = gw.openapi_http_target(url="{...}")
    assert tc["mcp"]["openApiSchema"] == {"inlinePayload": "{...}"}


def test_openapi_http_target_s3():
    tc = gw.openapi_http_target(s3_uri="s3://b/spec.yaml", bucket_owner="000000000000")
    assert tc == {"mcp": {"openApiSchema": {"s3": {
        "uri": "s3://b/spec.yaml", "bucketOwnerAccountId": "000000000000"}}}}


def test_openapi_http_target_requires_a_source():
    with pytest.raises(ValueError, match="inline"):
        gw.openapi_http_target()


def test_openapi_http_target_rejects_both_sources():
    with pytest.raises(ValueError, match="not both"):
        gw.openapi_http_target("{...}", s3_uri="s3://b/x")


def test_mcp_server_target():
    tc = gw.mcp_server_target("https://mcp.example/sse", listing_mode="DYNAMIC")
    assert tc == {"mcp": {"mcpServer": {"endpoint": "https://mcp.example/sse",
                                        "listingMode": "DYNAMIC"}}}


def test_mcp_server_target_requires_endpoint():
    with pytest.raises(ValueError, match="endpoint"):
        gw.mcp_server_target("")


# --------------------------------------------------------------------------- #
# create_gateway_target passes targetConfiguration through verbatim           #
# --------------------------------------------------------------------------- #
def test_create_gateway_target_passthrough(fake_control):
    tc = gw.openapi_http_target(s3_uri="s3://b/spec.yaml")
    gw.create_gateway_target("gw-123", "nvd-tools", tc, description="NVD")
    op, kw = fake_control.calls[0]
    assert op == "create_gateway_target"
    assert kw["gatewayIdentifier"] == "gw-123"
    assert kw["name"] == "nvd-tools"
    assert kw["targetConfiguration"] == tc  # verbatim, unwrapped
    assert kw["description"] == "NVD"


def test_create_gateway_target_validates_name(fake_control):
    with pytest.raises(ValueError, match="must match"):
        gw.create_gateway_target("gw-123", "bad name", {"mcp": {}})


# --------------------------------------------------------------------------- #
# list / cleanup                                                              #
# --------------------------------------------------------------------------- #
def test_list_gateways_uses_items_key(monkeypatch):
    fc = _FakeControl(gateways={"items": [{"gatewayId": "g1", "name": "a"}]})
    monkeypatch.setattr(gw, "_control", fc)
    assert gw.list_gateways() == [{"gatewayId": "g1", "name": "a"}]


def test_cleanup_gateways_deletes_only_prefix(monkeypatch):
    fc = _FakeControl(gateways={"items": [
        {"gatewayId": "g1", "name": "sentinel-a"},
        {"gatewayId": "g2", "name": "sentinel-b"},
        {"gatewayId": "g3", "name": "other-c"},
    ]})
    monkeypatch.setattr(gw, "_control", fc)
    deleted = gw.cleanup_gateways("sentinel-")
    assert deleted == ["sentinel-a", "sentinel-b"]
    assert fc.deleted == ["g1", "g2"]


def test_cleanup_gateways_best_effort_on_error(monkeypatch, capsys):
    fc = _FakeControl(gateways={"items": [
        {"gatewayId": "g1", "name": "sentinel-a"},
        {"gatewayId": "g2", "name": "sentinel-b"},
    ]})

    def boom(**kw):
        if kw["gatewayIdentifier"] == "g1":
            raise RuntimeError("in use")
        fc.deleted.append(kw["gatewayIdentifier"])
        return {}

    monkeypatch.setattr(gw, "_control", fc)
    monkeypatch.setattr(fc, "delete_gateway", boom)
    deleted = gw.cleanup_gateways("sentinel-")
    # g1 failed but teardown kept going and got g2.
    assert deleted == ["sentinel-b"]
    assert "skip" in capsys.readouterr().out


# --------------------------------------------------------------------------- #
# Scenario is import-safe offline (no AWS calls on import)                    #
# --------------------------------------------------------------------------- #
def test_scenario_named_supervisor_imports_without_aws(monkeypatch):
    """Importing the scenario must not touch AWS: any control/data client call
    should blow up the test, proving the module guards AWS work under __main__."""
    def _explode(*a, **k):
        raise AssertionError("scenario import made an AWS call")

    monkeypatch.setattr(sh._control, "create_gateway", _explode, raising=False)
    monkeypatch.setattr(sh, "create_harness", _explode)
    monkeypatch.setattr(sh, "invoke", _explode)
    import importlib
    mod = importlib.import_module("scenarios.scenario_named_supervisor")
    importlib.reload(mod)
    # It exposes the expected end-to-end entry points and the named-yaml path.
    assert hasattr(mod, "build") and hasattr(mod, "run") and hasattr(mod, "rec")
    assert mod.HARNESS_YAML.endswith(os.path.join("research-supervisor", "harness.yaml"))


def test_scenario_requires_gateway_arn(monkeypatch):
    """build() must fail fast with actionable guidance when SENTINEL_GATEWAY_ARN is
    unset — and must do so BEFORE any AWS call."""
    import importlib
    mod = importlib.import_module("scenarios.scenario_named_supervisor")
    monkeypatch.delenv("SENTINEL_GATEWAY_ARN", raising=False)
    monkeypatch.setattr(mod.sh, "create_harness", lambda *a, **k: pytest.fail("reached AWS"))
    with pytest.raises(SystemExit, match="SENTINEL_GATEWAY_ARN"):
        mod.build()
