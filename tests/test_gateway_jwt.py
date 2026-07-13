"""
Offline tests for cognito_jwt_authorizer + CUSTOM_JWT wiring (roadmap: CUSTOM_JWT)
=================================================================================
Validate the ``cognito_jwt_authorizer`` helper and its slot into ``create_gateway``
WITHOUT any AWS calls or network:

  * the human path builds ``{"customJWTAuthorizer": {discoveryUrl, allowedAudience}}``
    (ID tokens carry an ``aud`` claim);
  * the machine path builds ``{"customJWTAuthorizer": {discoveryUrl, allowedClients}}``
    (M2M access tokens have NO ``aud`` claim, so validate ``client_id``);
  * giving neither (or both) audience/clients raises locally;
  * a single string is accepted and wrapped into a one-element list;
  * the block slots into create_gateway(authorizer_type="CUSTOM_JWT", ...) and is
    sent verbatim as authorizerConfiguration;
  * the same config is REJECTED for AWS_IAM (the service rejects a config there).

HARD RULE: ZERO AWS calls. Dummy env is set before import (client construction is
offline) and the control-plane client is monkeypatched so nothing leaves the process.
Mirrors tests/test_gateway.py patterns (same _FakeControl + fixture shape).
"""
from __future__ import annotations

import os
import sys

import pytest

# Repo root on path so sibling scripts import (mirror test_gateway.py).
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
DISCOVERY = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_pool/.well-known/openid-configuration"


# --------------------------------------------------------------------------- #
# Fake control client — captures request kwargs, never leaves the process     #
# (same shape as tests/test_gateway.py)                                        #
# --------------------------------------------------------------------------- #
class _FakeControl:
    def __init__(self):
        self.calls: list = []

    def create_gateway(self, **kw):
        self.calls.append(("create_gateway", kw))
        return {"gatewayId": "gw-jwt", "gatewayArn": "arn:aws:test:gateway/gw-jwt",
                "status": "CREATING", "name": kw["name"]}


@pytest.fixture()
def fake_control(monkeypatch):
    fc = _FakeControl()
    monkeypatch.setattr(sh, "_control", fc)
    monkeypatch.setattr(sh, "EXECUTION_ROLE_ARN", ROLE)
    monkeypatch.setattr(gw, "_control", fc)
    monkeypatch.setattr(gw, "_role", lambda: ROLE)
    return fc


# --------------------------------------------------------------------------- #
# Human path — allowedAudience (ID token carries an aud claim)                 #
# --------------------------------------------------------------------------- #
def test_human_audience_path():
    cfg = gw.cognito_jwt_authorizer(DISCOVERY, allowed_audience=["app-client-id"])
    assert cfg == {"customJWTAuthorizer": {
        "discoveryUrl": DISCOVERY,
        "allowedAudience": ["app-client-id"],
    }}
    # Human path must NOT carry allowedClients.
    assert "allowedClients" not in cfg["customJWTAuthorizer"]


def test_human_audience_accepts_bare_string():
    cfg = gw.cognito_jwt_authorizer(DISCOVERY, allowed_audience="app-client-id")
    assert cfg["customJWTAuthorizer"]["allowedAudience"] == ["app-client-id"]


# --------------------------------------------------------------------------- #
# Machine path — allowedClients (M2M access token has NO aud claim)            #
# --------------------------------------------------------------------------- #
def test_machine_clients_path():
    cfg = gw.cognito_jwt_authorizer(DISCOVERY, allowed_clients=["m2m-client-id"])
    assert cfg == {"customJWTAuthorizer": {
        "discoveryUrl": DISCOVERY,
        "allowedClients": ["m2m-client-id"],
    }}
    # Machine path must NOT carry allowedAudience (access tokens have no aud).
    assert "allowedAudience" not in cfg["customJWTAuthorizer"]


def test_machine_clients_accepts_bare_string():
    cfg = gw.cognito_jwt_authorizer(DISCOVERY, allowed_clients="m2m-client-id")
    assert cfg["customJWTAuthorizer"]["allowedClients"] == ["m2m-client-id"]


# --------------------------------------------------------------------------- #
# Misconfiguration is caught locally                                          #
# --------------------------------------------------------------------------- #
def test_neither_audience_nor_clients_raises():
    with pytest.raises(ValueError, match="exactly one"):
        gw.cognito_jwt_authorizer(DISCOVERY)


def test_both_audience_and_clients_raises():
    with pytest.raises(ValueError, match="exactly one"):
        gw.cognito_jwt_authorizer(DISCOVERY, allowed_audience=["a"], allowed_clients=["c"])


def test_missing_discovery_url_raises():
    with pytest.raises(ValueError, match="discovery_url"):
        gw.cognito_jwt_authorizer("", allowed_audience=["a"])


# --------------------------------------------------------------------------- #
# Slots into create_gateway for CUSTOM_JWT (sent verbatim)                     #
# --------------------------------------------------------------------------- #
def test_slots_into_create_gateway_custom_jwt_human(fake_control):
    cfg = gw.cognito_jwt_authorizer(DISCOVERY, allowed_audience=["app-client-id"])
    gw.create_gateway("gw-jwt-human", authorizer_type="CUSTOM_JWT", authorizer_config=cfg)
    op, kw = fake_control.calls[0]
    assert op == "create_gateway"
    assert kw["authorizerType"] == "CUSTOM_JWT"
    assert kw["authorizerConfiguration"] == cfg


def test_slots_into_create_gateway_custom_jwt_machine(fake_control):
    cfg = gw.cognito_jwt_authorizer(DISCOVERY, allowed_clients=["m2m-client-id"])
    gw.create_gateway("gw-jwt-m2m", authorizer_type="CUSTOM_JWT", authorizer_config=cfg)
    _, kw = fake_control.calls[0]
    assert kw["authorizerConfiguration"]["customJWTAuthorizer"]["allowedClients"] == ["m2m-client-id"]


# --------------------------------------------------------------------------- #
# Rejected for AWS_IAM (the service rejects a config on AWS_IAM/NONE)          #
# --------------------------------------------------------------------------- #
def test_rejected_for_aws_iam(fake_control):
    cfg = gw.cognito_jwt_authorizer(DISCOVERY, allowed_audience=["app-client-id"])
    with pytest.raises(ValueError, match="only valid with"):
        gw.create_gateway("gw-iam", authorizer_type="AWS_IAM", authorizer_config=cfg)
    # And nothing was sent to the service.
    assert fake_control.calls == []
