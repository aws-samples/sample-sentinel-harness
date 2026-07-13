"""
Offline tests for sentinel_harness.core harness-endpoint wrappers
==================================================================
An endpoint is the promote-to-production mechanism (ROADMAP M2 §5.3): a passing
harness reaches production by pointing a named, optionally version-pinned endpoint
at it. These four wrappers are THIN — they assemble args and delegate to
``core._control``. The tests prove the arg-assembly contract with ZERO AWS calls:
``core._control`` is monkeypatched to a fake that captures the kwargs it receives.

Coverage:
- create_harness_endpoint always sends harnessId/endpointName,
- targetVersion/description are OMITTED when None and INCLUDED when set,
- extra kw passes straight through,
- create returns the unwrapped ``["endpoint"]`` with raw-response fallback,
- get_harness_endpoint sends the right params + unwraps (with fallback),
- list_harness_versions returns the ``harnessVersions`` list,
- delete_harness_endpoint sends the right params.

No real account/role/secret: the 000000000000 placeholder is set below.
"""
from __future__ import annotations

import os

import pytest

# --- Hermetic import: no real region/profile/credentials resolution. ---
os.environ.setdefault("SENTINEL_REGION", "us-east-1")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("SENTINEL_EXECUTION_ROLE_ARN", "arn:aws:iam::000000000000:role/test-harness-role")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")

from sentinel_harness import core as sh  # noqa: E402


class _CapturingControl:
    """Captures endpoint/version call kwargs; returns canned response envelopes.

    Any other attribute access blows up so an accidental real code path is loud."""

    def __init__(self, *, create=None, get=None, versions=None, delete=None):
        self.create_calls: list[dict] = []
        self.get_calls: list[dict] = []
        self.versions_calls: list[dict] = []
        self.delete_calls: list[dict] = []
        self._create = create if create is not None else {
            "endpoint": {"endpointName": "prod", "status": "CREATING", "targetVersion": "3"}
        }
        self._get = get if get is not None else {
            "endpoint": {"endpointName": "prod", "status": "READY", "targetVersion": "3"}
        }
        self._versions = versions if versions is not None else {
            "harnessVersions": [{"version": "1"}, {"version": "2"}, {"version": "3"}]
        }
        self._delete = delete if delete is not None else {
            "ResponseMetadata": {"HTTPStatusCode": 200}
        }

    def create_harness_endpoint(self, **kwargs):
        self.create_calls.append(kwargs)
        return self._create

    def get_harness_endpoint(self, **kwargs):
        self.get_calls.append(kwargs)
        return self._get

    def list_harness_versions(self, **kwargs):
        self.versions_calls.append(kwargs)
        return self._versions

    def delete_harness_endpoint(self, **kwargs):
        self.delete_calls.append(kwargs)
        return self._delete

    def __getattr__(self, item):  # pragma: no cover - defensive
        raise AssertionError(f"endpoint test must not touch _control.{item}")


@pytest.fixture()
def fake_control(monkeypatch):
    ctrl = _CapturingControl()
    monkeypatch.setattr(sh, "_control", ctrl)
    return ctrl


# --------------------------------------------------------------- create_harness_endpoint
def test_create_sends_required_params(fake_control):
    sh.create_harness_endpoint("hid-42", "prod")
    call = fake_control.create_calls[0]
    assert call["harnessId"] == "hid-42"
    assert call["endpointName"] == "prod"


def test_create_omits_target_version_and_description_when_none(fake_control):
    """A bare create sends only harnessId + endpointName — no None optionals leak."""
    sh.create_harness_endpoint("hid-42", "prod")
    call = fake_control.create_calls[0]
    assert set(call) == {"harnessId", "endpointName"}
    assert "targetVersion" not in call
    assert "description" not in call


def test_create_includes_target_version_and_description_when_set(fake_control):
    sh.create_harness_endpoint(
        "hid-42", "prod", target_version="3", description="promote passing candidate"
    )
    call = fake_control.create_calls[0]
    assert call["targetVersion"] == "3"
    assert call["description"] == "promote passing candidate"


def test_create_kw_passthrough(fake_control):
    """Extra kw (e.g. tags) passes straight through to the control-plane call."""
    sh.create_harness_endpoint("hid-42", "prod", tags={"env": "prod"})
    assert fake_control.create_calls[0]["tags"] == {"env": "prod"}


def test_create_returns_unwrapped_endpoint(fake_control):
    out = sh.create_harness_endpoint("hid-42", "prod")
    assert out == {"endpointName": "prod", "status": "CREATING", "targetVersion": "3"}


def test_create_returns_raw_response_when_no_endpoint_key(monkeypatch):
    ctrl = _CapturingControl(create={"ResponseMetadata": {"HTTPStatusCode": 200}})
    monkeypatch.setattr(sh, "_control", ctrl)
    out = sh.create_harness_endpoint("hid-42", "prod")
    assert out == {"ResponseMetadata": {"HTTPStatusCode": 200}}


# --------------------------------------------------------------- get_harness_endpoint
def test_get_sends_params_and_unwraps(fake_control):
    out = sh.get_harness_endpoint("hid-42", "prod")
    call = fake_control.get_calls[0]
    assert call == {"harnessId": "hid-42", "endpointName": "prod"}
    assert out == {"endpointName": "prod", "status": "READY", "targetVersion": "3"}


def test_get_returns_raw_response_when_no_endpoint_key(monkeypatch):
    ctrl = _CapturingControl(get={"ResponseMetadata": {"HTTPStatusCode": 200}})
    monkeypatch.setattr(sh, "_control", ctrl)
    out = sh.get_harness_endpoint("hid-42", "prod")
    assert out == {"ResponseMetadata": {"HTTPStatusCode": 200}}


# --------------------------------------------------------------- list_harness_versions
def test_list_versions_sends_id_and_returns_list(fake_control):
    out = sh.list_harness_versions("hid-42")
    assert fake_control.versions_calls[0] == {"harnessId": "hid-42"}
    assert out == [{"version": "1"}, {"version": "2"}, {"version": "3"}]


# --------------------------------------------------------------- delete_harness_endpoint
def test_delete_sends_params(fake_control):
    out = sh.delete_harness_endpoint("hid-42", "prod")
    assert fake_control.delete_calls[0] == {"harnessId": "hid-42", "endpointName": "prod"}
    assert out == {"ResponseMetadata": {"HTTPStatusCode": 200}}
