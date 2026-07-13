"""
Offline unit tests for ``sentinel_harness/registry_live.py``
============================================================
These tests are 100% OFFLINE and deterministic. They NEVER touch AWS. The live
Registry wrapper talks to the shared ``core._control`` (a real
``bedrock-agentcore-control`` boto3 client) — here we monkeypatch
``registry_live._control`` with an in-process **fake** whose methods return canned
dicts (or raise on demand). We assert:

* ``create_registry`` returns the ARN, defaults ``autoApproval`` to ``False``, sends
  a ``clientToken`` of at least 33 chars, and rejects an empty name / a bad
  ``authorizer_type`` with ``RegistryLiveError``.
* ``create_skill_record`` / ``create_custom_record`` send ``descriptorType``
  ``AGENT_SKILLS`` / ``CUSTOM`` with inline content and return
  ``{"recordArn", "status"}`` — DRAFT-until-approved because autoApproval is off.
* ``list_records`` returns the ``registryRecords`` list.
* ``submit_for_approval`` returns the status-transition dict (DRAFT ->
  PENDING_APPROVAL).
* EVERY wrapper surfaces an underlying client exception as ``RegistryLiveError``
  and never swallows it.
* the descriptor-type guard rejects an unknown type.

The real Registry (registryId 2lfhZ8sGMIXQnsOQ, an AGENT_SKILLS record moved
DRAFT -> PENDING_APPROVAL) was already exercised live on a non-prod dev account;
this file locks the request shape and error contract so regressions are caught
without AWS.
"""
from __future__ import annotations

import importlib

import pytest

registry_live = importlib.import_module("sentinel_harness.registry_live")
RegistryLiveError = registry_live.RegistryLiveError


# --------------------------------------------------------------------------- #
# Fakes                                                                       #
# --------------------------------------------------------------------------- #
class _FakeResourceNotFound(Exception):
    """Stand-in for the botocore ResourceNotFoundException modeled on the client."""


class _FakeExceptions:
    ResourceNotFoundException = _FakeResourceNotFound


class FakeControl:
    """Records the kwargs each op was called with and returns canned dicts.

    Mirrors the surface of the ``bedrock-agentcore-control`` client that
    ``registry_live`` uses: the six Registry ops plus an ``exceptions`` namespace
    (so ``delete_registry`` can catch ResourceNotFoundException by type).
    """

    def __init__(self, responses=None):
        self.calls: dict[str, dict] = {}
        self._responses = responses or {}
        self.exceptions = _FakeExceptions()

    def _record(self, op: str, kwargs: dict):
        self.calls[op] = kwargs

    def create_registry(self, **kwargs):
        self._record("create_registry", kwargs)
        return self._responses.get(
            "create_registry",
            {
                "registryArn": "arn:aws:bedrock-agentcore:us-east-1:000000000000:registry/reg-1",
                "ResponseMetadata": {"HTTPStatusCode": 200},
            },
        )

    def get_registry(self, **kwargs):
        self._record("get_registry", kwargs)
        return self._responses.get(
            "get_registry",
            {
                "registryId": "reg-1",
                "name": "sentinel-gov",
                "status": "ACTIVE",
                "ResponseMetadata": {"HTTPStatusCode": 200},
            },
        )

    def delete_registry(self, **kwargs):
        self._record("delete_registry", kwargs)
        return self._responses.get("delete_registry", {})

    def create_registry_record(self, **kwargs):
        self._record("create_registry_record", kwargs)
        return self._responses.get(
            "create_registry_record",
            {
                "recordArn": "arn:aws:bedrock-agentcore:us-east-1:000000000000:registry-record/rec-1",
                "status": "DRAFT",
                "ResponseMetadata": {"HTTPStatusCode": 200},
            },
        )

    def list_registry_records(self, **kwargs):
        self._record("list_registry_records", kwargs)
        return self._responses.get(
            "list_registry_records",
            {
                "registryRecords": [
                    {"name": "soc-triage", "descriptorType": "AGENT_SKILLS", "status": "DRAFT"}
                ],
                "ResponseMetadata": {"HTTPStatusCode": 200},
            },
        )

    def submit_registry_record_for_approval(self, **kwargs):
        self._record("submit_registry_record_for_approval", kwargs)
        return self._responses.get(
            "submit_registry_record_for_approval",
            {
                "recordId": "rec-1",
                "status": "PENDING_APPROVAL",
                "previousStatus": "DRAFT",
                "ResponseMetadata": {"HTTPStatusCode": 200},
            },
        )


class BoomControl:
    """A fake whose every op raises — proves nothing is swallowed."""

    class _BoomExceptions:
        # A ResourceNotFoundException that will NOT match the raised RuntimeError,
        # so delete_registry's generic handler is what wraps the failure.
        ResourceNotFoundException = _FakeResourceNotFound

    def __init__(self, exc: Exception | None = None):
        self._exc = exc or RuntimeError("boom: upstream client failure")
        self.exceptions = BoomControl._BoomExceptions()

    def _raise(self, *_a, **_k):
        raise self._exc

    create_registry = _raise
    get_registry = _raise
    delete_registry = _raise
    create_registry_record = _raise
    list_registry_records = _raise
    submit_registry_record_for_approval = _raise


@pytest.fixture
def fake(monkeypatch):
    ctl = FakeControl()
    monkeypatch.setattr(registry_live, "_control", ctl)
    return ctl


@pytest.fixture
def boom(monkeypatch):
    ctl = BoomControl()
    monkeypatch.setattr(registry_live, "_control", ctl)
    return ctl


# --------------------------------------------------------------------------- #
# create_registry                                                             #
# --------------------------------------------------------------------------- #
def test_create_registry_returns_arn(fake):
    arn = registry_live.create_registry("sentinel-gov")
    assert arn == "arn:aws:bedrock-agentcore:us-east-1:000000000000:registry/reg-1"


def test_create_registry_defaults_auto_approval_false(fake):
    registry_live.create_registry("sentinel-gov")
    sent = fake.calls["create_registry"]
    assert sent["approvalConfiguration"] == {"autoApproval": False}
    assert sent["name"] == "sentinel-gov"
    # default authorizer type
    assert sent["authorizerType"] == "AWS_IAM"


def test_create_registry_client_token_min_length(fake):
    registry_live.create_registry("x")  # short name -> token must still be padded
    sent = fake.calls["create_registry"]
    assert len(sent["clientToken"]) >= 33


def test_create_registry_honors_explicit_flags(fake):
    registry_live.create_registry(
        "sentinel-gov",
        description="governance registry",
        auto_approval=True,
        authorizer_type="CUSTOM_JWT",
        client_token="x" * 40,
    )
    sent = fake.calls["create_registry"]
    assert sent["approvalConfiguration"] == {"autoApproval": True}
    assert sent["authorizerType"] == "CUSTOM_JWT"
    assert sent["description"] == "governance registry"
    assert sent["clientToken"] == "x" * 40


def test_create_registry_omits_empty_description(fake):
    registry_live.create_registry("sentinel-gov")
    assert "description" not in fake.calls["create_registry"]


def test_create_registry_rejects_empty_name(fake):
    with pytest.raises(RegistryLiveError, match="name is required"):
        registry_live.create_registry("")
    # guard runs before any client call
    assert "create_registry" not in fake.calls


def test_create_registry_rejects_bad_authorizer_type(fake):
    with pytest.raises(RegistryLiveError, match="authorizer_type"):
        registry_live.create_registry("sentinel-gov", authorizer_type="OAUTH")
    assert "create_registry" not in fake.calls


def test_create_registry_missing_arn_is_error(monkeypatch):
    ctl = FakeControl(responses={"create_registry": {"ResponseMetadata": {}}})
    monkeypatch.setattr(registry_live, "_control", ctl)
    with pytest.raises(RegistryLiveError, match="no registryArn"):
        registry_live.create_registry("sentinel-gov")


def test_create_registry_wraps_client_error(boom):
    with pytest.raises(RegistryLiveError, match="create_registry.*failed") as ei:
        registry_live.create_registry("sentinel-gov")
    # underlying cause preserved, not swallowed
    assert isinstance(ei.value.__cause__, RuntimeError)


# --------------------------------------------------------------------------- #
# get_registry / delete_registry                                              #
# --------------------------------------------------------------------------- #
def test_get_registry_strips_response_metadata(fake):
    out = registry_live.get_registry("reg-1")
    assert out["status"] == "ACTIVE"
    assert "ResponseMetadata" not in out
    assert fake.calls["get_registry"] == {"registryId": "reg-1"}


def test_get_registry_wraps_client_error(boom):
    with pytest.raises(RegistryLiveError, match="get_registry.*failed"):
        registry_live.get_registry("reg-1")


def test_delete_registry_passes_id(fake):
    assert registry_live.delete_registry("reg-1") is None
    assert fake.calls["delete_registry"] == {"registryId": "reg-1"}


def test_delete_registry_missing_is_not_fatal(monkeypatch):
    class NotFoundControl(FakeControl):
        def delete_registry(self, **kwargs):
            raise _FakeResourceNotFound("gone")

    ctl = NotFoundControl()
    monkeypatch.setattr(registry_live, "_control", ctl)
    # ResourceNotFoundException is swallowed by design (idempotent teardown)
    assert registry_live.delete_registry("reg-404") is None


def test_delete_registry_wraps_other_client_error(boom):
    with pytest.raises(RegistryLiveError, match="delete_registry.*failed"):
        registry_live.delete_registry("reg-1")


# --------------------------------------------------------------------------- #
# create_skill_record / create_custom_record                                  #
# --------------------------------------------------------------------------- #
def test_create_skill_record_shape(fake):
    out = registry_live.create_skill_record(
        "reg-1", "soc-triage", "# SKILL\nTriage SOC alerts.", description="triage skill"
    )
    assert out == {
        "recordArn": "arn:aws:bedrock-agentcore:us-east-1:000000000000:registry-record/rec-1",
        "status": "DRAFT",
    }
    sent = fake.calls["create_registry_record"]
    assert sent["registryId"] == "reg-1"
    assert sent["name"] == "soc-triage"
    assert sent["descriptorType"] == "AGENT_SKILLS"
    assert sent["descriptors"] == {
        "agentSkills": {"skillMd": {"inlineContent": "# SKILL\nTriage SOC alerts."}}
    }
    assert sent["description"] == "triage skill"
    assert len(sent["clientToken"]) >= 33


def test_create_skill_record_draft_until_approved(fake):
    # autoApproval=false semantics: a freshly created record is DRAFT (not live)
    out = registry_live.create_skill_record("reg-1", "soc-triage", "# SKILL")
    assert out["status"] == "DRAFT"


def test_create_custom_record_shape(fake):
    out = registry_live.create_custom_record(
        "reg-1", "web-search", '{"tool":"web_search"}'
    )
    assert set(out) == {"recordArn", "status"}
    sent = fake.calls["create_registry_record"]
    assert sent["descriptorType"] == "CUSTOM"
    assert sent["descriptors"] == {"custom": {"inlineContent": '{"tool":"web_search"}'}}


def test_create_custom_record_omits_empty_description(fake):
    registry_live.create_custom_record("reg-1", "web-search", "{}")
    assert "description" not in fake.calls["create_registry_record"]


def test_create_record_rejects_unknown_descriptor_type(fake):
    with pytest.raises(RegistryLiveError, match="descriptor_type must be one of"):
        registry_live._create_record("reg-1", "bad", "GRPC", {"grpc": {}})
    assert "create_registry_record" not in fake.calls


def test_create_skill_record_wraps_client_error(boom):
    with pytest.raises(RegistryLiveError, match="create_registry_record.*failed"):
        registry_live.create_skill_record("reg-1", "soc-triage", "# SKILL")


def test_create_custom_record_wraps_client_error(boom):
    with pytest.raises(RegistryLiveError, match="create_registry_record.*failed"):
        registry_live.create_custom_record("reg-1", "web-search", "{}")


def test_create_record_returns_empty_strings_when_absent(monkeypatch):
    ctl = FakeControl(responses={"create_registry_record": {"ResponseMetadata": {}}})
    monkeypatch.setattr(registry_live, "_control", ctl)
    out = registry_live.create_skill_record("reg-1", "soc-triage", "# SKILL")
    assert out == {"recordArn": "", "status": ""}


# --------------------------------------------------------------------------- #
# list_records                                                                #
# --------------------------------------------------------------------------- #
def test_list_records_returns_registry_records(fake):
    records = registry_live.list_records("reg-1")
    assert records == [
        {"name": "soc-triage", "descriptorType": "AGENT_SKILLS", "status": "DRAFT"}
    ]
    assert fake.calls["list_registry_records"] == {"registryId": "reg-1"}


def test_list_records_empty_when_key_absent(monkeypatch):
    ctl = FakeControl(responses={"list_registry_records": {"ResponseMetadata": {}}})
    monkeypatch.setattr(registry_live, "_control", ctl)
    assert registry_live.list_records("reg-1") == []


def test_list_records_wraps_client_error(boom):
    with pytest.raises(RegistryLiveError, match="list_registry_records.*failed"):
        registry_live.list_records("reg-1")


# --------------------------------------------------------------------------- #
# submit_for_approval                                                         #
# --------------------------------------------------------------------------- #
def test_submit_for_approval_transition(fake):
    out = registry_live.submit_for_approval("reg-1", "rec-1")
    assert out["status"] == "PENDING_APPROVAL"
    assert out["previousStatus"] == "DRAFT"
    assert "ResponseMetadata" not in out
    assert fake.calls["submit_registry_record_for_approval"] == {
        "registryId": "reg-1",
        "recordId": "rec-1",
    }


def test_submit_for_approval_wraps_client_error(boom):
    with pytest.raises(RegistryLiveError, match="submit_registry_record_for_approval.*failed"):
        registry_live.submit_for_approval("reg-1", "rec-1")


# --------------------------------------------------------------------------- #
# helpers                                                                     #
# --------------------------------------------------------------------------- #
def test_client_token_pads_short_seed():
    assert len(registry_live._client_token("a")) >= 33


def test_client_token_deterministic_per_seed():
    assert registry_live._client_token("soc") == registry_live._client_token("soc")


def test_descriptor_types_constant():
    assert registry_live.DESCRIPTOR_TYPES == ("MCP", "A2A", "CUSTOM", "AGENT_SKILLS")
