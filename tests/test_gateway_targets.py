"""
Offline tests for the Gateway TARGET lifecycle + pagination drain (M17)
=======================================================================
Validate the target lifecycle wrappers and the shared pagination helper WITHOUT
any AWS calls or network:

  * list_gateway_targets / list_gateways drain ALL nextToken pages (the exact
    first-page-only cost+governance bug core._all_harnesses fixed for harnesses);
  * the runaway guard caps a backend that never clears nextToken;
  * delete_gateway_target / update_gateway_target / synchronize_gateway_targets
    forward the model-required members exactly (grounded via botocore);
  * update_gateway_target sends targetConfiguration as the REQUIRED full
    replacement and only forwards optional members when given;
  * synchronize_gateway_targets enforces the model's min=1/max=1 targetIdList cap
    locally and accepts a bare string;
  * cleanup_gateways deletes each gateway's targets BEFORE the gateway, keeps
    going when one target delete fails (surfaced as a WARNING), and still
    attempts the gateway delete.

HARD RULE: ZERO AWS calls. Dummy env is set before import (client construction is
offline) and the control-plane client is monkeypatched so nothing leaves the process.
"""
from __future__ import annotations

import logging
import os

import pytest

# --- Hermetic import: no real region/profile/credentials resolution. ---
os.environ.setdefault("SENTINEL_REGION", "us-east-1")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("SENTINEL_EXECUTION_ROLE_ARN", "arn:aws:iam::000000000000:role/test-harness-role")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")

from sentinel_harness import gateway as gw  # noqa: E402


# --------------------------------------------------------------------------- #
# Fake control client — captures request kwargs, never leaves the process     #
# --------------------------------------------------------------------------- #
class _FakeControl:
    """Serves canned paged responses and records every call verbatim."""

    def __init__(self, *, gateway_pages=None, target_pages=None):
        self.calls: list = []
        # Each entry is one full response dict ({"items": [...], "nextToken": ...}).
        self._gateway_pages = list(gateway_pages or [{"items": []}])
        self._target_pages = list(target_pages or [{"items": []}])
        self.deleted_gateways: list = []
        self.deleted_targets: list = []

    def _page(self, pages, token):
        # token is the 0-based index of the page to serve (as a string).
        return pages[int(token) if token else 0]

    def list_gateways(self, **kw):
        self.calls.append(("list_gateways", kw))
        return self._page(self._gateway_pages, kw.get("nextToken"))

    def list_gateway_targets(self, **kw):
        self.calls.append(("list_gateway_targets", kw))
        return self._page(self._target_pages, kw.get("nextToken"))

    def delete_gateway(self, **kw):
        self.calls.append(("delete_gateway", kw))
        self.deleted_gateways.append(kw["gatewayIdentifier"])
        return {}

    def delete_gateway_target(self, **kw):
        self.calls.append(("delete_gateway_target", kw))
        self.deleted_targets.append((kw["gatewayIdentifier"], kw["targetId"]))
        return {"targetId": kw["targetId"], "status": "DELETING"}

    def update_gateway_target(self, **kw):
        self.calls.append(("update_gateway_target", kw))
        return {"targetId": kw["targetId"], "status": "UPDATING", **kw}

    def synchronize_gateway_targets(self, **kw):
        self.calls.append(("synchronize_gateway_targets", kw))
        return {"targets": [{"targetId": t, "status": "SYNCHRONIZING"}
                            for t in kw["targetIdList"]]}


def _pages(prefix, count, per_page):
    """Build `count` paged responses whose items chain via 1-based nextToken."""
    pages = []
    for i in range(count):
        page = {"items": [{"targetId": f"{prefix}{i}-{j}", "gatewayId": f"{prefix}{i}-{j}",
                           "name": f"{prefix}{i}-{j}"} for j in range(per_page)]}
        if i < count - 1:
            page["nextToken"] = str(i + 1)
        pages.append(page)
    return pages


@pytest.fixture()
def fake(monkeypatch):
    fc = _FakeControl()
    monkeypatch.setattr(gw, "_control", fc)
    return fc


# --------------------------------------------------------------------------- #
# pagination drain — BOTH list functions, 3 fake pages                        #
# --------------------------------------------------------------------------- #
def test_list_gateways_drains_all_pages(monkeypatch):
    fc = _FakeControl(gateway_pages=_pages("g", 3, 2))
    monkeypatch.setattr(gw, "_control", fc)
    out = gw.list_gateways()
    assert len(out) == 6  # 3 pages x 2 items — page 1 alone would be 2
    assert sum(1 for c in fc.calls if c[0] == "list_gateways") == 3
    # nextToken threaded through: absent on page 1, then "1", "2".
    tokens = [kw.get("nextToken") for op, kw in fc.calls]
    assert tokens == [None, "1", "2"]


def test_list_gateway_targets_drains_all_pages(monkeypatch):
    fc = _FakeControl(target_pages=_pages("t", 3, 2))
    monkeypatch.setattr(gw, "_control", fc)
    out = gw.list_gateway_targets("gw-123")
    assert len(out) == 6
    # gatewayIdentifier is re-sent on EVERY page, not just the first.
    for op, kw in fc.calls:
        assert op == "list_gateway_targets"
        assert kw["gatewayIdentifier"] == "gw-123"


def test_list_gateways_single_page_no_token(monkeypatch):
    fc = _FakeControl(gateway_pages=[{"items": [{"gatewayId": "g1", "name": "a"}]}])
    monkeypatch.setattr(gw, "_control", fc)
    assert gw.list_gateways() == [{"gatewayId": "g1", "name": "a"}]
    assert sum(1 for c in fc.calls if c[0] == "list_gateways") == 1


def test_pagination_runaway_guard_caps(monkeypatch):
    """A backend that never clears nextToken must terminate at the guard, not spin."""
    calls = {"n": 0}

    def never_ending(**kw):
        calls["n"] += 1
        return {"items": [{"gatewayId": f"g{calls['n']}"}], "nextToken": "again"}

    monkeypatch.setattr(gw, "_MAX_PAGES", 5)  # keep the test fast; semantics identical
    out = gw._drain_pages(never_ending)
    assert calls["n"] == 5  # capped exactly at the guard
    assert len(out) == 5


# --------------------------------------------------------------------------- #
# delete / update / synchronize — param forwarding (model-grounded shapes)    #
# --------------------------------------------------------------------------- #
def test_delete_gateway_target_forwards_both_required_members(fake):
    out = gw.delete_gateway_target("gw-123", "tgt0000001")
    (op, kw), = fake.calls
    assert op == "delete_gateway_target"
    # Model: required = gatewayIdentifier + targetId, and NOTHING else is sent.
    assert kw == {"gatewayIdentifier": "gw-123", "targetId": "tgt0000001"}
    assert out["status"] == "DELETING"


def test_update_gateway_target_sends_required_full_replacement(fake):
    tc = gw.mcp_server_target("https://mcp.example/sse", listing_mode="DYNAMIC")
    gw.update_gateway_target("gw-123", "tgt0000001", tc)
    (op, kw), = fake.calls
    assert op == "update_gateway_target"
    # Model: gatewayIdentifier + targetId + targetConfiguration are ALL required —
    # targetConfiguration is a full replacement, so it must always be present.
    assert kw == {"gatewayIdentifier": "gw-123", "targetId": "tgt0000001",
                  "targetConfiguration": tc}


def test_update_gateway_target_optional_members(fake):
    tc = {"mcp": {"mcpServer": {"endpoint": "https://x"}}}
    creds = [{"credentialProviderType": "GATEWAY_IAM_ROLE"}]
    gw.update_gateway_target("gw-123", "tgt0000001", tc,
                             name="renamed-target", description="d",
                             credential_provider_configs=creds)
    (_, kw), = fake.calls
    assert kw["name"] == "renamed-target"
    assert kw["description"] == "d"
    assert kw["credentialProviderConfigurations"] == creds


def test_update_gateway_target_validates_name(fake):
    with pytest.raises(ValueError, match="must match"):
        gw.update_gateway_target("gw-123", "tgt0000001", {"mcp": {}}, name="bad name")
    assert fake.calls == []  # rejected locally, never reached the client


def test_synchronize_gateway_targets_accepts_bare_string(fake):
    out = gw.synchronize_gateway_targets("gw-123", "tgt0000001")
    (op, kw), = fake.calls
    assert op == "synchronize_gateway_targets"
    assert kw == {"gatewayIdentifier": "gw-123", "targetIdList": ["tgt0000001"]}
    assert out == [{"targetId": "tgt0000001", "status": "SYNCHRONIZING"}]


def test_synchronize_gateway_targets_rejects_multi_id(fake):
    # Model metadata caps targetIdList at min=1/max=1 — catch it locally.
    with pytest.raises(ValueError, match="exactly ONE"):
        gw.synchronize_gateway_targets("gw-123", ["t1", "t2"])
    with pytest.raises(ValueError, match="exactly ONE"):
        gw.synchronize_gateway_targets("gw-123", [])
    assert fake.calls == []


# --------------------------------------------------------------------------- #
# cleanup_gateways — targets go first, best-effort per target                 #
# --------------------------------------------------------------------------- #
def test_cleanup_deletes_targets_before_gateway(monkeypatch):
    fc = _FakeControl(
        gateway_pages=[{"items": [{"gatewayId": "g1", "name": "sentinel-a"}]}],
        target_pages=[{"items": [{"targetId": "t1", "name": "tools-1"},
                                 {"targetId": "t2", "name": "tools-2"}]}],
    )
    monkeypatch.setattr(gw, "_control", fc)
    deleted = gw.cleanup_gateways("sentinel-")
    assert deleted == ["sentinel-a"]
    assert fc.deleted_targets == [("g1", "t1"), ("g1", "t2")]
    # Ordering: BOTH target deletes strictly precede the gateway delete.
    ops = [op for op, _ in fc.calls]
    assert ops.index("delete_gateway") > max(
        i for i, op in enumerate(ops) if op == "delete_gateway_target")


def test_cleanup_still_deletes_gateway_when_target_delete_fails(monkeypatch, caplog):
    fc = _FakeControl(
        gateway_pages=[{"items": [{"gatewayId": "g1", "name": "sentinel-a"}]}],
        target_pages=[{"items": [{"targetId": "t1", "name": "tools-1"},
                                 {"targetId": "t2", "name": "tools-2"}]}],
    )

    real_delete_target = fc.delete_gateway_target

    def boom(**kw):
        if kw["targetId"] == "t1":
            raise RuntimeError("target stuck in SYNCHRONIZING")
        return real_delete_target(**kw)

    monkeypatch.setattr(gw, "_control", fc)
    monkeypatch.setattr(fc, "delete_gateway_target", boom)
    with caplog.at_level(logging.WARNING, logger="sentinel_harness.gateway"):
        deleted = gw.cleanup_gateways("sentinel-")
    # t1 failed (surfaced as WARNING) but t2 was deleted AND the gateway delete
    # was still attempted — one stuck target no longer aborts the teardown.
    assert fc.deleted_targets == [("g1", "t2")]
    assert deleted == ["sentinel-a"]
    assert any("could not delete target" in r.getMessage() and "tools-1" in r.getMessage()
               for r in caplog.records)


def test_cleanup_paginates_gateways_beyond_first_page(monkeypatch):
    # Gateways on page 2/3 must be found and deleted — not orphaned.
    pages = _pages("g", 3, 1)
    for p in pages:
        for item in p["items"]:
            item["name"] = "sentinel-" + item["gatewayId"]
    fc = _FakeControl(gateway_pages=pages)
    monkeypatch.setattr(gw, "_control", fc)
    deleted = gw.cleanup_gateways("sentinel-")
    assert len(deleted) == 3
    assert fc.deleted_gateways == ["g0-0", "g1-0", "g2-0"]


def test_cleanup_list_targets_failure_is_warned_and_gateway_still_tried(monkeypatch, caplog):
    fc = _FakeControl(gateway_pages=[{"items": [{"gatewayId": "g1", "name": "sentinel-a"}]}])

    def boom(**kw):
        raise RuntimeError("AccessDenied on ListGatewayTargets")

    monkeypatch.setattr(gw, "_control", fc)
    monkeypatch.setattr(fc, "list_gateway_targets", boom)
    with caplog.at_level(logging.WARNING, logger="sentinel_harness.gateway"):
        deleted = gw.cleanup_gateways("sentinel-")
    assert deleted == ["sentinel-a"]  # gateway delete still attempted
    assert any("could not list targets" in r.getMessage() for r in caplog.records)


# --------------------------------------------------------------------------- #
# model-grounding — the wrappers match the real service model, checked offline #
# --------------------------------------------------------------------------- #
def test_target_lifecycle_ops_match_service_model():
    """The shapes these wrappers assume must exist in the real botocore model, so a
    model drift is caught offline (mirrors test_hardening_builders_match_service_schema)."""
    import botocore.session
    m = botocore.session.get_session().get_service_model("bedrock-agentcore-control")

    lst = m.operation_model("ListGatewayTargets")
    assert set(lst.input_shape.required_members) == {"gatewayIdentifier"}
    assert {"items", "nextToken"} <= set(lst.output_shape.members)

    dele = m.operation_model("DeleteGatewayTarget")
    assert set(dele.input_shape.required_members) == {"gatewayIdentifier", "targetId"}

    upd = m.operation_model("UpdateGatewayTarget")
    # targetConfiguration REQUIRED on update => full replacement, never a patch.
    assert set(upd.input_shape.required_members) == {
        "gatewayIdentifier", "targetId", "targetConfiguration"}

    sync = m.operation_model("SynchronizeGatewayTargets")
    assert set(sync.input_shape.required_members) == {"gatewayIdentifier", "targetIdList"}
    til = sync.input_shape.members["targetIdList"]
    assert til.metadata.get("min") == 1 and til.metadata.get("max") == 1
    assert "targets" in sync.output_shape.members

    # ListGateways pagination members exist (the drain in list_gateways relies on them).
    lg = m.operation_model("ListGateways")
    assert {"nextToken"} <= set(lg.input_shape.members)
    assert {"items", "nextToken"} <= set(lg.output_shape.members)
