"""
Offline factory tests for sentinel-harness
============================================
Exercise ``sentinel_harness.factory`` — config-driven provision-at-scale — with
ZERO AWS calls and ZERO network. ``core._control`` / ``core.list_harnesses`` /
``core.create_harness`` are monkeypatched to in-memory fakes so nothing leaves the
process. The shipped ``harnesses/*/harness.yaml`` files are used as real fixtures.

Coverage:
- dry_run resolves + validates EVERY config with zero AWS calls (asserted by a fake
  that raises if touched),
- idempotency: an existing harness is skipped (``exists``), not recreated,
- env tagging: created harnesses carry the ``sentinel:env`` tag,
- tag-guard: a same-name harness under a different env blocks the fleet,
- a bad manifest fails loudly (FactoryError),
- teardown by manifest and by prefix.

No real account/role/secret: env is the 000000000000 placeholder set below.
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
from sentinel_harness import factory  # noqa: E402

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_HARNESSES_DIR = os.path.join(_REPO, "harnesses")


def _yaml(name: str) -> str:
    return os.path.join(_HARNESSES_DIR, name, "harness.yaml")


# --------------------------------------------------------------------------- #
# Env fixtures.                                                               #
# --------------------------------------------------------------------------- #
@pytest.fixture()
def gateway_env(monkeypatch):
    """Placeholder Gateway ARN so the shipped yaml's ${SENTINEL_GATEWAY_ARN} resolves."""
    monkeypatch.setenv(
        "SENTINEL_GATEWAY_ARN",
        "arn:aws:bedrock-agentcore:us-east-1:000000000000:gateway/test-gw",
    )
    # Pin the fleet env deterministically regardless of the outer shell.
    monkeypatch.setenv("SENTINEL_ENV", "staging")
    return os.environ["SENTINEL_GATEWAY_ARN"]


class _FakeControl:
    """In-memory stand-in for the bedrock-agentcore-control client.

    Records created harnesses (with tags) and can be pre-seeded with 'existing'
    ones so idempotency + the tag-guard are exercisable without AWS. Every method
    raises if a test forgot to allow it, so an accidental real path is loud."""

    def __init__(self, existing=None):
        self._store: dict[str, dict] = {}
        self.create_calls: list[dict] = []
        self.deleted: list[str] = []
        for h in existing or []:
            self._store[h["harnessName"]] = h

    def list_harnesses(self):
        return {"harnesses": list(self._store.values())}

    def create_harness(self, **kwargs):
        self.create_calls.append(kwargs)
        name = kwargs["harnessName"]
        hid = f"hid-{name}"
        rec = {
            "harnessName": name,
            "harnessId": hid,
            "arn": f"arn:aws:bedrock-agentcore:us-east-1:000000000000:harness/{hid}",
            "status": "CREATING",
            "tags": kwargs.get("tags", {}),
        }
        self._store[name] = rec
        return {"harness": rec}

    def delete_harness(self, **kwargs):
        hid = kwargs["harnessId"]
        for name, rec in list(self._store.items()):
            if rec["harnessId"] == hid:
                self.deleted.append(name)
                del self._store[name]
                return {}
        raise AssertionError(f"delete of unknown harnessId {hid}")


class _ExplodingControl:
    """Any attribute access blows up — used to prove dry_run makes NO AWS calls."""

    def __getattr__(self, item):
        raise AssertionError(f"dry_run must not touch AWS, but called _control.{item}")


@pytest.fixture()
def fake_control(monkeypatch):
    """Install a fresh in-memory control client and pin the exec-role env."""
    ctrl = _FakeControl()
    monkeypatch.setattr(sh, "_control", ctrl)
    monkeypatch.setattr(sh, "EXECUTION_ROLE_ARN", os.environ["SENTINEL_EXECUTION_ROLE_ARN"])
    return ctrl


def _manifest_two() -> dict:
    return {
        "tags": {"team": "secops"},
        "harnesses": [
            {"config": _yaml("alert-triage")},
            {"config": _yaml("detection-eng"), "tags": {"tier": "critical"}},
        ],
    }


# --------------------------------------------------------------------------- #
# dry_run: validates every config, ZERO AWS calls.                            #
# --------------------------------------------------------------------------- #
def test_dry_run_validates_all_configs_without_aws(gateway_env, monkeypatch):
    monkeypatch.setattr(sh, "_control", _ExplodingControl())
    results = factory.provision_fleet(_manifest_two(), dry_run=True)
    assert [r["action"] for r in results] == ["would_create", "would_create"]
    names = {r["name"] for r in results}
    assert names == {"sentinel_alert_triage", "sentinel_detection_eng"}
    # No harnessId is invented on dry_run.
    assert all("harnessId" not in r for r in results)


def test_dry_run_surfaces_missing_env_var(monkeypatch):
    """A ${ENV} the loader cannot expand must fail loudly even on dry_run."""
    monkeypatch.delenv("SENTINEL_GATEWAY_ARN", raising=False)
    monkeypatch.setattr(sh, "_control", _ExplodingControl())
    with pytest.raises(KeyError, match="SENTINEL_GATEWAY_ARN"):
        factory.provision_fleet(_manifest_two(), dry_run=True)


# --------------------------------------------------------------------------- #
# provisioning: create, env tag stamped, idempotent skip.                     #
# --------------------------------------------------------------------------- #
def test_provision_creates_and_stamps_env_tag(gateway_env, fake_control):
    results = factory.provision_fleet(_manifest_two())
    assert [r["action"] for r in results] == ["created", "created"]
    assert all(r["harnessId"] for r in results)
    assert len(fake_control.create_calls) == 2

    # Every created harness carries the sentinel:env tag == the fleet env (staging).
    for call in fake_control.create_calls:
        assert call["tags"][factory.ENV_TAG_KEY] == "staging"
        assert call["tags"]["team"] == "secops"          # fleet-wide tag merged in
    # Per-entry tag overrides land only on the entry that declared it.
    det = [c for c in fake_control.create_calls if c["harnessName"] == "sentinel_detection_eng"][0]
    assert det["tags"]["tier"] == "critical"


def test_provision_is_idempotent(gateway_env, fake_control):
    factory.provision_fleet(_manifest_two())
    n_after_first = len(fake_control.create_calls)
    # Second run: everything already exists -> all 'exists', no new create calls.
    results = factory.provision_fleet(_manifest_two())
    assert [r["action"] for r in results] == ["exists", "exists"]
    assert len(fake_control.create_calls) == n_after_first
    assert all(r["harnessId"] for r in results)


# --------------------------------------------------------------------------- #
# tag-guard: cross-env existing harness blocks the fleet.                     #
# --------------------------------------------------------------------------- #
def test_tag_guard_blocks_cross_env(gateway_env, monkeypatch):
    # A prod harness already owns the name; our fleet env is 'staging'.
    existing = [{
        "harnessName": "sentinel_alert_triage",
        "harnessId": "hid-prod",
        "tags": {factory.ENV_TAG_KEY: "prod"},
    }]
    ctrl = _FakeControl(existing=existing)
    monkeypatch.setattr(sh, "_control", ctrl)
    monkeypatch.setattr(sh, "EXECUTION_ROLE_ARN", os.environ["SENTINEL_EXECUTION_ROLE_ARN"])

    with pytest.raises(factory.FactoryError, match="cross-env tag-guard"):
        factory.provision_fleet(_manifest_two())
    # Guard fires before any create.
    assert ctrl.create_calls == []


def test_same_env_existing_is_not_guarded(gateway_env, monkeypatch):
    """A same-name harness already under the SAME env is a normal idempotent skip."""
    existing = [{
        "harnessName": "sentinel_alert_triage",
        "harnessId": "hid-staging",
        "tags": {factory.ENV_TAG_KEY: "staging"},
    }]
    ctrl = _FakeControl(existing=existing)
    monkeypatch.setattr(sh, "_control", ctrl)
    monkeypatch.setattr(sh, "EXECUTION_ROLE_ARN", os.environ["SENTINEL_EXECUTION_ROLE_ARN"])

    results = factory.provision_fleet(_manifest_two())
    by_name = {r["name"]: r for r in results}
    assert by_name["sentinel_alert_triage"]["action"] == "exists"
    assert by_name["sentinel_detection_eng"]["action"] == "created"


# --------------------------------------------------------------------------- #
# bad manifests fail loudly.                                                   #
# --------------------------------------------------------------------------- #
def test_missing_harnesses_key_fails_loud(fake_control):
    with pytest.raises(factory.FactoryError, match="harnesses"):
        factory.provision_fleet({"env": "dev"}, dry_run=True)


def test_bad_manifest_type_fails_loud(fake_control):
    with pytest.raises(factory.FactoryError, match="manifest must be"):
        factory.provision_fleet(42, dry_run=True)


def test_inline_entry_requires_name_and_prompt(fake_control):
    manifest = {"harnesses": [{"system_prompt": "hi"}]}  # missing name
    with pytest.raises(factory.FactoryError, match="name.*system_prompt|needs both"):
        factory.provision_fleet(manifest, dry_run=True)


def test_invalid_harness_name_fails_loud(fake_control):
    manifest = {"harnesses": [{"name": "bad-name-has-hyphens", "system_prompt": "hi"}]}
    with pytest.raises(factory.FactoryError, match="invalid harnessName"):
        factory.provision_fleet(manifest, dry_run=True)


def test_duplicate_name_in_manifest_fails_loud(gateway_env, fake_control):
    manifest = {"harnesses": [{"config": _yaml("alert-triage")}, {"config": _yaml("alert-triage")}]}
    with pytest.raises(factory.FactoryError, match="duplicate"):
        factory.provision_fleet(manifest, dry_run=True)


# --------------------------------------------------------------------------- #
# inline entry provisions with env tag (no yaml needed).                      #
# --------------------------------------------------------------------------- #
def test_inline_entry_provisions(fake_control, monkeypatch):
    monkeypatch.setenv("SENTINEL_ENV", "test")
    manifest = {
        "harnesses": [{
            "name": "adhoc_probe",
            "system_prompt": "You are a probe.",
            "model": {"bedrockModelConfig": {"modelId": "global.anthropic.claude-haiku-4-5"}},
        }],
    }
    results = factory.provision_fleet(manifest)
    assert results[0]["action"] == "created"
    call = fake_control.create_calls[0]
    assert call["harnessName"] == "adhoc_probe"
    assert call["tags"][factory.ENV_TAG_KEY] == "test"
    # 'tags' is factory-only sugar and must not leak into create_harness kwargs body
    # beyond the assembled tags dict — system prompt normalized by core.
    assert call["systemPrompt"] == [{"text": "You are a probe."}]


# --------------------------------------------------------------------------- #
# teardown.                                                                    #
# --------------------------------------------------------------------------- #
def test_teardown_by_manifest_deletes_only_wanted(gateway_env, fake_control):
    factory.provision_fleet(_manifest_two())
    # Seed an unrelated harness that shares no manifest entry.
    fake_control.create_harness(harnessName="sentinel_unrelated", systemPrompt=[{"text": "x"}])
    deleted = factory.teardown_fleet(_manifest_two())
    assert set(deleted) == {"sentinel_alert_triage", "sentinel_detection_eng"}
    # The unrelated harness is untouched.
    remaining = {h["harnessName"] for h in fake_control.list_harnesses()["harnesses"]}
    assert remaining == {"sentinel_unrelated"}


def test_teardown_by_prefix_delegates_to_cleanup(fake_control):
    fake_control.create_harness(harnessName="sentinel_a", systemPrompt=[{"text": "x"}])
    fake_control.create_harness(harnessName="sentinel_b", systemPrompt=[{"text": "x"}])
    fake_control.create_harness(harnessName="other_c", systemPrompt=[{"text": "x"}])
    deleted = factory.teardown_fleet("sentinel_")
    assert set(deleted) == {"sentinel_a", "sentinel_b"}
    remaining = {h["harnessName"] for h in fake_control.list_harnesses()["harnesses"]}
    assert remaining == {"other_c"}
