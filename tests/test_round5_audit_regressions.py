"""
Regression tests for the round-5 adversarial-audit fixes.
================================================================================
Round-5 audited the still-not-deep-audited modules (core invoke loop, loader,
factory, cli, mockdata). Of 22 findings, 7 survived independent skeptic
verification; this file pins each so it cannot silently regress:

  * cli / core (HIGH) — ``sentinel cleanup ""`` (or an unset ``$PREFIX``) matched
    EVERY harness (``"".startswith("")`` is True) and cascade-deleted managed
    memory. Now refused at BOTH layers (defense in depth) + a ``--dry-run``.
  * core (MED) — parallel HITL gates were captured but not resumable; the singular
    resume answered only one. New ``invoke_with_tool_results`` answers all in the
    one required message pair; the singular delegates to it.
  * factory (MED) — teardown deleted an UNTAGGED same-name prior (a pre-tagging
    prod harness) because the env-guard only fired on tagged priors. Now refused.
  * loader (LOW x2) — ``harnessName`` accepted a non-string/hyphenated value;
    ``allowedTools`` accepted non-string elements (nested list/dict/None) that
    silently failed HITL-gate wiring. Both now validated.
  * factory (LOW) — the documented ``name_prefix`` manifest key was a silent no-op;
    now a real governance guard.
  * mockdata (LOW) — dead ``_HOST_IDS`` / ``_IOC_BY_VALUE`` sets whose comments
    claimed a reference-integrity guard that did not exist; now a live import-time
    assertion.

HARD RULE: ZERO network, ZERO tokens, ZERO AWS — pure Python / monkeypatched.
"""
from __future__ import annotations

import os

import pytest

# --- Hermetic import: no real region/profile/credentials resolution. ---
os.environ.setdefault("SENTINEL_REGION", "us-east-1")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault(
    "SENTINEL_EXECUTION_ROLE_ARN", "arn:aws:iam::000000000000:role/test-harness-role"
)
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")

from sentinel_harness import core as sh  # noqa: E402
from sentinel_harness import factory as fac  # noqa: E402
from sentinel_harness import loader  # noqa: E402


# --------------------------------------------------------------------------- #
# #1 (HIGH) — cleanup empty-prefix guard (core + cli, defense in depth)        #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("bad", ["", "   ", "\t"])
def test_core_cleanup_refuses_empty_prefix(bad, monkeypatch):
    # Must refuse BEFORE listing/deleting anything.
    def _boom():
        raise AssertionError("cleanup must not enumerate harnesses on an empty prefix")

    monkeypatch.setattr(sh, "_all_harnesses", _boom)
    with pytest.raises(ValueError, match="empty"):
        sh.cleanup(bad)


def test_core_cleanup_still_works_with_real_prefix(monkeypatch):
    harnesses = [{"harnessName": "sentinel_a", "harnessId": "h1"},
                 {"harnessName": "other_b", "harnessId": "h2"}]
    monkeypatch.setattr(sh, "_all_harnesses", lambda: harnesses)
    deleted_ids = []
    monkeypatch.setattr(sh, "delete_harness", lambda hid, **kw: deleted_ids.append(hid))
    out = sh.cleanup("sentinel_")
    assert out == ["sentinel_a"] and deleted_ids == ["h1"]


def test_cli_cleanup_empty_prefix_exits_2_without_deleting(monkeypatch, capsys):
    from sentinel_harness import cli
    monkeypatch.setattr(cli.sh, "cleanup", lambda *a, **k: (_ for _ in ()).throw(
        AssertionError("cli must not call cleanup on empty prefix")))
    args = type("A", (), {"prefix": "", "dry_run": False})()
    rc = cli.cmd_cleanup(args)
    assert rc == 2
    assert "empty prefix" in capsys.readouterr().err.lower()


def test_cli_cleanup_dry_run_deletes_nothing(monkeypatch, capsys):
    from sentinel_harness import cli
    monkeypatch.setattr(cli.sh, "list_harnesses",
                        lambda: [{"harnessName": "sentinel_a"}, {"harnessName": "other_b"}])
    monkeypatch.setattr(cli.sh, "cleanup", lambda *a, **k: (_ for _ in ()).throw(
        AssertionError("dry-run must not delete")))
    args = type("A", (), {"prefix": "sentinel_", "dry_run": True})()
    rc = cli.cmd_cleanup(args)
    out = capsys.readouterr().out
    assert rc == 0 and "dry-run" in out and "sentinel_a" in out and "other_b" not in out


# --------------------------------------------------------------------------- #
# #2 (MED) — parallel HITL gates are all resumable                            #
# --------------------------------------------------------------------------- #
class _CaptureData:
    def __init__(self):
        self.calls = []

    def invoke_harness(self, **kwargs):
        self.calls.append(kwargs)
        return {"stream": iter(())}  # empty stream → benign drained result


def test_invoke_with_tool_results_answers_all_parallel_gates(monkeypatch):
    data = _CaptureData()
    monkeypatch.setattr(sh, "_data", data)
    tu1 = {"toolUseId": "tu1", "name": "gateA", "input": {"x": 1}}
    tu2 = {"toolUseId": "tu2", "name": "gateB", "input": {"y": 2}}
    sh.invoke_with_tool_results(
        "arn:aws:...:harness/h", "sess-" + "a" * 30,
        [(tu1, {"decision": "approve"}), (tu2, {"decision": "deny"}, "success")],
    )
    msgs = data.calls[0]["messages"]
    # exactly two messages: one assistant with BOTH toolUse blocks, one user with BOTH results
    assert [m["role"] for m in msgs] == ["assistant", "user"]
    tu_ids = [b["toolUse"]["toolUseId"] for b in msgs[0]["content"]]
    tr_ids = [b["toolResult"]["toolUseId"] for b in msgs[1]["content"]]
    assert tu_ids == ["tu1", "tu2"] and tr_ids == ["tu1", "tu2"]


def test_singular_resume_delegates_to_plural(monkeypatch):
    data = _CaptureData()
    monkeypatch.setattr(sh, "_data", data)
    tu = {"toolUseId": "tu1", "name": "gate", "input": {}}
    sh.invoke_with_tool_result("arn", "sess-" + "b" * 30, tu, {"ok": True})
    msgs = data.calls[0]["messages"]
    assert len(msgs) == 2
    assert msgs[0]["content"][0]["toolUse"]["toolUseId"] == "tu1"
    assert msgs[1]["content"][0]["toolResult"]["toolUseId"] == "tu1"


def test_invoke_with_tool_results_rejects_empty():
    with pytest.raises(ValueError, match="at least one"):
        sh.invoke_with_tool_results("arn", "sess-x", [])


def test_plural_helper_is_exported():
    import sentinel_harness
    assert hasattr(sentinel_harness, "invoke_with_tool_results")


# --------------------------------------------------------------------------- #
# #3 (MED) — factory teardown refuses an untagged same-name prior             #
# --------------------------------------------------------------------------- #
def _tag_env(env):
    return {fac.ENV_TAG_KEY: env}


def test_teardown_refuses_untagged_prior(monkeypatch):
    env = fac._fleet_env({})  # resolves to the ambient SENTINEL_ENV or "dev"
    manifest = {"harnesses": [{"config": "x"}]}
    # resolve to one entry named 'sentinel_a'; skip real YAML loading.
    monkeypatch.setattr(fac, "_resolve_fleet",
                        lambda m: ([{"name": "sentinel_a", "kwargs": {}, "tags": _tag_env(env)}], env))
    # existing prior with NO env tag
    monkeypatch.setattr(fac, "_index_existing",
                        lambda: {"sentinel_a": {"harnessName": "sentinel_a", "harnessId": "h1", "tags": {}}})
    monkeypatch.setattr(fac.core, "delete_harness",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not delete untagged")))
    with pytest.raises(fac.FactoryError, match="untagged"):
        fac.teardown_fleet(manifest)


def test_teardown_deletes_matching_env_prior(monkeypatch):
    env = fac._fleet_env({})
    manifest = {"harnesses": [{"config": "x"}]}
    monkeypatch.setattr(fac, "_resolve_fleet",
                        lambda m: ([{"name": "sentinel_a", "kwargs": {}, "tags": _tag_env(env)}], env))
    monkeypatch.setattr(fac, "_index_existing",
                        lambda: {"sentinel_a": {"harnessName": "sentinel_a", "harnessId": "h1",
                                                "tags": _tag_env(env)}})
    deleted = []
    monkeypatch.setattr(fac.core, "delete_harness", lambda hid, **k: deleted.append(hid))
    out = fac.teardown_fleet(manifest)
    assert out == ["sentinel_a"] and deleted == ["h1"]


# --------------------------------------------------------------------------- #
# #4 (LOW) — loader harnessName validation                                    #
# --------------------------------------------------------------------------- #
def _write_harness(tmp_path, name_line: str, extra: str = "") -> str:
    (tmp_path / "sp.md").write_text("You are a test agent.\n")
    (tmp_path / "harness.yaml").write_text(f"{name_line}\nsystemPrompt: sp.md\n{extra}")
    return str(tmp_path / "harness.yaml")


def test_loader_rejects_hyphenated_name(tmp_path):
    path = _write_harness(tmp_path, "harnessName: sentinel-detection")
    with pytest.raises(ValueError, match="invalid harnessName"):
        loader.load_harness_config(path)


def test_loader_rejects_non_string_name(tmp_path):
    path = _write_harness(tmp_path, "harnessName: 123")
    with pytest.raises(ValueError, match="invalid harnessName"):
        loader.load_harness_config(path)


def test_loader_accepts_valid_name(tmp_path):
    path = _write_harness(tmp_path, "harnessName: sentinel_detection_01")
    kwargs = loader.load_harness_config(path)
    assert kwargs["name"] == "sentinel_detection_01"


# --------------------------------------------------------------------------- #
# #5 (LOW) — loader allowedTools per-item type check                          #
# --------------------------------------------------------------------------- #
def test_loader_rejects_nonstring_allowed_tool(tmp_path):
    path = _write_harness(
        tmp_path, "harnessName: t_at",
        "allowedTools:\n  - request_approval\n  - [nested]\n",
    )
    with pytest.raises(ValueError, match="allowedTools"):
        loader.load_harness_config(path)


def test_loader_rejects_empty_string_allowed_tool(tmp_path):
    path = _write_harness(
        tmp_path, "harnessName: t_at2",
        "allowedTools:\n  - request_approval\n  - ''\n",
    )
    with pytest.raises(ValueError, match="allowedTools"):
        loader.load_harness_config(path)


# --------------------------------------------------------------------------- #
# #6 (LOW) — factory name_prefix is a real governance guard                   #
# --------------------------------------------------------------------------- #
def test_name_prefix_guard_rejects_nonconforming_name():
    manifest = {"name_prefix": "sentinel_", "env": "dev",
                "harnesses": [{"config": "x"}]}
    # a resolved entry whose name does not start with the prefix
    import sentinel_harness.factory as f

    orig = f._resolve_entry
    try:
        f._resolve_entry = lambda e, ft, env, i: {"name": "other_a", "kwargs": {}, "tags": {}}
        with pytest.raises(f.FactoryError, match="name_prefix"):
            f._resolve_fleet(manifest)
    finally:
        f._resolve_entry = orig


def test_name_prefix_guard_passes_conforming_names():
    manifest = {"name_prefix": "sentinel_", "env": "dev",
                "harnesses": [{"config": "x"}]}
    import sentinel_harness.factory as f

    orig = f._resolve_entry
    try:
        f._resolve_entry = lambda e, ft, env, i: {"name": "sentinel_a", "kwargs": {}, "tags": {}}
        resolved, env = f._resolve_fleet(manifest)
        assert resolved[0]["name"] == "sentinel_a" and env == "dev"
    finally:
        f._resolve_entry = orig


def test_name_prefix_rejects_empty_string():
    manifest = {"name_prefix": "  ", "harnesses": [{"config": "x"}]}
    import sentinel_harness.factory as f

    orig = f._resolve_entry
    try:
        f._resolve_entry = lambda e, ft, env, i: {"name": "sentinel_a", "kwargs": {}, "tags": {}}
        with pytest.raises(f.FactoryError, match="name_prefix"):
            f._resolve_fleet(manifest)
    finally:
        f._resolve_entry = orig


# --------------------------------------------------------------------------- #
# #7 (LOW) — mockdata reference-integrity guard is live                       #
# --------------------------------------------------------------------------- #
def test_mockdata_world_integrity_guard_passes_on_shipped_world():
    import mockdata.world as w
    # importing already ran the guard; call it again explicitly to pin it exists.
    w._assert_reference_integrity()  # must not raise


def test_mockdata_guard_catches_dangling_host():
    import mockdata.world as w
    w._ALERTS.append({"alert_id": "bad-x", "host": "ghost-99", "src_ip": None})
    try:
        with pytest.raises(ValueError, match="unknown host"):
            w._assert_reference_integrity()
    finally:
        w._ALERTS.pop()


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
