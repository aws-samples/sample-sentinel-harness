"""
Offline tests for the ops_query multi-account operations tool
=============================================================
Dedicated tests for ``tools/ops_query/handler.py`` — the deterministic, OFFLINE
multi-account ops-query tool the ops-automation supervisor consumes. ZERO AWS,
ZERO network, no real sleep. The handler is deterministic by design, so the
offline paths need no mocking; only the live (``OPS_QUERY_LIVE=1``) branch is
steered via env / monkeypatch, and even then it performs no I/O (the live
client is a stub that raises).

This file is a good citizen about ``sys.modules``: the tool ships a module
literally named ``handler`` (as do sibling tools), so importing it by bare name
would collide when the whole suite runs. We load it from an explicit file path
under a UNIQUE module name and NEVER register the bare ``handler`` name —
mirroring tests/test_asset_lookup.py — so this file cannot poison any other tool
test regardless of collection order. We also put REPO_ROOT on sys.path so the
handler's ``from mockdata.accounts import ...`` resolves.
"""
from __future__ import annotations

import importlib.util
import os
import runpy
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OPS_TOOL_DIR = os.path.join(REPO_ROOT, "tools", "ops_query")
HANDLER_PATH = os.path.join(OPS_TOOL_DIR, "handler.py")

# The handler does ``from mockdata.accounts import ...`` — make the repo root
# importable so that resolves regardless of pytest's rootdir.
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)


def _load_module(unique_name: str, path: str):
    """Import a standalone .py file under a unique name without polluting the
    bare module namespace shared by sibling tools."""
    spec = importlib.util.spec_from_file_location(unique_name, path)
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[unique_name] = module
    spec.loader.exec_module(module)
    return module


ops_handler = _load_module("ops_query_handler_dedicated", HANDLER_PATH)

# Ground-truth from the fictional inventory, so assertions stay in lockstep with
# the data file rather than hardcoding a copy of it.
from mockdata.accounts import accounts as _accounts  # noqa: E402
from mockdata.accounts import finding_types as _finding_types  # noqa: E402

_ALL_IDS = {a["account_id"] for a in _accounts()}


# --------------------------------------------------------------------------- #
# Wildcard estate query                                                       #
# --------------------------------------------------------------------------- #
def test_wildcard_returns_full_estate():
    res = ops_handler.handler({"query": "*"}, None)
    assert res["ok"] is True
    assert res["source"] == "stub"
    ids = {a["account_id"] for a in res["accounts"]}
    assert ids == _ALL_IDS
    # Fictional demo ids present and clearly-fake (repeated digits).
    assert "111111111111" in ids and "444444444444" in ids


def test_wildcard_accounts_carry_expected_shape():
    res = ops_handler.handler({"query": "*"}, None)
    for acct in res["accounts"]:
        assert set(acct) == {
            "account_id", "name", "environment", "region", "resources", "findings"
        }
        assert set(acct["resources"]) == {"ec2", "s3_buckets", "iam_roles"}
        assert isinstance(acct["findings"], list)


def test_wildcard_estate_has_the_clean_negative_case():
    """security-audit (444444444444) is deliberately clean — the agent must not
    fabricate findings for it."""
    res = ops_handler.handler({"query": "*"}, None)
    by_id = {a["account_id"]: a for a in res["accounts"]}
    assert by_id["444444444444"]["findings"] == []


# --------------------------------------------------------------------------- #
# Single-account query                                                        #
# --------------------------------------------------------------------------- #
def test_single_account_returns_only_that_account():
    res = ops_handler.handler({"account": "111111111111"}, None)
    assert res["ok"] is True and res["source"] == "stub"
    assert len(res["accounts"]) == 1
    acct = res["accounts"][0]
    assert acct["account_id"] == "111111111111"
    assert acct["environment"] == "prod"
    # prod-payments carries the two headline high-severity findings.
    ftypes = {f["finding_type"] for f in acct["findings"]}
    assert ftypes == {"public_s3", "over_permissive_role"}


def test_unknown_but_wellformed_account_matches_nothing():
    """A 12-digit id not in the inventory is not an error — it matches nothing."""
    res = ops_handler.handler({"account": "999999999999"}, None)
    assert res["ok"] is True and res["source"] == "stub"
    assert res["accounts"] == []


# --------------------------------------------------------------------------- #
# finding_type filter                                                         #
# --------------------------------------------------------------------------- #
def test_finding_type_public_s3_is_account_tagged():
    res = ops_handler.handler({"finding_type": "public_s3"}, None)
    assert res["ok"] is True and res["source"] == "stub"
    assert res["finding_type"] == "public_s3"
    assert len(res["findings"]) == 1
    f = res["findings"][0]
    # Each finding is tagged with its owning account for one-shot ticketing.
    assert f["account_id"] == "111111111111"
    assert f["account_name"] == "prod-payments (fictional)"
    assert f["finding_type"] == "public_s3"
    assert f["severity"] == "high"


def test_finding_type_sweeps_across_all_accounts():
    """Every known finding_type resolves to at least one tagged finding, and the
    counts match the inventory exactly (no over/under reporting)."""
    for ftype in _finding_types():
        res = ops_handler.handler({"finding_type": ftype}, None)
        assert res["ok"] is True
        expected = sum(
            1
            for a in _accounts()
            for f in a["findings"]
            if f["finding_type"] == ftype
        )
        assert len(res["findings"]) == expected
        assert all(f["finding_type"] == ftype for f in res["findings"])
        assert all("account_id" in f for f in res["findings"])


# --------------------------------------------------------------------------- #
# Input validation errors                                                     #
# --------------------------------------------------------------------------- #
def test_missing_selector_is_validation_error():
    res = ops_handler.handler({}, None)
    assert res["ok"] is False and res["error"] == "validation_error"
    assert "missing selector" in res["message"]


def test_ambiguous_multiple_selectors_is_validation_error():
    res = ops_handler.handler({"query": "*", "account": "111111111111"}, None)
    assert res["ok"] is False and res["error"] == "validation_error"
    assert "ambiguous" in res["message"]


@pytest.mark.parametrize("bad", ["", "   ", "\t"])
def test_blank_selector_value_is_validation_error(bad):
    res = ops_handler.handler({"account": bad}, None)
    assert res["ok"] is False and res["error"] == "validation_error"


@pytest.mark.parametrize("bad", [123, None, ["*"], {"q": 1}])
def test_non_string_selector_value_is_validation_error(bad):
    res = ops_handler.handler({"query": bad}, None)
    assert res["ok"] is False and res["error"] == "validation_error"


def test_non_dict_event_is_validation_error():
    res = ops_handler.handler("not-a-dict", None)  # type: ignore[arg-type]
    assert res["ok"] is False and res["error"] == "validation_error"


def test_query_only_supports_wildcard():
    res = ops_handler.handler({"query": "111111111111"}, None)
    assert res["ok"] is False and res["error"] == "validation_error"
    assert "wildcard" in res["message"]


@pytest.mark.parametrize("bad", ["11111", "11111111111a", "1111111111111"])
def test_malformed_account_id_is_validation_error(bad):
    res = ops_handler.handler({"account": bad}, None)
    assert res["ok"] is False and res["error"] == "validation_error"
    assert "invalid account id" in res["message"]


def test_unknown_finding_type_is_validation_error():
    res = ops_handler.handler({"finding_type": "no_such_type"}, None)
    assert res["ok"] is False and res["error"] == "validation_error"
    assert "unknown finding_type" in res["message"]


def test_over_long_selector_value_is_validation_error():
    too_long = "1" * (ops_handler._MAX_QUERY_LEN + 1)
    res = ops_handler.handler({"account": too_long}, None)
    assert res["ok"] is False and res["error"] == "validation_error"
    assert "too long" in res["message"]


# --------------------------------------------------------------------------- #
# Determinism + copy safety                                                   #
# --------------------------------------------------------------------------- #
def test_offline_query_is_deterministic():
    a = ops_handler.handler({"query": "*"}, None)
    b = ops_handler.handler({"query": "*"}, None)
    assert a == b


def test_result_mutation_does_not_corrupt_shared_source():
    a = ops_handler.handler({"query": "*"}, None)
    a["accounts"][0]["findings"].append({"finding_type": "TAMPERED"})
    a["accounts"][0]["name"] = "TAMPERED"
    b = ops_handler.handler({"query": "*"}, None)
    assert all(acct["name"] != "TAMPERED" for acct in b["accounts"])
    assert all(
        f["finding_type"] != "TAMPERED"
        for acct in b["accounts"]
        for f in acct["findings"]
    )


# --------------------------------------------------------------------------- #
# Live (OPS_QUERY_LIVE) branch behavior — still ZERO network                  #
# --------------------------------------------------------------------------- #
def test_default_is_offline_stub_no_network(monkeypatch):
    monkeypatch.delenv("OPS_QUERY_LIVE", raising=False)

    def _boom(sel):  # pragma: no cover - must never be called offline
        raise AssertionError("live backend must not be reached in offline mode")

    monkeypatch.setattr(ops_handler, "_fetch_live", _boom)
    res = ops_handler.handler({"query": "*"}, None)
    assert res["ok"] is True and res["source"] == "stub"


@pytest.mark.parametrize("val", ["0", "true", "yes", "", "01"])
def test_live_flag_only_activates_on_exact_1(monkeypatch, val):
    monkeypatch.setenv("OPS_QUERY_LIVE", val)
    monkeypatch.setattr(
        ops_handler,
        "_fetch_live",
        lambda s: (_ for _ in ()).throw(AssertionError("should stay offline")),
    )
    res = ops_handler.handler({"query": "*"}, None)
    assert res["source"] == "stub"


def test_live_without_backend_url_surfaces_upstream_error(monkeypatch):
    monkeypatch.setenv("OPS_QUERY_LIVE", "1")
    monkeypatch.delenv("OPS_QUERY_URL", raising=False)
    res = ops_handler.handler({"query": "*"}, None)
    assert res["ok"] is False and res["error"] == "upstream_error"
    assert "OPS_QUERY_URL is not set" in res["message"]


def test_live_with_unreachable_backend_surfaces_upstream_error(monkeypatch):
    """The live path is now a REAL urllib client. Pointing it at a refused
    local port (ZERO external network) must surface upstream_error, never crash
    and never fall back to the offline fixtures. Full request-shape / response-
    parsing coverage lives in tests/test_ops_query_live.py against an in-process
    mock http.server."""
    monkeypatch.setenv("OPS_QUERY_LIVE", "1")
    # 127.0.0.1:1 — a privileged port nothing listens on → connection refused.
    monkeypatch.setenv("OPS_QUERY_URL", "http://127.0.0.1:1/api")
    monkeypatch.delenv("OPS_QUERY_TOKEN", raising=False)
    res = ops_handler.handler({"query": "*"}, None)
    assert res["ok"] is False and res["error"] == "upstream_error"


def test_fetch_live_without_url_raises_runtime_error(monkeypatch):
    monkeypatch.delenv("OPS_QUERY_URL", raising=False)
    with pytest.raises(RuntimeError, match="OPS_QUERY_URL is not set"):
        ops_handler._fetch_live({"query": "*"})


def test_fetch_live_with_unreachable_backend_raises_runtime_error(monkeypatch):
    """Directly exercise the transport-failure branch of the real client: a
    refused local port raises RuntimeError (ZERO external network)."""
    monkeypatch.setenv("OPS_QUERY_URL", "http://127.0.0.1:1/api")
    monkeypatch.delenv("OPS_QUERY_TOKEN", raising=False)
    with pytest.raises(RuntimeError, match="request failed"):
        ops_handler._fetch_live({"query": "*"})


def test_live_success_path_sets_source_live(monkeypatch):
    """When a live client IS wired (future), the handler wraps its payload with
    source='live'. We stub _fetch_live to return a payload — still ZERO network."""
    monkeypatch.setenv("OPS_QUERY_LIVE", "1")
    fake = {"accounts": []}
    monkeypatch.setattr(ops_handler, "_fetch_live", lambda s: fake)
    res = ops_handler.handler({"query": "*"}, None)
    assert res["ok"] is True and res["source"] == "live"
    assert res["accounts"] == []


# --------------------------------------------------------------------------- #
# __main__ entrypoint                                                         #
# --------------------------------------------------------------------------- #
def test_main_entrypoint_prints_estate(capsys, monkeypatch):
    import json

    monkeypatch.delenv("OPS_QUERY_LIVE", raising=False)
    runpy.run_path(HANDLER_PATH, run_name="__main__")
    out = capsys.readouterr().out
    parsed = json.loads(out)
    assert parsed["ok"] is True and parsed["source"] == "stub"
    assert {a["account_id"] for a in parsed["accounts"]} == _ALL_IDS


# --------------------------------------------------------------------------- #
# House rule: no hardcoded secrets, and account ids never in arn:/iam:: ctx   #
# --------------------------------------------------------------------------- #
def test_source_has_no_secrets_and_no_account_id_in_arn_context():
    import re

    src = open(HANDLER_PATH, encoding="utf-8").read()
    assert "sk-" not in src and "ghp_" not in src
    # No 12-digit id sits inside an arn:/iam:: context in the source.
    for m in re.finditer(r"(arn:[^\s\"']*|iam::)(\d{12})", src):
        raise AssertionError(f"account id in arn/iam context: {m.group(0)!r}")
