"""
Offline tests for the create_ticket ticketing WRITE tool
========================================================
Dedicated tests for ``tools/create_ticket/handler.py`` — the deterministic,
OFFLINE, side-effect-free ticketing mock that terminates the alert-triage flow.
ZERO AWS, ZERO network, no real sleep, no wall-clock dependence. The handler is
deterministic by design, so the offline paths need no mocking; only the live
(``CREATE_TICKET_LIVE=1``) branch is steered via env, and even then it performs
no I/O (the live client is a HITL-gated stub that raises).

Like the sibling tool tests, this file is a good ``sys.modules`` citizen: the
tool ships a module literally named ``handler``, so importing it by bare name
would collide when the whole suite runs. We load it from an explicit file path
under a UNIQUE module name and NEVER register the bare ``handler`` name.
"""
from __future__ import annotations

import importlib.util
import os
import runpy
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOL_DIR = os.path.join(REPO_ROOT, "tools", "create_ticket")
HANDLER_PATH = os.path.join(TOOL_DIR, "handler.py")


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


create_ticket = _load_module("create_ticket_handler_dedicated", HANDLER_PATH)


def _valid_event() -> dict:
    return {
        "title": "Log4Shell exploitation attempt against web-01",
        "severity": "critical",
        "description": "Inbound JNDI payload matched CVE-2021-44228 against web-01.",
        "assignee": "secops",
        "related_alert_id": "alert-1001",
        "related_host": "web-01",
    }


# --------------------------------------------------------------------------- #
# Happy path: a valid ticket gets an id + open status + echoed fields         #
# --------------------------------------------------------------------------- #
def test_valid_ticket_returns_id_status_open_and_echoes_fields():
    res = create_ticket.handler(_valid_event(), None)
    assert res["ok"] is True
    assert res["source"] == "stub"
    ticket = res["ticket"]

    # An id was assigned, with the SEC- prefix mirroring the mock world.
    assert isinstance(ticket["ticket_id"], str)
    assert ticket["ticket_id"].startswith("SEC-")
    # Freshly created tickets are open.
    assert ticket["status"] == "open"
    # created_ts is present and deterministic (not wall clock).
    assert isinstance(ticket["created_ts"], str) and ticket["created_ts"]

    # The finding fields are echoed back unchanged.
    assert ticket["title"] == _valid_event()["title"]
    assert ticket["severity"] == "critical"
    assert ticket["description"] == _valid_event()["description"]
    assert ticket["assignee"] == "secops"


def test_minimal_valid_ticket_optional_fields_default_to_none():
    res = create_ticket.handler(
        {
            "title": "Suspicious binary on app-01",
            "severity": "medium",
            "description": "EDR flagged an unsigned binary spawning a shell.",
        },
        None,
    )
    assert res["ok"] is True
    ticket = res["ticket"]
    assert ticket["status"] == "open"
    assert ticket["assignee"] is None
    assert ticket["related_alert_id"] is None
    assert ticket["related_host"] is None


# --------------------------------------------------------------------------- #
# related_alert_id / related_host pass through onto the ticket                #
# --------------------------------------------------------------------------- #
def test_related_alert_and_host_pass_through():
    res = create_ticket.handler(_valid_event(), None)
    ticket = res["ticket"]
    # These link the ticket back to the alert->asset chain in mockdata/world.py.
    assert ticket["related_alert_id"] == "alert-1001"
    assert ticket["related_host"] == "web-01"


# --------------------------------------------------------------------------- #
# Severity validation: enum enforced, case-normalized                         #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("sev", ["low", "medium", "high", "critical"])
def test_all_valid_severities_accepted(sev):
    ev = _valid_event()
    ev["severity"] = sev
    res = create_ticket.handler(ev, None)
    assert res["ok"] is True
    assert res["ticket"]["severity"] == sev


def test_severity_is_case_insensitive():
    ev = _valid_event()
    ev["severity"] = "CRITICAL"
    res = create_ticket.handler(ev, None)
    assert res["ok"] is True and res["ticket"]["severity"] == "critical"


@pytest.mark.parametrize("bad_sev", ["info", "sev1", "urgent", "", "  ", "LOWish"])
def test_bad_severity_is_validation_error(bad_sev):
    ev = _valid_event()
    ev["severity"] = bad_sev
    res = create_ticket.handler(ev, None)
    assert res["ok"] is False and res["error"] == "validation_error"


def test_missing_severity_is_validation_error():
    ev = _valid_event()
    del ev["severity"]
    res = create_ticket.handler(ev, None)
    assert res["ok"] is False and res["error"] == "validation_error"


@pytest.mark.parametrize("bad_sev", [1, None, ["high"], {"s": 1}])
def test_non_string_severity_is_validation_error(bad_sev):
    ev = _valid_event()
    ev["severity"] = bad_sev
    res = create_ticket.handler(ev, None)
    assert res["ok"] is False and res["error"] == "validation_error"


# --------------------------------------------------------------------------- #
# Required title / description validation                                     #
# --------------------------------------------------------------------------- #
def test_missing_title_is_validation_error():
    ev = _valid_event()
    del ev["title"]
    res = create_ticket.handler(ev, None)
    assert res["ok"] is False and res["error"] == "validation_error"
    assert "title" in res["message"]


def test_missing_description_is_validation_error():
    ev = _valid_event()
    del ev["description"]
    res = create_ticket.handler(ev, None)
    assert res["ok"] is False and res["error"] == "validation_error"
    assert "description" in res["message"]


@pytest.mark.parametrize("blank", ["", "   ", "\t\n"])
def test_blank_title_is_validation_error(blank):
    ev = _valid_event()
    ev["title"] = blank
    res = create_ticket.handler(ev, None)
    assert res["ok"] is False and res["error"] == "validation_error"


@pytest.mark.parametrize("blank", ["", "   ", "\t\n"])
def test_blank_description_is_validation_error(blank):
    ev = _valid_event()
    ev["description"] = blank
    res = create_ticket.handler(ev, None)
    assert res["ok"] is False and res["error"] == "validation_error"


def test_non_dict_event_is_validation_error():
    res = create_ticket.handler("not-a-dict", None)  # type: ignore[arg-type]
    assert res["ok"] is False and res["error"] == "validation_error"


def test_over_long_title_is_validation_error():
    ev = _valid_event()
    ev["title"] = "a" * (create_ticket._MAX_TITLE_LEN + 1)
    res = create_ticket.handler(ev, None)
    assert res["ok"] is False and res["error"] == "validation_error"
    assert "too long" in res["message"]


# --------------------------------------------------------------------------- #
# Optional-field type validation                                              #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("field", ["assignee", "related_alert_id", "related_host"])
def test_present_but_non_string_optional_is_validation_error(field):
    ev = _valid_event()
    ev[field] = 123
    res = create_ticket.handler(ev, None)
    assert res["ok"] is False and res["error"] == "validation_error"


@pytest.mark.parametrize("field", ["assignee", "related_alert_id", "related_host"])
def test_explicit_none_optional_is_accepted(field):
    ev = _valid_event()
    ev[field] = None
    res = create_ticket.handler(ev, None)
    assert res["ok"] is True
    assert res["ticket"][field] is None


# --------------------------------------------------------------------------- #
# Determinism: same input -> same content-hash id (documented behavior)       #
# --------------------------------------------------------------------------- #
def test_same_input_yields_same_ticket_id():
    a = create_ticket.handler(_valid_event(), None)
    b = create_ticket.handler(_valid_event(), None)
    # Content-hash id => identical requests de-duplicate to the same id and
    # produce byte-identical records (no counter, no clock).
    assert a["ticket"]["ticket_id"] == b["ticket"]["ticket_id"]
    assert a == b


def test_different_content_yields_different_ticket_id():
    a = create_ticket.handler(_valid_event(), None)
    ev = _valid_event()
    ev["title"] = "A different finding entirely"
    b = create_ticket.handler(ev, None)
    assert a["ticket"]["ticket_id"] != b["ticket"]["ticket_id"]


def test_created_ts_is_deterministic_not_wall_clock():
    a = create_ticket.handler(_valid_event(), None)
    b = create_ticket.handler(_valid_event(), None)
    assert a["ticket"]["created_ts"] == b["ticket"]["created_ts"]


def test_result_mutation_does_not_leak_between_calls():
    a = create_ticket.handler(_valid_event(), None)
    a["ticket"]["status"] = "TAMPERED"
    b = create_ticket.handler(_valid_event(), None)
    assert b["ticket"]["status"] == "open"


# --------------------------------------------------------------------------- #
# Live (CREATE_TICKET_LIVE) branch behavior — still ZERO network              #
# --------------------------------------------------------------------------- #
def test_default_is_offline_stub_no_network(monkeypatch):
    monkeypatch.delenv("CREATE_TICKET_LIVE", raising=False)

    def _boom(fields):  # pragma: no cover - must never be called offline
        raise AssertionError("live backend must not be reached in offline mode")

    monkeypatch.setattr(create_ticket, "_create_live", _boom)
    res = create_ticket.handler(_valid_event(), None)
    assert res["ok"] is True and res["source"] == "stub"


@pytest.mark.parametrize("val", ["0", "true", "yes", "", "01"])
def test_live_flag_only_activates_on_exact_1(monkeypatch, val):
    monkeypatch.setenv("CREATE_TICKET_LIVE", val)
    monkeypatch.setattr(
        create_ticket,
        "_create_live",
        lambda f: (_ for _ in ()).throw(AssertionError("should stay offline")),
    )
    res = create_ticket.handler(_valid_event(), None)
    assert res["source"] == "stub"


def test_live_without_backend_url_surfaces_upstream_error(monkeypatch):
    monkeypatch.setenv("CREATE_TICKET_LIVE", "1")
    monkeypatch.delenv("CREATE_TICKET_URL", raising=False)
    res = create_ticket.handler(_valid_event(), None)
    assert res["ok"] is False and res["error"] == "upstream_error"
    assert "CREATE_TICKET_URL is not set" in res["message"]


def test_live_with_backend_url_surfaces_not_implemented(monkeypatch):
    monkeypatch.setenv("CREATE_TICKET_LIVE", "1")
    monkeypatch.setenv("CREATE_TICKET_URL", "https://tracker.example.test/api")
    res = create_ticket.handler(_valid_event(), None)
    assert res["ok"] is False and res["error"] == "upstream_error"
    assert "not wired yet" in res["message"]
    assert "tracker.example.test" in res["message"]


def test_create_live_raises_not_implemented_directly(monkeypatch):
    monkeypatch.setenv("CREATE_TICKET_URL", "https://tracker.example.test")
    with pytest.raises(NotImplementedError, match="live ticketing backend"):
        create_ticket._create_live(_valid_event())


def test_create_live_without_url_raises_runtime_error(monkeypatch):
    monkeypatch.delenv("CREATE_TICKET_URL", raising=False)
    with pytest.raises(RuntimeError, match="CREATE_TICKET_URL is not set"):
        create_ticket._create_live(_valid_event())


def test_live_success_path_sets_source_live(monkeypatch):
    """When a live client IS wired (future), the handler wraps its ticket with
    source='live'. We stub _create_live to return a record — still ZERO network."""
    monkeypatch.setenv("CREATE_TICKET_LIVE", "1")
    fake_ticket = {"ticket_id": "SEC-9999", "status": "open"}
    monkeypatch.setattr(create_ticket, "_create_live", lambda f: fake_ticket)
    res = create_ticket.handler(_valid_event(), None)
    assert res["ok"] is True
    assert res["source"] == "live"
    assert res["ticket"] == fake_ticket


# --------------------------------------------------------------------------- #
# __main__ entrypoint                                                         #
# --------------------------------------------------------------------------- #
def test_main_entrypoint_prints_created_ticket(capsys, monkeypatch):
    import json

    monkeypatch.delenv("CREATE_TICKET_LIVE", raising=False)
    runpy.run_path(HANDLER_PATH, run_name="__main__")
    out = capsys.readouterr().out
    parsed = json.loads(out)
    assert parsed["ok"] is True
    assert parsed["source"] == "stub"
    assert parsed["ticket"]["status"] == "open"
    assert parsed["ticket"]["related_host"] == "web-01"


# --------------------------------------------------------------------------- #
# House rule: no hardcoded secrets or real account ids in the source          #
# --------------------------------------------------------------------------- #
def test_source_has_no_hardcoded_secrets_or_account_ids():
    import re

    src = open(HANDLER_PATH, encoding="utf-8").read()
    for m in re.findall(r"\b\d{12}\b", src):
        assert m == "000000000000", f"hardcoded account id: {m}"
    assert "sk-" not in src and "ghp_" not in src
