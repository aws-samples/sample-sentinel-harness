"""
Offline tests for the connector conformance kit.

ZERO network, ZERO AWS. Two jobs:
  1. Assert every SHIPPED connector is conformant (a regression guard: a future
     connector change that breaks the contract fails CI here).
  2. Prove the kit actually BITES — deliberately-broken connectors must be caught
     (a conformance kit that can't fail is worthless).
"""
from __future__ import annotations

import pytest

from sentinel_harness import connectors as C
from sentinel_harness.connectors import conformance as K
from sentinel_harness.connectors.base import ConnectorError


# --------------------------------------------------------------------------- #
# every shipped connector is conformant                                       #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("name", C.available_siem_connectors())
def test_shipped_siem_connector_conformant(name):
    res = K.check_siem_connector(C.get_siem_connector(name))
    assert res.ok, f"{name} failed conformance: {res.failures}"
    assert len(res.checks) >= 4


@pytest.mark.parametrize("name", C.available_ticketing_connectors())
def test_shipped_ticketing_connector_conformant(name):
    res = K.check_ticketing_connector(C.get_ticketing_connector(name))
    assert res.ok, f"{name} failed conformance: {res.failures}"
    assert len(res.checks) >= 4


def test_certify_all_reports_every_connector():
    results = K.certify_all(
        C.get_siem_connector, C.get_ticketing_connector,
        C.available_siem_connectors(), C.available_ticketing_connectors(),
    )
    assert set(results) == set(C.available_siem_connectors()) | set(C.available_ticketing_connectors())
    assert all(r.ok for r in results.values())


# --------------------------------------------------------------------------- #
# the kit BITES: broken connectors are caught                                 #
# --------------------------------------------------------------------------- #
class _NoNameSiem:
    name = ""  # invalid

    def build_request(self, s, v):
        return {"body": {}, "path": ""}

    def parse_response(self, p):
        return []


def test_kit_catches_empty_name():
    res = K.check_siem_connector(_NoNameSiem())
    assert res.ok is False
    assert any("has_name" in f for f in res.failures)


class _BadShapeSiem:
    name = "bad_shape"

    def build_request(self, s, v):
        return "not a dict"  # violates the {body, path} contract

    def parse_response(self, p):
        return [{"only": "one field"}]  # not the neutral shape

    def sample_response(self):
        return {"anything": True}


def test_kit_catches_bad_request_shape_and_non_neutral_events():
    res = K.check_siem_connector(_BadShapeSiem())
    assert res.ok is False
    assert any("build_request_shape" in f for f in res.failures)
    assert any("parse_sample_to_neutral" in f for f in res.failures)


class _SwallowsForeignSiem:
    name = "swallows"

    def build_request(self, s, v):
        return {"body": {}, "path": ""}

    def parse_response(self, p):
        # WRONG: returns [] for anything instead of raising on a foreign envelope
        return [{f: "" if f not in ("src_ip", "dst_ip") else None
                 for f in K.NEUTRAL_EVENT_FIELDS}] if "results" in (p or {}) else []

    def sample_response(self):
        return {"results": [{}]}


def test_kit_catches_swallowed_foreign_envelope():
    res = K.check_siem_connector(_SwallowsForeignSiem())
    assert res.ok is False
    assert any("rejects_foreign_envelope" in f for f in res.failures)


class _NoTitleCheckTicketing:
    name = "no_title_check"

    def build_request(self, request):
        return {"body": {"t": request.get("title", "")}, "path": "/x"}  # accepts title-less

    def parse_response(self, p):
        if not isinstance(p, dict) or "id" not in p:
            raise ConnectorError("no id")
        return {"ticket_id": p["id"], "status": "open", "url": ""}

    def sample_response(self):
        return {"id": "T1"}


def test_kit_catches_missing_title_validation():
    res = K.check_ticketing_connector(_NoTitleCheckTicketing())
    assert res.ok is False
    assert any("rejects_titleless" in f for f in res.failures)


# --------------------------------------------------------------------------- #
# a third-party connector with sample_response() self-certifies               #
# --------------------------------------------------------------------------- #
class _ThirdPartySiem:
    """A well-behaved hypothetical third-party connector using its OWN sample."""

    name = "acme_siem"

    def build_request(self, selector, value):
        q = "all" if selector == "*" else f"{selector}:{value}"
        return {"body": {"q": q}, "path": "/search"}

    def parse_response(self, payload):
        from sentinel_harness.connectors.base import neutral_event
        if not isinstance(payload, dict) or "records" not in payload:
            raise ConnectorError("acme reply missing 'records'")
        return [neutral_event(r) for r in payload["records"]]

    def sample_response(self):
        return {"records": [{"alert_id": "acme-1", "host": "web-01",
                             "severity": "high", "technique": "T1190"}]}


def test_third_party_connector_self_certifies_via_sample_response():
    res = K.check_siem_connector(_ThirdPartySiem())
    assert res.ok, f"third-party connector should be conformant: {res.failures}"
