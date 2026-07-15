"""
Offline contract tests for sentinel_harness.connectors.

ZERO network, ZERO AWS, no clock, no credentials — connectors are PURE
translators, so every property is checkable against a native-shape fixture:
- build_request emits the backend's native query shape,
- parse_response maps a native response envelope to the neutral shape EXACTLY,
- field-name drift (flat-dotted AND nested keys) is absorbed,
- malformed envelopes raise ConnectorError (never silently yield []),
- the registry looks up by name and fails loudly on an unknown connector.
"""
from __future__ import annotations

import pytest

from sentinel_harness import connectors as C
from sentinel_harness.connectors.base import NEUTRAL_EVENT_FIELDS, ConnectorError


# --------------------------------------------------------------------------- #
# registry                                                                    #
# --------------------------------------------------------------------------- #
def test_siem_registry_lists_expected():
    assert set(C.available_siem_connectors()) == {"splunk", "elastic", "opensearch"}


def test_ticketing_registry_lists_expected():
    assert set(C.available_ticketing_connectors()) == {"servicenow", "jira"}


def test_unknown_siem_connector_raises_with_names():
    with pytest.raises(KeyError) as ei:
        C.get_siem_connector("qradar")
    assert "splunk" in str(ei.value)  # lists known names


def test_unknown_ticketing_connector_raises():
    with pytest.raises(KeyError):
        C.get_ticketing_connector("trac")


# --------------------------------------------------------------------------- #
# Splunk                                                                      #
# --------------------------------------------------------------------------- #
def test_splunk_build_request_spl():
    req = C.get_siem_connector("splunk").build_request("host", "web-01")
    assert 'host="web-01"' in req["body"]["search"]
    assert req["body"]["output_mode"] == "json"


def test_splunk_build_request_wildcard():
    req = C.get_siem_connector("splunk").build_request("*", "*")
    assert "search index=" in req["body"]["search"]


def test_splunk_parse_results_envelope():
    conn = C.get_siem_connector("splunk")
    reply = {"results": [
        {"id": "alert-1001", "_time": "2026-06-28T14:03:11Z", "level": "critical",
         "signature": "Log4Shell", "host": "web-01", "src": "203.0.113.66",
         "dest": "192.0.2.10", "mitre_technique": "T1190", "_raw": "JNDI payload"},
    ]}
    events = conn.parse_response(reply)
    assert len(events) == 1
    ev = events[0]
    assert set(ev) == set(NEUTRAL_EVENT_FIELDS)
    assert ev["alert_id"] == "alert-1001"
    assert ev["severity"] == "critical"
    assert ev["rule_name"] == "Log4Shell"
    assert ev["src_ip"] == "203.0.113.66"
    assert ev["technique"] == "T1190"


def test_splunk_empty_results_is_empty_list():
    assert C.get_siem_connector("splunk").parse_response({"results": []}) == []


def test_splunk_missing_envelope_raises():
    with pytest.raises(ConnectorError):
        C.get_siem_connector("splunk").parse_response({"data": []})
    with pytest.raises(ConnectorError):
        C.get_siem_connector("splunk").parse_response([])  # bare list, not enveloped


# --------------------------------------------------------------------------- #
# Elastic / OpenSearch (shared envelope)                                      #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("name", ["elastic", "opensearch"])
def test_es_family_build_request_dsl(name):
    conn = C.get_siem_connector(name)
    star = conn.build_request("*", "*")
    assert star["body"]["query"] == {"match_all": {}}
    assert star["path"] == "/_search"
    term = conn.build_request("host", "web-01")
    assert term["body"]["query"]["term"] == {"host.keyword": "web-01"}


@pytest.mark.parametrize("name", ["elastic", "opensearch"])
def test_es_family_parse_nested_and_flat(name):
    conn = C.get_siem_connector(name)
    # nested _source keys
    nested = {"hits": {"hits": [
        {"_source": {"alert_id": "a1", "host": {"name": "web-01"},
                     "source": {"ip": "203.0.113.66"}, "severity": "critical",
                     "rule": "Log4Shell", "technique": "T1190"}},
    ]}}
    ev = conn.parse_response(nested)[0]
    assert ev["host"] == "web-01" and ev["src_ip"] == "203.0.113.66"
    assert set(ev) == set(NEUTRAL_EVENT_FIELDS)
    # flat-dotted keys
    flat = {"hits": {"hits": [
        {"_source": {"alert_id": "a2", "host.name": "bastion-01",
                     "source.ip": "198.51.100.200", "severity": "high",
                     "rule": "SSH Brute Force", "technique": "T1110"}},
    ]}}
    ev2 = conn.parse_response(flat)[0]
    assert ev2["host"] == "bastion-01" and ev2["src_ip"] == "198.51.100.200"


@pytest.mark.parametrize("name", ["elastic", "opensearch"])
def test_es_family_missing_hits_raises(name):
    with pytest.raises(ConnectorError):
        C.get_siem_connector(name).parse_response({"results": []})
    with pytest.raises(ConnectorError):
        C.get_siem_connector(name).parse_response({"hits": {"total": 0}})


# --------------------------------------------------------------------------- #
# ServiceNow                                                                  #
# --------------------------------------------------------------------------- #
def test_servicenow_build_incident():
    conn = C.get_ticketing_connector("servicenow")
    req = conn.build_request({"title": "Log4Shell on web-01", "severity": "critical",
                              "related_alert_ids": ["alert-1001", "alert-1002"],
                              "assigned_team": "secops", "body": "details"})
    assert req["path"] == "/api/now/table/incident"
    assert req["body"]["short_description"] == "Log4Shell on web-01"
    assert req["body"]["urgency"] == "1"  # critical → high urgency
    assert req["body"]["correlation_id"] == "alert-1001,alert-1002"


def test_servicenow_parse_result():
    res = C.get_ticketing_connector("servicenow").parse_response(
        {"result": {"number": "INC0012345", "state": "new"}})
    assert res["ticket_id"] == "INC0012345"
    assert res["status"] == "new"


def test_servicenow_requires_title():
    with pytest.raises(ConnectorError):
        C.get_ticketing_connector("servicenow").build_request({"severity": "high"})


def test_servicenow_missing_result_raises():
    with pytest.raises(ConnectorError):
        C.get_ticketing_connector("servicenow").parse_response({"error": "bad"})


# --------------------------------------------------------------------------- #
# Jira                                                                        #
# --------------------------------------------------------------------------- #
def test_jira_build_issue():
    conn = C.get_ticketing_connector("jira")
    req = conn.build_request({"title": "Kerberoasting on dc-01", "severity": "high",
                              "related_alert_ids": ["alert-1008"], "assigned_team": "ir"})
    assert req["path"] == "/rest/api/2/issue"
    assert req["body"]["fields"]["summary"] == "Kerberoasting on dc-01"
    assert req["body"]["fields"]["priority"]["name"] == "High"
    assert "alert-1008" in req["body"]["fields"]["labels"]
    assert "team:ir" in req["body"]["fields"]["labels"]


def test_jira_parse_key():
    res = C.get_ticketing_connector("jira").parse_response({"key": "SEC-42", "self": "http://x/SEC-42"})
    assert res["ticket_id"] == "SEC-42"


def test_jira_missing_key_raises():
    with pytest.raises(ConnectorError):
        C.get_ticketing_connector("jira").parse_response({"errors": {}})


# --------------------------------------------------------------------------- #
# neutral_event contract + hygiene                                            #
# --------------------------------------------------------------------------- #
def test_neutral_event_defaults_all_fields():
    ev = C.neutral_event({"alert_id": "x"})
    assert set(ev) == set(NEUTRAL_EVENT_FIELDS)
    assert ev["src_ip"] is None and ev["dst_ip"] is None  # legitimately absent
    assert ev["false_positive"] is False


def test_no_endpoints_or_secrets_in_connector_source():
    import os
    import re
    pkg = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "sentinel_harness", "connectors")
    for fn in os.listdir(pkg):
        if not fn.endswith(".py"):
            continue
        text = open(os.path.join(pkg, fn), encoding="utf-8").read()
        # no hardcoded http(s) endpoints, no obvious tokens
        assert not re.search(r"https?://[a-z0-9.]+\.(com|net|io)\b", text, re.I), f"{fn} hardcodes an endpoint"
        for tok in ("AKIA", "ghp_", "xoxb-", "Bearer "):
            assert tok not in text, f"{fn} contains {tok!r}"


# --------------------------------------------------------------------------- #
# INTEGRATION: siem_query tool + connector + in-process mock backend          #
# --------------------------------------------------------------------------- #
def _load_siem_tool():
    import importlib.util
    import os
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "tools", "siem_query", "handler.py")
    spec = importlib.util.spec_from_file_location("siem_query_undertest", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_siem_tool_routes_through_splunk_connector(monkeypatch):
    """The real tool, with SIEM_QUERY_CONNECTOR=splunk pointed at an in-process
    mock Splunk (127.0.0.1, ephemeral port), must send SPL, parse the native
    results[] envelope, and return a normalized event. ZERO external network."""
    import json
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    captured = {}

    class _MockSplunk(BaseHTTPRequestHandler):
        def log_message(self, *a):  # silence
            pass

        def do_POST(self):  # noqa: N802
            n = int(self.headers.get("Content-Length", 0))
            captured["req"] = json.loads(self.rfile.read(n))
            reply = {"results": [
                {"id": "alert-1001", "_time": "2026-06-28T14:03:11Z", "level": "critical",
                 "signature": "Log4Shell", "host": "web-01", "src": "203.0.113.66",
                 "mitre_technique": "T1190", "_raw": "JNDI payload"},
            ]}
            b = json.dumps(reply).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), _MockSplunk)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        monkeypatch.setenv("SIEM_QUERY_LIVE", "1")
        monkeypatch.setenv("SIEM_QUERY_URL", f"http://127.0.0.1:{port}/services/search")
        monkeypatch.setenv("SIEM_QUERY_CONNECTOR", "splunk")
        mod = _load_siem_tool()
        out = mod.handler({"query": "web-01"}, None)
    finally:
        srv.shutdown()

    assert out["ok"] is True
    assert out["source"] == "live"
    assert len(out["events"]) == 1
    ev = out["events"][0]
    assert ev["alert_id"] == "alert-1001" and ev["rule_name"] == "Log4Shell"
    assert ev["src_ip"] == "203.0.113.66"
    # the tool sent SPL (the connector's native shape), not a bare {key: value}
    assert "search" in captured["req"]


def test_siem_tool_unknown_connector_is_upstream_error(monkeypatch):
    """A mis-set SIEM_QUERY_CONNECTOR fails loudly as upstream_error, not silently."""
    monkeypatch.setenv("SIEM_QUERY_LIVE", "1")
    monkeypatch.setenv("SIEM_QUERY_URL", "http://127.0.0.1:9/x")
    monkeypatch.setenv("SIEM_QUERY_CONNECTOR", "qradar")
    mod = _load_siem_tool()
    out = mod.handler({"query": "*"}, None)
    assert out["ok"] is False
    assert out["error"] == "upstream_error"
    assert "qradar" in out["message"]
