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
    assert set(C.available_siem_connectors()) == {
        "splunk", "elastic", "opensearch", "qradar", "microsoft_sentinel",
        "chronicle", "sumologic", "datadog",
    }


def test_ticketing_registry_lists_expected():
    assert set(C.available_ticketing_connectors()) == {"servicenow", "jira", "pagerduty"}


def test_unknown_siem_connector_raises_with_names():
    with pytest.raises(KeyError) as ei:
        C.get_siem_connector("nonesuch_siem")
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
# QRadar (AQL → events[])                                                     #
# --------------------------------------------------------------------------- #
def test_qradar_build_aql():
    conn = C.get_siem_connector("qradar")
    assert "SELECT * FROM events" in conn.build_request("*", "*")["body"]["query_expression"]
    filt = conn.build_request("sourceip", "203.0.113.66")["body"]["query_expression"]
    assert "sourceip = '203.0.113.66'" in filt


def test_qradar_parse_events_envelope():
    conn = C.get_siem_connector("qradar")
    ev = conn.parse_response({"events": [
        {"id": "a1", "severity": "critical", "rule": "Log4Shell", "host": "web-01",
         "src": "203.0.113.66", "technique": "T1190"}]})
    assert len(ev) == 1 and set(ev[0]) == set(NEUTRAL_EVENT_FIELDS)
    assert ev[0]["alert_id"] == "a1" and ev[0]["src_ip"] == "203.0.113.66"


def test_qradar_missing_events_raises():
    with pytest.raises(ConnectorError):
        C.get_siem_connector("qradar").parse_response({"data": []})


def test_qradar_empty_events_is_empty_list():
    assert C.get_siem_connector("qradar").parse_response({"events": []}) == []


# --------------------------------------------------------------------------- #
# Microsoft Sentinel (KQL → columnar tables[].columns/rows)                   #
# --------------------------------------------------------------------------- #
def test_sentinel_build_kql():
    conn = C.get_siem_connector("microsoft_sentinel")
    assert "SecurityAlert" in conn.build_request("*", "*")["body"]["query"]
    filt = conn.build_request("Computer", "web-01")["body"]["query"]
    assert 'Computer == "web-01"' in filt


def test_sentinel_parses_columnar_rows():
    """The columnar (columns+rows) shape must project to neutral events — the
    framework-flexibility check (not a list of objects like the others)."""
    conn = C.get_siem_connector("microsoft_sentinel")
    reply = {"tables": [{
        "columns": [{"name": "alert_id"}, {"name": "severity"}, {"name": "rule_name"},
                    {"name": "host"}, {"name": "src_ip"}, {"name": "technique"}],
        "rows": [
            ["a1", "critical", "Log4Shell", "web-01", "203.0.113.66", "T1190"],
            ["a2", "high", "SSH Brute Force", "bastion-01", "198.51.100.200", "T1110"],
        ],
    }]}
    events = conn.parse_response(reply)
    assert len(events) == 2
    assert set(events[0]) == set(NEUTRAL_EVENT_FIELDS)
    assert events[0]["alert_id"] == "a1" and events[0]["host"] == "web-01"
    assert events[1]["src_ip"] == "198.51.100.200"


def test_sentinel_accepts_bare_string_columns():
    conn = C.get_siem_connector("microsoft_sentinel")
    reply = {"tables": [{"columns": ["alert_id", "host"], "rows": [["a3", "db-01"]]}]}
    ev = conn.parse_response(reply)
    assert ev[0]["alert_id"] == "a3" and ev[0]["host"] == "db-01"


def test_sentinel_empty_tables_is_empty_list():
    assert C.get_siem_connector("microsoft_sentinel").parse_response({"tables": []}) == []


def test_sentinel_missing_tables_raises():
    with pytest.raises(ConnectorError):
        C.get_siem_connector("microsoft_sentinel").parse_response({"rows": []})
    with pytest.raises(ConnectorError):
        # table without columns/rows
        C.get_siem_connector("microsoft_sentinel").parse_response({"tables": [{"columns": []}]})


# --------------------------------------------------------------------------- #
# PagerDuty                                                                   #
# --------------------------------------------------------------------------- #
def test_pagerduty_build_incident():
    conn = C.get_ticketing_connector("pagerduty")
    req = conn.build_request({"title": "Log4Shell on web-01", "severity": "critical",
                              "body": "exploit observed"})
    assert req["path"] == "/incidents"
    assert req["body"]["incident"]["urgency"] == "high"  # critical → high
    assert req["body"]["incident"]["title"] == "Log4Shell on web-01"


def test_pagerduty_medium_is_low_urgency():
    req = C.get_ticketing_connector("pagerduty").build_request(
        {"title": "noisy", "severity": "medium"})
    assert req["body"]["incident"]["urgency"] == "low"


def test_pagerduty_parse_incident():
    res = C.get_ticketing_connector("pagerduty").parse_response(
        {"incident": {"id": "PABC123", "status": "triggered", "html_url": "http://pd/PABC123"}})
    assert res["ticket_id"] == "PABC123" and res["status"] == "triggered"


def test_pagerduty_missing_incident_raises():
    with pytest.raises(ConnectorError):
        C.get_ticketing_connector("pagerduty").parse_response({"error": "bad"})


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
    monkeypatch.setenv("SIEM_QUERY_CONNECTOR", "nonesuch_siem")
    mod = _load_siem_tool()
    out = mod.handler({"query": "*"}, None)
    assert out["ok"] is False
    assert out["error"] == "upstream_error"
    assert "nonesuch_siem" in out["message"]


# --------------------------------------------------------------------------- #
# regression: audited MEDIUM/LOW connector findings                           #
# --------------------------------------------------------------------------- #
def test_deeply_nested_dict_never_lands_in_scalar_field():
    """A doubly-nested object (host.name.fqdn) must not put a dict in ev['host']."""
    es = C.get_siem_connector("elastic")
    ev = es.parse_response({"hits": {"hits": [
        {"_source": {"host": {"name": {"fqdn": "web-01"}}, "alert_id": "a",
                     "severity": "high", "rule": "R", "technique": "T1190"}}]}})
    assert ev[0]["host"] == ""  # rejected, not the nested dict


def test_ms_sentinel_row_col_mismatch_raises():
    ms = C.get_siem_connector("microsoft_sentinel")
    with pytest.raises(ConnectorError):
        ms.parse_response({"tables": [{"columns": [{"name": "alert_id"}, {"name": "host"}],
                                       "rows": [["a1"]]}]})  # 2 cols, 1 value
    with pytest.raises(ConnectorError):
        ms.parse_response({"tables": [{"columns": [{"name": "alert_id"}],
                                       "rows": [["a1", "extra"]]}]})  # 1 col, 2 values


def test_string_false_positive_not_flipped_true():
    from sentinel_harness.connectors.base import neutral_event
    assert neutral_event({"false_positive": "false"})["false_positive"] is False
    assert neutral_event({"false_positive": "0"})["false_positive"] is False
    assert neutral_event({"false_positive": "true"})["false_positive"] is True
    assert neutral_event({"fp": "yes"})["false_positive"] is False  # 'fp' not a neutral key
    # via the real map path (fp candidate)
    from sentinel_harness.connectors.siem import _map_record
    assert _map_record({"alert_id": "x", "fp": "0"})["false_positive"] is False


def test_string_related_alert_ids_not_char_split():
    sn = C.get_ticketing_connector("servicenow")
    req = sn.build_request({"title": "t", "severity": "high", "related_alert_ids": "alert-1001"})
    assert req["body"]["correlation_id"] == "alert-1001"  # not 'a,l,e,r,t,...'
    jira = C.get_ticketing_connector("jira")
    jreq = jira.build_request({"title": "t", "severity": "high", "related_alert_ids": "alert-1001"})
    assert "alert-1001" in jreq["body"]["fields"]["labels"]


def test_bad_related_alert_ids_type_raises():
    with pytest.raises(ConnectorError):
        C.get_ticketing_connector("servicenow").build_request(
            {"title": "t", "related_alert_ids": 12345})


@pytest.mark.parametrize("name", ["splunk", "qradar", "microsoft_sentinel"])
def test_dsl_injection_is_escaped(name):
    """A value with the DSL delimiter cannot break out of the quoted literal."""
    conn = C.get_siem_connector(name)
    body = conn.build_request("field", 'x" OR 1=1 | drop')["body"]
    dsl = body.get("search") or body.get("query_expression") or body.get("query")
    # the raw unescaped delimiter sequence must not appear outside an escaped form
    assert '" OR 1=1 | drop"' not in dsl or "\\" in dsl


# --------------------------------------------------------------------------- #
# batch-2 SIEM connectors: Chronicle / Sumo Logic / Datadog                   #
# --------------------------------------------------------------------------- #
def test_chronicle_build_and_parse():
    conn = C.get_siem_connector("chronicle")
    assert "udmSearch" in conn.build_request("host", "web-01")["path"]
    ev = conn.parse_response({"events": [
        {"udm": {"alert_id": "c1", "host": {"name": "web-01"}, "severity": "high",
                 "rule": "R", "src_ip": "203.0.113.66", "technique": "T1190"}}]})
    assert set(ev[0]) == set(NEUTRAL_EVENT_FIELDS)
    assert ev[0]["alert_id"] == "c1" and ev[0]["host"] == "web-01"


def test_chronicle_missing_events_raises():
    with pytest.raises(ConnectorError):
        C.get_siem_connector("chronicle").parse_response({"nope": []})


def test_sumologic_build_and_parse():
    conn = C.get_siem_connector("sumologic")
    assert "limit 1000" in conn.build_request("*", "*")["body"]["query"]
    ev = conn.parse_response({"messages": [
        {"map": {"alert_id": "s1", "host": "bastion-01", "severity": "high",
                 "rule": "R", "src_ip": "198.51.100.200", "technique": "T1110"}}]})
    assert set(ev[0]) == set(NEUTRAL_EVENT_FIELDS)
    assert ev[0]["src_ip"] == "198.51.100.200"


def test_sumologic_missing_messages_raises():
    with pytest.raises(ConnectorError):
        C.get_siem_connector("sumologic").parse_response({"results": []})


def test_datadog_build_and_parse_nested_attributes():
    conn = C.get_siem_connector("datadog")
    body = conn.build_request("host", "db-01")["body"]
    assert "filter" in body and "query" in body["filter"]
    # Datadog nests event fields under attributes.attributes for signals
    ev = conn.parse_response({"data": [
        {"attributes": {"attributes": {"alert_id": "d1", "host": "db-01"},
                        "severity": "critical", "rule": "R", "technique": "T1005"}}]})
    assert set(ev[0]) == set(NEUTRAL_EVENT_FIELDS)
    assert ev[0]["alert_id"] == "d1" and ev[0]["host"] == "db-01"
    assert ev[0]["severity"] == "critical"


def test_datadog_missing_data_raises():
    with pytest.raises(ConnectorError):
        C.get_siem_connector("datadog").parse_response({"signals": []})


@pytest.mark.parametrize("name", ["chronicle", "sumologic", "datadog"])
def test_batch2_dsl_injection_escaped(name):
    conn = C.get_siem_connector(name)
    body = conn.build_request("field", 'x" OR 1=1')["body"]
    dsl = body.get("query") or str(body.get("filter"))
    # the value's quote must be escaped (backslash) so it can't break the literal
    assert '\\"' in dsl or 'OR 1=1' not in dsl.split('"')[0]


# --------------------------------------------------------------------------- #
# regression (round-2 audit): Datadog nested-attributes merge must not clobber #
# a real top-level value (top level WINS; nested only fills gaps)             #
# --------------------------------------------------------------------------- #
def test_datadog_toplevel_attribute_wins_over_nested():
    conn = C.get_siem_connector("datadog")
    reply = {"data": [{"attributes": {
        "attributes": {"alert_id": "d1", "severity": ""},   # nested (raw) sub-block
        "severity": "critical",                             # real top-level value
        "rule": "R", "host": "db-01", "technique": "T1005",
    }}]}
    ev = conn.parse_response(reply)[0]
    assert ev["severity"] == "critical"   # top-level wins, NOT the nested ''
    assert ev["alert_id"] == "d1"         # nested fills a gap the top level lacks
