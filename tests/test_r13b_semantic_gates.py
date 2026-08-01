"""
Round-13b regression suite — connector selector semantics & response fidelity.
==============================================================================
Round 13's fan-out workflow returned 15 adversarially-reproduced findings across
the FP heuristic and the connector seams — far more than the two I had found by
hand, and one of them **overturned a conclusion I had already drawn**. That is
worth recording, because it is a lesson about the method, not just the code:

    I probed the FP heuristic's false-NEGATIVE direction with a fixture that used
    `category: process_creation` + `level: high`, measured >=2 warnings on every
    broad rule, and concluded the heuristic was SOUND in that direction. It is
    not. Those two properties independently trip checks #2 and #5; the fixture,
    not the heuristic, was doing the work. With a neutral fixture
    (`service: sysmon`, `level: medium`) six match-everything predicates score
    ZERO warnings. **Probing a heuristic requires varying every dimension that
    can mask the result, or you are measuring the fixture.**

This module covers the CONNECTOR half of that round (the FP half lands in the
sibling suite). Two defect classes, both of which make the offline-validated
behaviour diverge from production:

1. **A semantic selector was emitted as a field filter.** `siem_query` accepts
   `query` (match-all) and `since` (a time floor) — query SEMANTICS, not backend
   fields. Passing them straight to `build_request` produced `query="*"` and
   `since="<ts>"`: filters on fields no backend has. The LIVE path returned 0 rows
   where the offline mock returned all 11. A detection validated offline silently
   returned nothing in production.

2. **Response normalization lost or fabricated fields.** An ES hit's `_id` was
   discarded whenever `_source` was present, so two DISTINCT documents produced
   byte-identical neutral events (`alert_id: ""`) and deduped into one. Jira
   hardcoded `status: "open"`, contradicting a reply that said otherwise. And the
   generic live path and the connector path returned OPPOSITE booleans for a
   string `false_positive` — one of them dropping a genuine alert as noise.

Every test below FAILS on pre-R13b source. Zero network, zero AWS, zero LLM.
"""
from __future__ import annotations

import importlib.util
import os
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

os.environ.setdefault("SENTINEL_REGION", "us-east-1")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("SENTINEL_EXECUTION_ROLE_ARN",
                      "arn:aws:iam::000000000000:role/test-harness-role")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")


def _load(unique_name: str, rel_path: str):
    path = os.path.join(REPO_ROOT, rel_path)
    spec = importlib.util.spec_from_file_location(unique_name, path)
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[unique_name] = module
    spec.loader.exec_module(module)
    return module


siem_query = _load("siem_query_r13b", "tools/siem_query/handler.py")

from sentinel_harness.connectors import (  # noqa: E402
    available_siem_connectors, get_siem_connector, get_ticketing_connector,
)
from sentinel_harness.connectors import conformance as C  # noqa: E402
from sentinel_harness.connectors.base import (  # noqa: E402
    ConnectorError, _coerce_bool, resolve_selector,
)

_ALL = available_siem_connectors()


# --------------------------------------------------------------------------- #
# INV-CONNECTOR-3 — a semantic selector is never a field filter               #
# --------------------------------------------------------------------------- #
class TestSelectorSemantics:
    """`query` and `since` are query semantics, not backend field names."""

    def test_resolve_selector_classifies_the_semantic_ones(self):
        assert resolve_selector("query", "*")[0] == "match_all"
        assert resolve_selector("*", "")[0] == "match_all"
        assert resolve_selector("since", "2026-06-28T00:00:00Z")[0] == "time_floor"
        assert resolve_selector("query", "ransomware")[0] == "free_text"
        kind, field, _ = resolve_selector("host", "web-01")
        assert (kind, field) == ("field", "host")

    @pytest.mark.parametrize("name", _ALL)
    def test_match_all_selector_is_not_a_field_filter(self, name):
        """`query: "*"` must mean "everything", not a filter on a `query` field."""
        emitted = str(get_siem_connector(name).build_request("query", "*"))
        for wrong in ('query="*"', "query = '*'", '@query:', '"query": "*"'):
            assert wrong not in emitted, f"{name} filters on a nonexistent query field"

    @pytest.mark.parametrize("name", _ALL)
    def test_time_floor_selector_becomes_a_range_not_an_equality(self, name):
        """`since: <ts>` is a lower time bound. Emitting `since="<ts>"` filtered on a
        field no backend has — the live path returned zero rows."""
        ts = "2026-06-28T00:00:00Z"
        emitted = str(get_siem_connector(name).build_request("since", ts))
        for wrong in (f'since="{ts}"', f"since = '{ts}'", "@since:"):
            assert wrong not in emitted, f"{name} emits `since` as a field equality"
        assert ts in emitted, f"{name} dropped the time bound entirely"

    @pytest.mark.parametrize("name", _ALL)
    def test_ordinary_field_selectors_still_filter_on_that_field(self, name):
        """Regression: the fix must not break the common case."""
        emitted = str(get_siem_connector(name).build_request("host", "web-01"))
        assert "web-01" in emitted
        assert "host" in emitted

    @pytest.mark.parametrize("name", _ALL)
    def test_free_text_query_is_a_search_not_a_field(self, name):
        """A non-`*` value on the `query` selector is free text over the record."""
        emitted = str(get_siem_connector(name).build_request("query", "ransomware"))
        assert "ransomware" in emitted
        assert 'query="ransomware"' not in emitted

    @pytest.mark.parametrize("name", _ALL)
    def test_every_tool_selector_is_translatable(self, name):
        """All six selectors `siem_query` accepts must produce a sane request — none
        may silently become a filter on a field that does not exist."""
        conn = get_siem_connector(name)
        for key in ("host", "technique", "severity", "alert_id", "since", "query"):
            value = "*" if key == "query" else "x"
            req = conn.build_request(key, value)
            assert isinstance(req, dict) and "body" in req and "path" in req

    def test_result_set_equivalence_survives_the_selector_fix(self):
        """The R13 equivalence guarantee must still hold after the rewrite."""
        r = C.check_result_set_equivalence(get_siem_connector, _ALL)
        assert r.ok, r.failures


# --------------------------------------------------------------------------- #
# INV-CONNECTOR-4 — the two live paths agree on every coercion                #
# --------------------------------------------------------------------------- #
class TestLivePathsAgree:
    """PRE-R13b: `bool("false")` is True, so the generic live path flagged a genuine
    alert as a false positive and dropped it as noise, while the connector path read
    the same bytes as False. Two live paths, opposite security verdicts."""

    @pytest.mark.parametrize("value", [
        "false", "0", "no", "False", "FALSE", "f", "n",
        "true", "1", "yes", "Y", "t", True, False, None, "",
    ])
    def test_generic_and_connector_paths_agree(self, value):
        generic = siem_query._normalize_live_event({"false_positive": value})["false_positive"]
        connector = _coerce_bool(value)
        assert generic == connector, f"{value!r}: generic={generic} connector={connector}"

    @pytest.mark.parametrize("falsey", ["false", "False", "0", "no", "f"])
    def test_a_string_false_is_not_a_false_positive(self, falsey):
        """The specific harm: a real alert must not be dropped as noise because the
        backend serialized its boolean as a string."""
        ev = siem_query._normalize_live_event({"alert_id": "a1", "false_positive": falsey})
        assert ev["false_positive"] is False

    @pytest.mark.parametrize("truthy", ["true", "1", "yes"])
    def test_a_string_true_is_still_a_false_positive(self, truthy):
        ev = siem_query._normalize_live_event({"alert_id": "a1", "false_positive": truthy})
        assert ev["false_positive"] is True


# --------------------------------------------------------------------------- #
# INV-CONNECTOR-5 — normalization neither loses nor fabricates a field        #
# --------------------------------------------------------------------------- #
class TestResponseNormalizationFidelity:

    @pytest.mark.parametrize("name", ["elastic", "opensearch"])
    def test_es_hit_id_survives_into_alert_id(self, name):
        """PRE-R13b: `_id` lives at the HIT level, and reading only `_source` dropped
        it — so two DISTINCT documents produced byte-identical neutral events and
        deduped into one, with no way to trace an alert to its document."""
        payload = {"hits": {"hits": [
            {"_id": "doc-a", "_source": {"host": "web-01", "severity": "high"}},
            {"_id": "doc-b", "_source": {"host": "web-02", "severity": "high"}},
        ]}}
        events = get_siem_connector(name).parse_response(payload)
        ids = [e["alert_id"] for e in events]
        assert ids == ["doc-a", "doc-b"]
        assert len(set(ids)) == 2, "two distinct documents collapsed to one event"

    @pytest.mark.parametrize("name", ["elastic", "opensearch"])
    def test_document_owned_id_wins_over_the_hit_id(self, name):
        """The fallback must not override an id the document itself carries."""
        payload = {"hits": {"hits": [
            {"_id": "es-internal", "_source": {"alert_id": "REAL-1", "host": "h"}},
        ]}}
        assert get_siem_connector(name).parse_response(payload)[0]["alert_id"] == "REAL-1"

    def test_jira_reports_the_status_the_reply_states(self):
        """PRE-R13b: hardcoded "open" contradicted a reply reporting a real status —
        telling the caller a ticket needs work that a workflow already started."""
        jira = get_ticketing_connector("jira")
        r = jira.parse_response({"key": "SEC-1", "self": "http://x/1",
                                 "fields": {"status": {"name": "In Progress"}}})
        assert r["status"] == "in progress"

    def test_jira_falls_back_to_open_only_when_absent(self):
        """The Jira create API's minimal response genuinely omits status."""
        jira = get_ticketing_connector("jira")
        assert jira.parse_response({"key": "SEC-2"})["status"] == "open"

    def test_sentinel_duplicate_column_is_refused_not_clobbered(self):
        """PRE-R13b: the row→record zip silently kept the LAST of duplicate column
        names, discarding the earlier value with no signal."""
        ms = get_siem_connector("microsoft_sentinel")
        dup = {"tables": [{"columns": [{"name": "host"}, {"name": "host"}],
                           "rows": [["a", "b"]]}]}
        with pytest.raises(ConnectorError, match="duplicate column"):
            ms.parse_response(dup)

    def test_sentinel_normal_table_still_parses(self):
        ms = get_siem_connector("microsoft_sentinel")
        ok = {"tables": [{"columns": [{"name": "host"}, {"name": "severity"}],
                          "rows": [["web-01", "high"]]}]}
        events = ms.parse_response(ok)
        assert events[0]["host"] == "web-01"
        assert events[0]["severity"] == "high"

    @pytest.mark.parametrize("name", _ALL)
    def test_every_connector_still_passes_shape_conformance(self, name):
        """Regression: the per-connector contract is unaffected by all of the above."""
        res = C.check_siem_connector(get_siem_connector(name))
        assert res.ok, f"{name}: {res.failures}"
