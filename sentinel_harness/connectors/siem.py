"""
sentinel-harness · SIEM/search connectors (Splunk · Elastic · OpenSearch)
=========================================================================
Concrete, plug-and-play translators between sentinel's neutral query/event shape
and the three most common SIEM/search backends. Pure translation — NO network
(see ``connectors/base.py``). An adopter picks one via ``SIEM_QUERY_CONNECTOR``.

Each connector knows two things about its backend:
  1. how to phrase sentinel's ``(selector, value)`` query as the backend's native
     request body (+ any URL path suffix), and
  2. how to dig the events out of the backend's response envelope and map each to
     the neutral 10-field event.

Field mapping is deliberately permissive on the READ side (a backend record may
name a field ``rule``/``signature``/``rule_name``; a source IP ``src_ip``/
``source.ip``/``src``) so a connector tolerates real-world field-name drift, then
funnels everything through :func:`base.neutral_event` for a guaranteed shape.

Nothing here carries an endpoint, index name, token, or tenant — only the vendor's
public API shape.
"""
from __future__ import annotations

from typing import Any, Dict, List

from .base import ConnectorError, neutral_event

# --------------------------------------------------------------------------- #
# permissive field extraction (shared by the SIEM connectors)                 #
# --------------------------------------------------------------------------- #
# Each neutral field maps from a list of candidate source keys, tried in order.
# Dotted keys (e.g. "source.ip") are resolved through nested dicts. This is what
# lets one connector absorb the common field-name variants a real backend emits.
_FIELD_CANDIDATES: Dict[str, List[str]] = {
    "alert_id": ["alert_id", "id", "_id", "event_id", "uid"],
    "ts": ["ts", "timestamp", "@timestamp", "_time", "time"],
    "severity": ["severity", "level", "priority", "urgency"],
    "rule_name": ["rule_name", "rule", "signature", "search_name", "rule.name"],
    "host": ["host", "hostname", "dest_host", "asset", "host.name"],
    "src_ip": ["src_ip", "src", "source_ip", "source.ip", "src.ip"],
    "dst_ip": ["dst_ip", "dest", "dest_ip", "destination.ip", "dst.ip"],
    "technique": ["technique", "mitre_technique", "attack_technique", "technique_id"],
    "summary": ["summary", "raw_summary", "message", "_raw", "description"],
    "false_positive": ["false_positive", "is_fp", "fp"],
}


def _dig(record: Dict[str, Any], dotted: str) -> Any:
    """Resolve a possibly-dotted key through nested dicts; return None if absent."""
    cur: Any = record
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _lookup(record: Dict[str, Any], key: str) -> Any:
    """Return the value for ``key`` from a record, tolerating BOTH shapes a real
    backend uses for a dotted field: a LITERAL flat key (``{"host.name": "x"}``,
    common in flattened Splunk/ECS exports) AND a NESTED path
    (``{"host": {"name": "x"}}``, common in raw ES ``_source``).

    Tries the literal key first, then the nested walk. A resolved value that is
    itself a dict (from EITHER branch — e.g. a doubly-nested ``host.name.fqdn``)
    is rejected so a bare object never lands in a scalar neutral field."""
    if key in record:
        val = record[key]
        return None if isinstance(val, dict) else val
    if "." in key:
        val = _dig(record, key)
        return None if isinstance(val, dict) else val  # guard the nested branch too
    return None


def _map_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """Map one backend record to the neutral event via the candidate table."""
    if not isinstance(record, dict):
        raise ConnectorError(f"expected an object event, got {type(record).__name__}")
    mapped: Dict[str, Any] = {}
    for field, candidates in _FIELD_CANDIDATES.items():
        for key in candidates:
            val = _lookup(record, key)
            if val is not None:
                mapped[field] = val
                break
    return neutral_event(mapped)


# --------------------------------------------------------------------------- #
# Splunk                                                                       #
# --------------------------------------------------------------------------- #
# --------------------------------------------------------------------------- #
# DSL escaping helpers — the audit-confirmed injection fix                    #
# --------------------------------------------------------------------------- #
def _escape_dquote(value: str) -> str:
    """Escape a value for interpolation inside a double-quoted DSL string (SPL/KQL).

    Backslash-escapes ``\\`` then ``"`` so the value cannot break out of the quoted
    literal and inject arbitrary DSL commands. This is the fix for the audited
    SPL/KQL injection finding (a value like `x" | delete index=*` would previously
    close the quote and append an arbitrary command)."""
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _escape_squote(value: str) -> str:
    """Escape a value for interpolation inside a single-quoted AQL string (QRadar).

    Doubles single quotes (``'`` → ``''``) — the standard SQL/AQL escaping — so
    the value cannot break out of the quoted literal."""
    return value.replace("'", "''")


class SplunkConnector:
    """Splunk connector. Query becomes an SPL search over a configurable index;
    results come back under ``results`` (the Splunk search-results envelope).

    build_request emits an SPL string in the body (the tool posts it to the
    search endpoint); parse_response reads ``payload["results"]`` (a list of
    result rows) and maps each. A missing ``results`` key is a ConnectorError —
    an empty search returns ``{"results": []}``, never a bare list, so absence of
    the key means a malformed/error reply, not zero hits."""

    name = "splunk"

    def build_request(self, selector: str, value: str) -> Dict[str, Any]:
        if selector == "*":
            spl = "search index=* sourcetype=alert"
        else:
            spl = f'search index=* sourcetype=alert {selector}="{_escape_dquote(value)}"'
        return {"body": {"search": spl, "output_mode": "json"}, "path": ""}

    def parse_response(self, payload: Any) -> List[Dict[str, Any]]:
        if not isinstance(payload, dict) or "results" not in payload:
            raise ConnectorError("Splunk reply missing 'results' envelope")
        rows = payload["results"]
        if not isinstance(rows, list):
            raise ConnectorError("Splunk 'results' must be a list")
        return [_map_record(r) for r in rows]


# --------------------------------------------------------------------------- #
# Elasticsearch / OpenSearch (same hits.hits[]._source envelope)              #
# --------------------------------------------------------------------------- #
class _EsFamilyConnector:
    """Shared logic for Elasticsearch & OpenSearch — identical query DSL +
    ``hits.hits[]._source`` response envelope.

    build_request emits an ES ``query`` DSL (``match_all`` for ``*``, else a
    ``term`` filter); parse_response walks ``payload["hits"]["hits"]`` and maps
    each hit's ``_source``. A missing ``hits.hits`` path is a ConnectorError."""

    name = "_es_family"

    def build_request(self, selector: str, value: str) -> Dict[str, Any]:
        if selector == "*":
            query: Dict[str, Any] = {"match_all": {}}
        else:
            query = {"term": {f"{selector}.keyword": value}}
        return {"body": {"query": query, "size": 1000}, "path": "/_search"}

    def parse_response(self, payload: Any) -> List[Dict[str, Any]]:
        if not isinstance(payload, dict):
            raise ConnectorError(f"{self.name} reply must be an object")
        hits = payload.get("hits")
        if not isinstance(hits, dict) or not isinstance(hits.get("hits"), list):
            raise ConnectorError(f"{self.name} reply missing hits.hits[] envelope")
        out: List[Dict[str, Any]] = []
        for hit in hits["hits"]:
            if not isinstance(hit, dict):
                raise ConnectorError(f"{self.name} hit must be an object")
            source = hit.get("_source", hit)
            out.append(_map_record(source))
        return out


class ElasticConnector(_EsFamilyConnector):
    """Elasticsearch connector (``hits.hits[]._source``)."""

    name = "elastic"


class OpenSearchConnector(_EsFamilyConnector):
    """OpenSearch connector — same DSL/envelope as Elasticsearch."""

    name = "opensearch"


# --------------------------------------------------------------------------- #
# IBM QRadar (AQL → {"events": [...]})                                        #
# --------------------------------------------------------------------------- #
class QRadarConnector:
    """IBM QRadar connector. Query becomes an AQL SELECT over the events table;
    results come back as ``{"events": [ {...}, ... ]}`` (QRadar Ariel search
    result envelope).

    build_request emits the AQL string; parse_response reads ``payload["events"]``.
    A missing ``events`` key is a ConnectorError (an empty search returns
    ``{"events": []}``, never a bare list)."""

    name = "qradar"

    def build_request(self, selector: str, value: str) -> Dict[str, Any]:
        if selector == "*":
            aql = "SELECT * FROM events LAST 24 HOURS"
        else:
            aql = f"SELECT * FROM events WHERE {selector} = '{_escape_squote(value)}' LAST 24 HOURS"
        return {"body": {"query_expression": aql}, "path": "/api/ariel/searches"}

    def parse_response(self, payload: Any) -> List[Dict[str, Any]]:
        if not isinstance(payload, dict) or "events" not in payload:
            raise ConnectorError("QRadar reply missing 'events' envelope")
        rows = payload["events"]
        if not isinstance(rows, list):
            raise ConnectorError("QRadar 'events' must be a list")
        return [_map_record(r) for r in rows]


# --------------------------------------------------------------------------- #
# Microsoft Sentinel / Log Analytics (KQL → columnar tables[].rows[])         #
# --------------------------------------------------------------------------- #
class MicrosoftSentinelConnector:
    """Microsoft Sentinel (Log Analytics) connector. Query becomes KQL; results
    come back COLUMNAR — ``{"tables": [{"columns": [{"name": ...}], "rows":
    [[v0, v1, ...]]}]}`` — NOT a list of objects. This exercises the connector
    framework's flexibility: parse_response zips each row against the column names
    into a dict before mapping to the neutral event.

    build_request emits a KQL string; parse_response reads the FIRST table's
    columns+rows. A missing ``tables[0]`` with ``columns``/``rows`` is a
    ConnectorError."""

    name = "microsoft_sentinel"

    def build_request(self, selector: str, value: str) -> Dict[str, Any]:
        if selector == "*":
            kql = "SecurityAlert | take 1000"
        else:
            kql = f'SecurityAlert | where {selector} == "{_escape_dquote(value)}" | take 1000'
        return {"body": {"query": kql}, "path": "/v1/query"}

    def parse_response(self, payload: Any) -> List[Dict[str, Any]]:
        if not isinstance(payload, dict) or not isinstance(payload.get("tables"), list):
            raise ConnectorError("Microsoft Sentinel reply missing 'tables' list")
        tables = payload["tables"]
        if not tables:
            return []
        table = tables[0]
        if not isinstance(table, dict) or "columns" not in table or "rows" not in table:
            raise ConnectorError("Microsoft Sentinel table missing columns/rows")
        columns = table["columns"]
        rows = table["rows"]
        if not isinstance(columns, list) or not isinstance(rows, list):
            raise ConnectorError("Microsoft Sentinel columns/rows must be lists")
        # Column entries may be {"name": "..."} objects or bare strings.
        col_names = [
            (c.get("name") if isinstance(c, dict) else str(c)) for c in columns
        ]
        out: List[Dict[str, Any]] = []
        for row in rows:
            if not isinstance(row, list):
                raise ConnectorError("Microsoft Sentinel row must be a list of values")
            # A row must line up with the columns; a length mismatch is a corrupt
            # table, not a partial event — raise rather than silently dropping/
            # defaulting columns (audited: silent partial-event acceptance).
            if len(row) != len(col_names):
                raise ConnectorError(
                    f"Microsoft Sentinel row/column length mismatch: "
                    f"{len(row)} values vs {len(col_names)} columns"
                )
            # zip row values to column names → a record dict → neutral event.
            record = {name: row[i] for i, name in enumerate(col_names) if name}
            out.append(_map_record(record))
        return out
