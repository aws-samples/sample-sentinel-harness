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

from .base import (
    resolve_selector,
    DEFAULT_RESULT_LIMIT,
    ConnectorError,
    neutral_event,
)

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


# The fields a FREE-TEXT query may search (INV-CONNECTOR-6). Deliberately the neutral
# event's own field set — that is exactly the data this tool's contract exposes, so a
# free-text search cannot reach a document field the caller could not have selected
# directly. Passed to `simple_query_string.fields`, which otherwise defaults to `*`.
_FREE_TEXT_FIELDS = ("alert_id", "ts", "severity", "rule_name", "host",
                     "src_ip", "dst_ip", "technique", "summary")


def _escape_squote(value: str) -> str:
    """Escape a value for interpolation inside a single-quoted AQL string (QRadar).

    Doubles single quotes (``'`` → ``''``) — the standard SQL/AQL escaping — so
    the value cannot break out of the quoted literal.

    INV-CONNECTOR-8: a TRAILING BACKSLASH also has to be neutralised. Doubling quotes
    alone emitted::

        host = 'x\\' LIMIT 1000        for the value  x\\

    A parser that treats ``\\`` as an escape character reads ``\\'`` as a literal quote,
    so the closing delimiter is consumed and the rest of the statement — including the
    ``LIMIT`` clause — falls inside the string or shifts meaning. Whether Ariel actually
    honours backslash escapes is not something a caller's safety should depend on: the
    value is quoted for a dialect we do not control, so both plausible readings must be
    safe. Doubling the backslash makes the literal unambiguous under either.

    Order matters: backslashes FIRST, or the escaping introduced for quotes would then
    be re-escaped and change the value.
    """
    return value.replace("\\", "\\\\").replace("'", "''")


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
        kind, field, val = resolve_selector(selector, value)
        base = "search index=* sourcetype=alert"
        if kind == "match_all":
            spl = base
        elif kind == "time_floor":
            # SPL expresses a lower time bound natively; an equality on a `since`
            # FIELD (the pre-fix behaviour) matches nothing on a real backend.
            spl = f'{base} earliest="{_escape_dquote(val)}"'
        elif kind == "free_text":
            spl = f'{base} "{_escape_dquote(val)}"'
        else:
            spl = f'{base} {field}="{_escape_dquote(val)}"'
        return {"body": {"search": f"{spl} | head {DEFAULT_RESULT_LIMIT}",
                         "output_mode": "json"}, "path": ""}

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
        kind, field, val = resolve_selector(selector, value)
        query: Dict[str, Any]
        if kind == "match_all":
            query = {"match_all": {}}
        elif kind == "time_floor":
            # A lower time bound is a RANGE query, not a term on a `since` field.
            query = {"range": {"@timestamp": {"gte": val}}}
        elif kind == "free_text":
            # INV-CONNECTOR-6: `query_string` INTERPRETS Lucene syntax, so a
            # caller-supplied value was a query-language injection by construction —
            # the only such site among the 8 connectors, because the other seven place
            # the value inside a quoted literal and escape it (_escape_dquote /
            # _escape_squote). Here JSON quoting protects the transport and does
            # nothing about the DSL.
            #
            #     value "web-01 OR *"  ->  query_string: matches EVERY document
            #                              (the agent reads alerts for hosts outside
            #                               the one it asked about)
            #     value "x AND NOT x"  ->  matches NOTHING (an attack hidden, and the
            #                              empty result reads as good news)
            #
            # `simple_query_string` is the fix rather than escaping: it never throws on
            # malformed input and, with an explicit `flags` allowlist, the operators a
            # value can reach are enumerated instead of being whatever Lucene supports.
            # AND/OR/NOT and phrase quoting stay available — free text still works —
            # while field-scoping (`host:*`), ranges, regex (`/.../`) and boosting are
            # not parsed at all.
            query = {"simple_query_string": {
                "query": val,
                "flags": "AND|OR|NOT|PHRASE|WHITESPACE",
                # Without this a value naming a field the caller was not scoped to
                # would still be honoured by the default `*` field expansion.
                "fields": list(_FREE_TEXT_FIELDS),
                "default_operator": "and",
            }}
        else:
            query = {"term": {f"{field}.keyword": val}}
        return {"body": {"query": query, "size": DEFAULT_RESULT_LIMIT}, "path": "/_search"}

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
            # The document id lives at the HIT level, not inside _source. Reading
            # only _source discarded it, so two distinct documents that carry no
            # in-body id produced BYTE-IDENTICAL neutral events (alert_id "") —
            # they then dedupe into one, and an analyst cannot trace an alert back
            # to its document. Fold the hit-level _id in as a fallback, without
            # letting it override an id the document itself carries.
            if isinstance(source, dict) and hit.get("_id") is not None:
                if not any(source.get(k) is not None
                           for k in ("alert_id", "id", "event_id", "uid")):
                    source = {**source, "_id": hit["_id"]}
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
        kind, field, val = resolve_selector(selector, value)
        if kind == "match_all":
            aql = f"SELECT * FROM events LIMIT {DEFAULT_RESULT_LIMIT}"
        elif kind == "time_floor":
            # AQL expresses a lower bound with START; an equality on a `since`
            # FIELD matched nothing on a real QRadar.
            aql = (
                f"SELECT * FROM events START '{_escape_squote(val)}' "
                f"LIMIT {DEFAULT_RESULT_LIMIT}"
            )
        elif kind == "free_text":
            aql = (
                f"SELECT * FROM events WHERE TEXT SEARCH '{_escape_squote(val)}' "
                f"LIMIT {DEFAULT_RESULT_LIMIT}"
            )
        else:
            aql = (
                f"SELECT * FROM events WHERE {field} = '{_escape_squote(val)}' "
                f"LIMIT {DEFAULT_RESULT_LIMIT}"
            )
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
        kind, field, val = resolve_selector(selector, value)
        if kind == "match_all":
            kql = f"SecurityAlert | take {DEFAULT_RESULT_LIMIT}"
        elif kind == "time_floor":
            kql = (
                f'SecurityAlert | where TimeGenerated >= todatetime("{_escape_dquote(val)}") '
                f"| take {DEFAULT_RESULT_LIMIT}"
            )
        elif kind == "free_text":
            kql = (
                f'SecurityAlert | where * has "{_escape_dquote(val)}" '
                f"| take {DEFAULT_RESULT_LIMIT}"
            )
        else:
            kql = (
                f'SecurityAlert | where {field} == "{_escape_dquote(val)}" '
                f"| take {DEFAULT_RESULT_LIMIT}"
            )
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
        # DUPLICATE column names would make the row→record dict comprehension below
        # silently keep the LAST value and discard the earlier one — a data loss with
        # no signal, and (worse) non-deterministic in which value an analyst sees.
        # A duplicated column is a corrupt table, handled the same way as the
        # row/column length mismatch below: raise rather than quietly clobber.
        named = [n for n in col_names if n]
        if len(named) != len(set(named)):
            dupes = sorted({n for n in named if named.count(n) > 1})
            raise ConnectorError(
                f"Microsoft Sentinel table has duplicate column name(s) {dupes} — "
                "zipping rows would silently discard all but the last value"
            )
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


# --------------------------------------------------------------------------- #
# Google Chronicle / SecOps (UDM search → {"events": [{"udm": {...}}]})       #
# --------------------------------------------------------------------------- #
class ChronicleConnector:
    """Google Chronicle / SecOps connector. Query becomes a UDM search filter;
    results come back under ``events`` where each carries a nested ``udm`` object.

    build_request emits a UDM query string (escaped for the double-quoted literal);
    parse_response reads ``payload["events"]`` and maps each event's ``udm`` block
    (falling back to the event itself). A missing ``events`` key is a ConnectorError."""

    name = "chronicle"

    def build_request(self, selector: str, value: str) -> Dict[str, Any]:
        kind, field, val = resolve_selector(selector, value)
        if kind == "match_all":
            udm = "metadata.event_type != \"\""
        elif kind == "time_floor":
            udm = f'metadata.event_timestamp >= "{_escape_dquote(val)}"'
        elif kind == "free_text":
            udm = f'metadata.description = /{_escape_dquote(val)}/ nocase'
        else:
            udm = f'{field} = "{_escape_dquote(val)}"'
        # Bound the result set to the shared default (Chronicle carries the cap as a
        # request field, not in the query text) so every connector returns the same
        # number of rows for the same neutral query.
        return {"body": {"query": udm, "limit": DEFAULT_RESULT_LIMIT},
                "path": "/v1/events:udmSearch"}

    def parse_response(self, payload: Any) -> List[Dict[str, Any]]:
        if not isinstance(payload, dict) or "events" not in payload:
            raise ConnectorError("Chronicle reply missing 'events' envelope")
        rows = payload["events"]
        if not isinstance(rows, list):
            raise ConnectorError("Chronicle 'events' must be a list")
        out: List[Dict[str, Any]] = []
        for e in rows:
            if not isinstance(e, dict):
                raise ConnectorError("Chronicle event must be an object")
            out.append(_map_record(e.get("udm", e)))
        return out


# --------------------------------------------------------------------------- #
# Sumo Logic (search job → {"messages": [{"map": {...}}]})                    #
# --------------------------------------------------------------------------- #
class SumoLogicConnector:
    """Sumo Logic connector. Query becomes a search-query string; results come
    back under ``messages`` where each carries a flat ``map`` of fields.

    build_request emits a Sumo query (escaped); parse_response reads
    ``payload["messages"]`` and maps each message's ``map`` block."""

    name = "sumologic"

    def build_request(self, selector: str, value: str) -> Dict[str, Any]:
        kind, field, val = resolve_selector(selector, value)
        if kind == "match_all":
            q = f"_sourceCategory=* | limit {DEFAULT_RESULT_LIMIT}"
        elif kind == "time_floor":
            # Sumo carries the time range as request fields, not in the query text.
            q = f"_sourceCategory=* | limit {DEFAULT_RESULT_LIMIT}"
            return {"body": {"query": q, "from": val}, "path": "/api/v1/search/jobs"}
        elif kind == "free_text":
            q = f'_sourceCategory=* "{_escape_dquote(val)}" | limit {DEFAULT_RESULT_LIMIT}'
        else:
            q = f'{field}="{_escape_dquote(val)}" | limit {DEFAULT_RESULT_LIMIT}'
        return {"body": {"query": q}, "path": "/api/v1/search/jobs"}

    def parse_response(self, payload: Any) -> List[Dict[str, Any]]:
        if not isinstance(payload, dict) or "messages" not in payload:
            raise ConnectorError("Sumo Logic reply missing 'messages' envelope")
        rows = payload["messages"]
        if not isinstance(rows, list):
            raise ConnectorError("Sumo Logic 'messages' must be a list")
        out: List[Dict[str, Any]] = []
        for m in rows:
            if not isinstance(m, dict):
                raise ConnectorError("Sumo Logic message must be an object")
            out.append(_map_record(m.get("map", m)))
        return out


# --------------------------------------------------------------------------- #
# Datadog (security signals → {"data": [{"attributes": {...}}]})              #
# --------------------------------------------------------------------------- #
class DatadogConnector:
    """Datadog Cloud SIEM connector. Query becomes a signals search ``filter[query]``;
    results come back JSON:API style under ``data`` where each item carries an
    ``attributes`` object (often with a nested ``custom``/``attributes`` block).

    build_request emits the filter query; parse_response reads ``payload["data"]``
    and maps each item's ``attributes`` (merging a nested ``attributes`` sub-block
    if present, as Datadog signals nest event fields there)."""

    name = "datadog"

    def build_request(self, selector: str, value: str) -> Dict[str, Any]:
        kind, field, val = resolve_selector(selector, value)
        if kind == "match_all":
            q = "*"
        elif kind == "time_floor":
            # Datadog carries the time range as filter.from, not in the query text.
            return {"body": {"filter": {"query": "*", "from": val},
                             "page": {"limit": DEFAULT_RESULT_LIMIT}},
                    "path": "/api/v2/security_monitoring/signals/search"}
        elif kind == "free_text":
            q = f'"{_escape_dquote(val)}"'
        else:
            q = f'@{field}:"{_escape_dquote(val)}"'
        # Datadog carries the cap as a page[limit], not in the query text — bound it
        # to the shared default so its result set matches the other connectors'.
        return {"body": {"filter": {"query": q}, "page": {"limit": DEFAULT_RESULT_LIMIT}},
                "path": "/api/v2/security_monitoring/signals/search"}

    def parse_response(self, payload: Any) -> List[Dict[str, Any]]:
        if not isinstance(payload, dict) or "data" not in payload:
            raise ConnectorError("Datadog reply missing 'data' envelope")
        rows = payload["data"]
        if not isinstance(rows, list):
            raise ConnectorError("Datadog 'data' must be a list")
        out: List[Dict[str, Any]] = []
        for item in rows:
            if not isinstance(item, dict):
                raise ConnectorError("Datadog data item must be an object")
            attrs = item.get("attributes", item)
            if not isinstance(attrs, dict):
                raise ConnectorError("Datadog item attributes must be an object")
            # Datadog nests some event fields under attributes.attributes for
            # signals. Merge so the TOP-LEVEL attrs WIN on any key collision (the
            # nested sub-block only FILLS keys the top level lacks) — otherwise the
            # raw sub-block clobbered a real top-level value (e.g. severity → '').
            nested = attrs.get("attributes")
            nested = nested if isinstance(nested, dict) else {}
            merged = {**nested, **{k: v for k, v in attrs.items() if k != "attributes"}}
            out.append(_map_record(merged))
        return out
