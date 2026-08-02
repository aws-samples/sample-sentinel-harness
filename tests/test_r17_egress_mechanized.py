"""
Round-17 part 2 — mechanizing the egress guard, and the connector injection audit.
=================================================================================
Round 16 found two SSRF defects in ``ops_query``, fixed them there, and recorded
INV-OPS-5. Round 17 then found **the identical pair in ``siem_query``**:

  1. the range check called ``ipaddress.ip_address()`` directly, so
     ``http://2852039166/`` / ``http://0xA9FEA9FE/`` / ``http://0251.0376.0251.0376/``
     — all three are 169.254.169.254, the cloud metadata service — fell through as if
     they were DNS names;
  2. bare ``urlopen`` follows 3xx, so an allowed backend answering
     ``302 Location: http://169.254.169.254/...`` had the client fetch the metadata
     service AND forward its ``Authorization: Bearer`` header to it.

Both reproduced end to end. That is the **fourth** time a fixed defect returned in this
codebase by the same route: the fix was applied to one call site instead of being made a
mechanism (see INV-COERCE for the other three).

A survey settled it — of the eight tools that open outbound HTTP, exactly one was
complete::

    tool             url guard   redirect refused   alt-IP parsing
    ops_query           yes            yes               yes
    siem_query          yes            NO                NO
    asset_lookup        yes            NO                NO
    enrich_ioc          yes            NO                NO
    web_search          yes            NO                NO
    nvd_lookup          NO             NO                NO
    epss_kev            NO             NO                NO
    attack_lookup       NO             NO                NO

So the guard now lives in ``sentinel_harness/egress.py``, once, and this module fails
the build if a live path opens a socket without it.

The connector half of the round
-------------------------------
The 8 SIEM connectors were audited on QUERY INJECTION, a dimension round 13b did not
cover (it looked at selector semantics and response fidelity). Result:

- Seven of eight place the caller's value inside a QUOTED LITERAL and escape it
  (``_escape_dquote`` for SPL/KQL/UDM/Sumo/Datadog, ``_escape_squote`` for AQL). Those
  were audited and fixed earlier; the tests below pin them so they stay fixed.
- **Elastic and OpenSearch put a free-text value into ``query_string``, which
  INTERPRETS Lucene syntax** — injection by construction, and the only such site. JSON
  quoting protects the transport and does nothing about the DSL.

Zero network for the guard tests (they call the checks directly) and zero network for
the connector tests (``build_request`` is a pure translator that returns a dict).
"""
from __future__ import annotations

import ast
import os
import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

os.environ.setdefault("SENTINEL_REGION", "us-east-1")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("SENTINEL_EXECUTION_ROLE_ARN",
                      "arn:aws:iam::000000000000:role/test-harness-role")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")

from sentinel_harness import egress  # noqa: E402
from sentinel_harness.connectors import (  # noqa: E402
    available_siem_connectors, get_siem_connector,
)

# Every tool that opens outbound HTTP. Hardcoded rather than discovered so that ADDING
# a live path forces a decision here — a new tool silently escaping the sweep is the
# failure mode this module exists to prevent.
_LIVE_PATH_TOOLS = (
    "siem_query", "ops_query", "asset_lookup", "enrich_ioc",
    "web_search", "nvd_lookup", "epss_kev", "attack_lookup",
)

# Alternate spellings of 169.254.169.254, the cloud metadata service.
_METADATA_SPELLINGS = (
    "169.254.169.254",
    "2852039166",              # decimal
    "0xA9FEA9FE",              # hex
    "0251.0376.0251.0376",     # dotted octal
)


def _tool_source(name: str) -> str:
    return (REPO_ROOT / "tools" / name / "handler.py").read_text(encoding="utf-8")


# The body key each string-DSL connector puts its query under. Explicit rather than
# "find the longest string", so a connector that renames its key fails loudly here
# instead of having its query silently unchecked.
_QUERY_BODY_KEYS = ("search", "query", "query_expression")

# The quote character each string-DSL backend uses to delimit a value literal — the
# only one whose parity means anything. QRadar's AQL is single-quoted (so a double
# quote in a value is inert); the rest are double-quoted (so a single quote is inert).
# Mapping this explicitly is what turned a noisy assertion into a meaningful one.
_DELIMITER = {
    "splunk": '"',
    "microsoft_sentinel": '"',
    "chronicle": '"',
    "sumologic": '"',
    "datadog": '"',
    "qradar": "'",
}


def _query_text(request: dict) -> str:
    """Extract the DSL query string a connector emitted.

    Needed because asserting on `str(request)` measures Python's repr escaping rather
    than the query's own — a false alarm that flagged all seven correctly-escaped
    backends before it was caught.
    """
    body = request.get("body")
    assert isinstance(body, dict), f"request has no body dict: {request!r}"
    for key in _QUERY_BODY_KEYS:
        value = body.get(key)
        if isinstance(value, str):
            return value
        # Datadog nests it: {"filter": {"query": ...}}
        if isinstance(value, dict) and isinstance(value.get("query"), str):
            return value["query"]
    nested = body.get("filter")
    if isinstance(nested, dict) and isinstance(nested.get("query"), str):
        return nested["query"]
    raise AssertionError(
        f"no query string found under {_QUERY_BODY_KEYS} in {body!r} — a connector "
        "renamed its body key, so its query would go unchecked"
    )


# --------------------------------------------------------------------------- #
# INV-EGRESS-1 — every live path opens through the ONE shared guard           #
# --------------------------------------------------------------------------- #
class TestEveryLivePathUsesTheSharedGuard:
    """The structural half. A behavioural test proves one tool is right today; this
    fails when a NEW tool — or a refactor of an old one — opens a socket directly."""

    def test_the_tool_inventory_is_complete(self):
        """Guard the guard: if a tool that opens HTTP is missing from
        `_LIVE_PATH_TOOLS`, every assertion below silently stops covering it."""
        opens_http = set()
        for path in sorted((REPO_ROOT / "tools").rglob("handler.py")):
            source = path.read_text(encoding="utf-8")
            if "urlopen" in source or "open_checked" in source:
                opens_http.add(path.parent.name)
        missing = sorted(opens_http - set(_LIVE_PATH_TOOLS))
        assert not missing, (
            f"tool(s) open outbound HTTP but are not in _LIVE_PATH_TOOLS: {missing}. "
            "Add them — an unlisted live path is exempt from every check here."
        )
        assert len(opens_http) >= 8, f"only found {len(opens_http)} live paths"

    @pytest.mark.parametrize("tool", _LIVE_PATH_TOOLS)
    def test_no_live_path_calls_urlopen_directly(self, tool):
        """`urllib.request.urlopen` follows redirects. Using it at all re-opens the
        credential-forwarding hole, regardless of how carefully the first URL was
        vetted — which is exactly how siem_query was vulnerable while having a guard.
        """
        tree = ast.parse(_tool_source(tool))
        offenders = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr == "urlopen":
                offenders.append(node.lineno)
            elif isinstance(func, ast.Name) and func.id == "urlopen":
                offenders.append(node.lineno)
        assert not offenders, (
            f"tools/{tool}/handler.py calls urlopen directly at line(s) {offenders}. "
            "Use `sentinel_harness.egress.open_checked(request, timeout=...)`, which "
            "vets the URL and refuses redirects in one call."
        )

    @pytest.mark.parametrize("tool", _LIVE_PATH_TOOLS)
    def test_every_live_path_imports_the_shared_guard(self, tool):
        source = _tool_source(tool)
        assert "from sentinel_harness import egress" in source, (
            f"tools/{tool}/handler.py does not import the shared egress guard"
        )
        assert "egress.open_checked" in source, (
            f"tools/{tool}/handler.py imports the guard but never opens through it"
        )

    @pytest.mark.parametrize("tool", ("siem_query", "ops_query"))
    def test_no_tool_reimplements_the_ip_parser(self, tool):
        """The two tools that HAD their own copy must now delegate. A local
        `ipaddress.ip_address(host)` in a range check is the exact defect."""
        source = _tool_source(tool)
        assert "egress.parse_ip_literal" in source or "egress.assert_safe_url" in source
        # The give-away pattern: parsing the host locally to range-check it.
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "ip_address"):
                pytest.fail(
                    f"tools/{tool}/handler.py calls ipaddress.ip_address() at line "
                    f"{node.lineno} — that parses only dotted-quad/IPv6 and misses "
                    "the decimal/hex/octal spellings of 169.254.169.254. Delegate to "
                    "egress.parse_ip_literal."
                )


# --------------------------------------------------------------------------- #
# INV-EGRESS-2 — the guard's own behaviour                                    #
# --------------------------------------------------------------------------- #
class TestTheSharedGuardBehaviour:

    @pytest.mark.parametrize("spelling", _METADATA_SPELLINGS)
    def test_every_spelling_of_the_metadata_address_is_refused(self, spelling):
        with pytest.raises(egress.EgressError):
            egress.assert_safe_url(f"http://{spelling}/latest/meta-data/")

    @pytest.mark.parametrize("spelling", _METADATA_SPELLINGS)
    def test_the_parser_resolves_every_spelling_to_the_same_address(self, spelling):
        import ipaddress
        assert egress.parse_ip_literal(spelling) == \
            ipaddress.ip_address("169.254.169.254")

    @pytest.mark.parametrize("url", [
        "file:///etc/passwd",
        "gopher://example.com/",
        "ftp://example.com/x",
        "https://evil@169.254.169.254/",       # userinfo prefix
        "http://[::ffff:169.254.169.254]/",    # IPv4-mapped IPv6
        "http://0.0.0.0/",                     # unspecified
        "http://224.0.0.1/",                   # multicast
    ])
    def test_other_dangerous_targets_are_refused(self, url):
        with pytest.raises(egress.EgressError):
            egress.assert_safe_url(url)

    @pytest.mark.parametrize("url", [
        "https://siem.example.com/services/search",
        "http://siem.internal:8089/q",
        "http://127.0.0.1:8080/q",     # a self-hosted backend / the test mock
        "https://1backend.example.com/q",   # a DNS name that STARTS with a digit
    ])
    def test_legitimate_backends_are_allowed(self, url):
        """CONTROL: over-refusing is how a guard gets removed by the people it blocks."""
        egress.assert_safe_url(url)

    @pytest.mark.parametrize("host", ["ops.example.com", "1backend.example.com",
                                      "8080.example.net", "localhost", ""])
    def test_the_parser_does_not_misread_a_dns_name_as_an_ip(self, host):
        assert egress.parse_ip_literal(host) is None, host

    def test_a_redirect_is_refused_with_an_explanation(self):
        handler = egress._NoRedirect()
        with pytest.raises(egress.EgressError, match="refusing to follow"):
            handler.redirect_request(
                None, None, 302, "Found", {},
                "http://169.254.169.254/latest/meta-data/")

    def test_the_opener_installs_the_no_redirect_handler(self):
        """Pin the WIRING: `_NoRedirect` existing but not installed would leave the
        hole open while looking fixed."""
        opener = egress.build_opener()
        assert any(isinstance(h, egress._NoRedirect) for h in opener.handlers)

    def test_egress_error_is_a_runtime_error(self):
        """Handlers map RuntimeError to `upstream_error`; EgressError must inherit so
        the refusal surfaces as an upstream failure, never a silent empty result."""
        assert issubclass(egress.EgressError, RuntimeError)


# --------------------------------------------------------------------------- #
# INV-CONNECTOR-6 — a free-text value is not a query language                 #
# --------------------------------------------------------------------------- #
class TestConnectorQueryInjection:
    """The connector half of round 17.

    Seven of eight connectors place the caller's value inside a quoted literal and
    escape it. Elastic and OpenSearch put a free-text value into `query_string`, which
    INTERPRETS Lucene — so `web-01 OR *` widened the query to match every document, and
    `x AND NOT x` narrowed it to match none. The first leaks alerts for hosts the agent
    did not ask about; the second hides an attack behind an empty result that reads as
    good news.
    """

    # Values that try to change what the query MEANS, in both directions.
    _WIDENING = ("web-01 OR *", "web-01 OR host:*", "web-01 OR _index:*",
                 "web-01 OR severity:[* TO *]", "web-01 OR /.*/")
    _NARROWING = ("web-01 AND NOT web-01", "web-01 AND severity:__nope__")

    @pytest.mark.parametrize("backend", ("elastic", "opensearch"))
    def test_free_text_does_not_use_query_string(self, backend):
        """`query_string` parses the full Lucene grammar including field scoping,
        ranges, regex and boosting. `simple_query_string` with an explicit `flags`
        allowlist enumerates what a value can reach instead."""
        query = get_siem_connector(backend).build_request("query", "web-01")["body"]["query"]
        assert "query_string" not in query, (
            "free text is back on query_string, which interprets Lucene syntax"
        )
        assert "simple_query_string" in query

    @pytest.mark.parametrize("backend", ("elastic", "opensearch"))
    def test_the_operator_set_is_explicitly_bounded(self, backend):
        query = get_siem_connector(backend).build_request("query", "web-01")["body"]["query"]
        sqs = query["simple_query_string"]
        assert "flags" in sqs, "without `flags`, every simple-query operator is live"
        flags = set(sqs["flags"].split("|"))
        # The operators free text genuinely needs...
        assert {"AND", "OR", "NOT", "PHRASE", "WHITESPACE"} <= flags
        # ...and none of the ones that reach beyond the caller's scope.
        assert not ({"PREFIX", "PRECEDENCE", "ESCAPE", "SLOP", "FUZZY", "NEAR", "ALL"}
                    & flags)

    @pytest.mark.parametrize("backend", ("elastic", "opensearch"))
    def test_the_searchable_fields_are_bounded(self, backend):
        """Without an explicit `fields`, `simple_query_string` expands to `*` — so a
        value naming a document field outside the neutral event shape would still be
        honoured."""
        query = get_siem_connector(backend).build_request("query", "web-01")["body"]["query"]
        fields = query["simple_query_string"].get("fields")
        assert fields, "no field allowlist: the query expands to every document field"
        assert "host" in fields and "summary" in fields
        assert "*" not in fields

    @pytest.mark.parametrize("backend", ("elastic", "opensearch"))
    @pytest.mark.parametrize("value", _WIDENING + _NARROWING)
    def test_a_field_selector_keeps_a_hostile_value_literal(self, backend, value):
        """CONTROL, and the reassuring half: on a FIELD selector the value lands in a
        `term`, which does not interpret syntax at all."""
        query = get_siem_connector(backend).build_request("host", value)["body"]["query"]
        assert "term" in query
        assert query["term"]["host.keyword"] == value

    @pytest.mark.parametrize("backend", [
        b for b in available_siem_connectors() if b not in ("elastic", "opensearch")
    ])
    @pytest.mark.parametrize("value", [
        'x" | delete index=*',          # SPL command injection
        "x' OR 1=1 --",                 # AQL
        'x" or true',                    # KQL
        "x' OR TRUE OR '",
        'x\\" | stats count',            # a pre-escaped quote
        "x\\",                           # a trailing backslash
    ])
    def test_a_string_dsl_connector_escapes_a_breakout_attempt(self, backend, value):
        """The seven quoted-literal backends. An earlier round added
        `_escape_dquote`/`_escape_squote`; this pins that the escaping survives.

        THE ASSERTION HAD TO BE REWRITTEN, and the reason is worth recording: my first
        version checked that the emitted query does not CONTAIN `'" | '`. That flagged
        all seven backends — on output that was correctly escaped. Chronicle emitted

            host = "x\\" | delete index=*"

        where the quote IS backslash-escaped and cannot close the literal; my substring
        matched the `" | ` inside `\\" | `. QRadar was flagged for a DOUBLE quote in a
        SINGLE-quoted AQL literal, where it is not a metacharacter at all.

        That was the sixth time substring-matching stood in for a structural judgement
        in this repo (see INV-COERCE's note). The correct question is not "does a quote
        appear before an operator" but **"is any quote UNESCAPED inside the literal"** —
        so the check now walks the emitted string and counts quote characters that are
        not preceded by a backslash, per the quoting style that connector uses.
        """
        request = get_siem_connector(backend).build_request("host", value)
        # Take the QUERY STRING itself, not `str(request)`. Counting quotes on the
        # repr of a dict was a second false alarm on top of the first: `str()` adds
        # Python's own escaping layer, so I was measuring the repr's quotes rather
        # than the DSL's. The lesson generalizes — when checking a property of an
        # emitted artifact, extract the artifact.
        emitted = _query_text(request)

        def unescaped_count(text: str, quote: str) -> int:
            total = 0
            index = 0
            while index < len(text):
                char = text[index]
                if char == "\\":
                    index += 2          # the escape consumes the next character
                    continue
                if char == quote:
                    total += 1
                index += 1
            return total

        # Check ONLY the quote character this backend uses as its literal delimiter.
        # Checking both was the third refinement of this assertion: a double quote
        # inside single-quoted AQL — and a single quote inside double-quoted SPL/KQL —
        # is not a metacharacter, so an odd count of it is perfectly normal and flagged
        # QRadar for `x" or true`, which is entirely safe.
        #
        # A well-formed query has an EVEN number of unescaped delimiters: they pair up.
        # A value that broke out leaves an odd count, because its own quote closed a
        # literal nothing reopened.
        quote = _DELIMITER[backend]
        count = unescaped_count(emitted, quote)
        assert count % 2 == 0, (
            f"{backend} emitted an ODD number ({count}) of unescaped {quote!r} for "
            f"value {value!r} — the value closed a literal it did not reopen:\n"
            f"  {emitted}"
        )
        # And the value must still be present in SOME form: escaping, not dropping. A
        # connector that silently discarded the value would pass every check above.
        leading = value.split('"')[0].split("'")[0].rstrip("\\")
        if leading:
            assert leading in emitted, (
                f"{backend} dropped the value entirely: {emitted}"
            )

    @pytest.mark.parametrize("backend", available_siem_connectors())
    def test_a_benign_value_still_reaches_the_query(self, backend):
        """CONTROL: escaping must not drop the value — a connector that emits nothing
        would pass every injection test above while being useless."""
        emitted = str(get_siem_connector(backend).build_request("host", "web-01"))
        assert "web-01" in emitted

    def test_the_injection_harness_can_detect_a_regression(self):
        """POSITIVE CONTROL for the escaping tests: with escaping removed, the
        breakout assertion must fire. Without this, a change that neuters
        `_escape_dquote` would leave every test above passing vacuously.
        """
        from sentinel_harness.connectors import siem
        original = siem._escape_dquote
        siem._escape_dquote = lambda value: value      # the defect, re-injected
        try:
            emitted = _query_text(get_siem_connector("splunk").build_request(
                "host", 'x" | delete index=*'))

            def unescaped_count(text: str, quote: str) -> int:
                total, index = 0, 0
                while index < len(text):
                    if text[index] == "\\":
                        index += 2
                        continue
                    if text[index] == quote:
                        total += 1
                    index += 1
                return total

            assert unescaped_count(emitted, '"') % 2 == 1, (
                "with escaping disabled the quote count is still even, so the "
                "assertion above cannot detect a breakout and proves nothing:\n"
                f"  {emitted[:200]}"
            )
        finally:
            siem._escape_dquote = original


# --------------------------------------------------------------------------- #
# INV-CONNECTOR-7 — the connectors carry no credentials                       #
# --------------------------------------------------------------------------- #
class TestConnectorsHoldNoCredentials:
    """The connectors' module docstring says "Nothing here carries an endpoint, index
    name, token, or tenant". That is a self-certified claim of exactly the kind round
    16 audited, so it is checked rather than trusted.

    It matters because `build_request`'s return value travels up the call stack, into
    error messages and (in the scenarios) into evidence files.
    """

    @pytest.mark.parametrize("backend", available_siem_connectors())
    def test_build_request_returns_no_credential_material(self, backend):
        request = get_siem_connector(backend).build_request("host", "web-01")
        flat = str(request).lower()
        for marker in ("authorization", "bearer", "token", "api_key", "apikey",
                       "password", "secret"):
            assert marker not in flat, (
                f"{backend}.build_request returned something containing {marker!r}: "
                f"{str(request)[:160]}"
            )

    def test_the_connector_module_reads_no_environment_variable(self):
        """A connector that reached for an env var would be holding a secret, and
        would also stop being the pure translator the conformance suite assumes."""
        source = (REPO_ROOT / "sentinel_harness" / "connectors" / "siem.py").read_text()
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr == "environ":
                pytest.fail(f"connectors/siem.py reads os.environ at line {node.lineno}")
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "getenv"):
                pytest.fail(f"connectors/siem.py calls getenv at line {node.lineno}")

    def test_the_connector_module_opens_no_socket(self):
        """The pure-translator contract: build_request returns a dict, it does not send
        it. If this ever changes, every injection finding above becomes live rather
        than latent, and the severity of this whole family changes."""
        source = (REPO_ROOT / "sentinel_harness" / "connectors" / "siem.py").read_text()
        for forbidden in ("urlopen", "requests.", "socket.socket", "http.client"):
            assert forbidden not in source, (
                f"connectors/siem.py now contains {forbidden!r} — it is no longer a "
                "pure translator, and the injection tests above describe a LIVE "
                "vulnerability rather than a latent one"
            )
