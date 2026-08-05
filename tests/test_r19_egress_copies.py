"""
Round-19 — INV-EGRESS-3: no module keeps its own host range-check.
=================================================================
Round 16 found an SSRF pair in ``ops_query`` and fixed it there. Round 17 found the
IDENTICAL pair in ``siem_query``, concluded that "a fix applied to one call site is not
an invariant", and built ``test_r17_egress_mechanized.py`` to make it a mechanism.

That guard's parser check was parameterized over ``("siem_query", "ops_query")``.

The two tools that had already been found. So round 19 asked the guard's own question of
the guard — which modules were never checked? — and found **four** more local copies:

    tools/asset_lookup/handler.py     _assert_safe_url  (shadowed by open_checked)
    tools/enrich_ioc/handler.py       _assert_safe_url  (shadowed by open_checked)
    tools/web_search/handler.py       _assert_safe_url  (shadowed by open_checked)
    sentinel_harness/gateway.py       _validate_discovery_url  (NOT shadowed)

All four called ``ipaddress.ip_address()``, which parses only dotted-quad / standard
IPv6, so every alternate spelling of a forbidden address walked past their range checks
as if it were a DNS name. Reproduced against each.

Why the fourth is the serious one
---------------------------------
The three tool-side copies ran in front of ``egress.open_checked``, which re-vets with
the strong predicate — so they were a staged regression (the next refactor reasoning
"already vetted here" restores the hole), not a live one.

``gateway._validate_discovery_url`` has no downstream recheck. It is the only gate
between a config value and ``customJWTAuthorizer.discoveryUrl`` — the OIDC discovery
document, which tells the gateway **which public keys sign a valid token**. It also
blocks loopback, a stricter policy than the egress guard's, and six hosts defeated it::

    https://2852039166/...           169.254.169.254  (decimal)
    https://0xA9FEA9FE/...           169.254.169.254  (hex)
    https://0251.0376.0251.0376/...  169.254.169.254  (octal)
    https://2130706433/...           127.0.0.1        (decimal)
    https://0x7f000001/...           127.0.0.1        (hex)
    https://0177.0.0.01/...          127.0.0.1        (octal)

A reviewer reading the resulting config sees a plausible number. The docstring's promise
— "an identity provider must be a real, externally-verifiable endpoint" — did not hold.

The split this module enforces
------------------------------
**Parser shared, policy local.** The parser was wrong in all four copies; the policy is
what legitimately differs (the gateway requires https and refuses loopback; a
self-hosted SIEM at 127.0.0.1 is a valid backend). Demanding that every caller delegate
the whole check would have been wrong and would have been routed around.

Zero network, zero AWS.
"""
from __future__ import annotations

import ast
import pathlib

import pytest

import child_pytest
from sentinel_harness import egress, gateway

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

# Every tree that can hold a host check. INV-EGRESS-1's sweep looked only at `tools/`,
# which is why the gateway copy — the one without a downstream recheck — was invisible
# to it for two rounds.
_SWEPT_TREES = ("tools", "sentinel_harness", "intake")

# The module that is ALLOWED to parse an IP literal itself: the shared parser.
_THE_PARSER = "sentinel_harness/egress.py"

# Modules that call `ipaddress.ip_address()` for a purpose that is NOT a host range
# check, keyed to the exact reason. Classifying an IOC or a firewall rule's address is a
# legitimate use of the narrow parser — an IOC written as `2852039166` is not an IP
# address any threat feed would emit, and treating it as one would be wrong.
#
# Keyed by path so a NEW call in one of these files still has to be argued for, rather
# than inheriting a file-level pass — the INV-GUARD-1 lesson (a round-17 allowlist keyed
# by file turned out to be a permanent file-level exemption, proven by a positive
# control).
_NON_HOST_USES: dict[str, str] = {
    "tools/enrich_ioc/handler.py":
        "classifies a submitted INDICATOR as an IP vs a domain/hash; an IOC in decimal "
        "notation is not something a threat feed emits, and accepting one would widen "
        "what counts as an IP indicator",
    "tools/asset_lookup/handler.py":
        "classifies the QUERY as an IP vs a hostname to pick the lookup key; same "
        "reasoning as enrich_ioc",
    "tools/allowlist_optimizer/handler.py":
        "parses firewall-rule addresses to compute CIDR coverage — arithmetic over "
        "operator-authored rules, not a decision about where to send a request",
    "tools/sigma_match/handler.py":
        "parses a log field's value to evaluate a Sigma CIDR condition; a detection "
        "rule matching against event data, with no egress involved",
}

# The give-away that a call IS a host range check: the result is tested against
# `is_link_local` / `is_reserved` / `is_multicast` / `is_loopback` / `is_unspecified`.
# That is a decision about whether an address is safe to CONNECT to, which is the one
# thing that must use the shared parser.
_RANGE_CHECK_ATTRS = frozenset({
    "is_link_local", "is_multicast", "is_reserved", "is_unspecified", "is_loopback",
    "is_private", "is_global",
})

_METADATA_SPELLINGS = (
    "169.254.169.254", "2852039166", "0xA9FEA9FE", "0251.0376.0251.0376",
)
_LOOPBACK_SPELLINGS = (
    "127.0.0.1", "2130706433", "0x7f000001", "0177.0.0.01",
)


def _swept_modules() -> list[pathlib.Path]:
    out = []
    for tree in _SWEPT_TREES:
        base = REPO_ROOT / tree
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*.py")):
            if "__pycache__" in path.parts or "build" in path.parts:
                continue
            out.append(path)
    return out


def _relpath(path: pathlib.Path) -> str:
    return str(path.relative_to(REPO_ROOT))


def _range_check_attrs_in(source: str) -> list[int]:
    """Line numbers where an address object is tested against a range property."""
    tree = ast.parse(source)
    hits = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr in _RANGE_CHECK_ATTRS:
            hits.append(node.lineno)
    return hits


def _narrow_parser_calls_in(source: str) -> list[int]:
    """Line numbers calling `ipaddress.ip_address(...)` — the narrow parser."""
    tree = ast.parse(source)
    hits = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "ip_address":
            hits.append(node.lineno)
        elif isinstance(func, ast.Name) and func.id == "ip_address":
            hits.append(node.lineno)
    return hits


# --------------------------------------------------------------------------- #
# INV-EGRESS-3 — one parser, swept over every tree                            #
# --------------------------------------------------------------------------- #
class TestNoModuleKeepsItsOwnHostCheck:

    def test_the_sweep_finds_modules(self):
        """Guard the guard, first. Every assertion below is negative, so a broken tree
        walk passes them all — which is how INV-EGRESS-1 read healthy while missing four
        copies."""
        modules = _swept_modules()
        assert len(modules) >= 40, (
            f"the sweep found only {len(modules)} modules; it is not looking at the "
            "tree and every check below is vacuous"
        )
        assert any(_relpath(p) == _THE_PARSER for p in modules), (
            f"{_THE_PARSER} is not in the swept set, so the sweep is not reading "
            "the tree it claims to"
        )

    def test_no_module_range_checks_an_address_it_parsed_narrowly(self):
        """The defect, stated structurally: a module that both calls the NARROW parser
        and tests the result against a range property is deciding "is this safe to
        connect to" with a parser that cannot see the attack.

        Note the two halves must BOTH be present. Testing for `ip_address()` alone
        produces four false positives (the IOC/rule classifiers in `_NON_HOST_USES`);
        testing for `is_link_local` alone would miss a copy that spelled its ranges out
        as CIDR comparisons. The conjunction is what makes this precise.
        """
        offenders = {}
        for path in _swept_modules():
            rel = _relpath(path)
            if rel == _THE_PARSER:
                continue  # the shared parser is where the narrow call belongs
            source = path.read_text(encoding="utf-8")
            narrow = _narrow_parser_calls_in(source)
            if not narrow:
                continue
            if not _range_check_attrs_in(source):
                # Parses an address but never range-checks it — a classifier. It still
                # has to be argued for.
                assert rel in _NON_HOST_USES, (
                    f"{rel} calls ipaddress.ip_address() at line(s) {narrow} for a "
                    "purpose this module has not classified. If it is a host range "
                    "check, delegate to egress.parse_ip_literal. If it is not, add it "
                    "to _NON_HOST_USES with the reason."
                )
                continue
            offenders[rel] = narrow
        assert not offenders, (
            "module(s) parse a host with ipaddress.ip_address() AND range-check the "
            f"result: {offenders}. That parser accepts only dotted-quad / standard "
            "IPv6, so every alternate spelling of 169.254.169.254 walks past the range "
            "check as a DNS name. Delegate to egress.parse_ip_literal — the policy can "
            "stay local, only the parse must be shared."
        )

    @pytest.mark.parametrize("relpath", sorted(_NON_HOST_USES))
    def test_every_classifier_exemption_still_applies(self, relpath):
        """A stale exemption is how an allowlist rots into a blanket skip. If the file
        stopped calling the narrow parser, the entry must go."""
        path = REPO_ROOT / relpath
        assert path.is_file(), f"_NON_HOST_USES names a missing module: {relpath}"
        narrow = _narrow_parser_calls_in(path.read_text(encoding="utf-8"))
        assert narrow, (
            f"{relpath} no longer calls ipaddress.ip_address(), so its _NON_HOST_USES "
            "entry is stale — remove it"
        )

    @pytest.mark.parametrize("relpath", sorted(_NON_HOST_USES))
    def test_every_classifier_exemption_carries_a_reason(self, relpath):
        reason = _NON_HOST_USES[relpath]
        assert len(reason.strip()) >= 40, (
            f"the exemption for {relpath} is too thin to review: {reason!r}. The reason "
            "is the claim a reviewer checks; without it the entry is just a silencer."
        )

    @pytest.mark.parametrize("tool", ("asset_lookup", "enrich_ioc", "web_search"))
    def test_the_three_shadowed_copies_now_delegate(self, tool):
        """The specific regression. Each kept an `_assert_safe_url` whose range check
        used the narrow parser."""
        source = (REPO_ROOT / "tools" / tool / "handler.py").read_text(encoding="utf-8")
        assert "egress.assert_safe_url" in source, (
            f"tools/{tool}/handler.py no longer delegates its URL check"
        )
        assert "_ALLOWED_URL_SCHEMES = egress.ALLOWED_URL_SCHEMES" in source, (
            f"tools/{tool}/handler.py redefines the scheme allowlist instead of "
            "re-exporting it, so the two can drift"
        )

    def test_the_gateway_delegates_its_parser_but_keeps_its_policy(self):
        """The fourth copy, and the only one with no downstream recheck. It must use the
        shared PARSER while keeping its stricter POLICY — https-only and loopback
        refused, neither of which the egress guard imposes."""
        source = (REPO_ROOT / "sentinel_harness" / "gateway.py").read_text(
            encoding="utf-8")
        assert "egress.parse_ip_literal" in source, (
            "gateway.py no longer uses the shared parser"
        )
        assert "is_loopback" in source, (
            "gateway.py stopped refusing loopback — an IdP on the box is not "
            "externally verifiable, and this policy is deliberately stricter than "
            "the egress guard's"
        )


# --------------------------------------------------------------------------- #
# The behavioural half — the four copies' actual verdicts                     #
# --------------------------------------------------------------------------- #
class TestTheReproducedAttacks:
    """Structural delegation proves the call goes to the right place; these prove the
    right answer comes back. Both are needed: a delegation to a parser that stopped
    handling octal would pass every check above."""

    @pytest.mark.parametrize("spelling", _METADATA_SPELLINGS)
    def test_the_gateway_refuses_the_metadata_service(self, spelling):
        with pytest.raises(ValueError, match="non-routable/metadata"):
            gateway._validate_discovery_url(
                f"https://{spelling}/.well-known/openid-configuration")

    @pytest.mark.parametrize("spelling", _LOOPBACK_SPELLINGS)
    def test_the_gateway_refuses_loopback(self, spelling):
        """This guard's policy — unlike the egress guard's — refuses loopback, because
        an identity provider on the local box is not externally verifiable."""
        with pytest.raises(ValueError, match="non-routable/metadata"):
            gateway._validate_discovery_url(
                f"https://{spelling}/.well-known/openid-configuration")

    def test_the_gateway_still_allows_a_real_idp(self):
        """CONTROL. A guard that refuses everything is not a guard, and refusing a real
        IdP would make the authorizer unconfigurable."""
        gateway._validate_discovery_url(
            "https://idp.example.com/.well-known/openid-configuration")

    def test_the_gateway_still_requires_https(self):
        with pytest.raises(ValueError, match="must be https"):
            gateway._validate_discovery_url(
                "http://idp.example.com/.well-known/openid-configuration")

    @pytest.mark.parametrize("tool", ("asset_lookup", "enrich_ioc", "web_search"))
    @pytest.mark.parametrize("spelling", _METADATA_SPELLINGS)
    def test_each_shadowed_copy_refuses_every_spelling(self, tool, spelling):
        handler = _load_handler(tool)
        with pytest.raises(RuntimeError):
            handler._assert_safe_url(f"http://{spelling}/latest/meta-data/")

    @pytest.mark.parametrize("tool", ("asset_lookup", "enrich_ioc", "web_search"))
    def test_each_shadowed_copy_still_allows_its_backend(self, tool):
        """CONTROL: loopback and a DNS name must stay allowed for these three — a
        self-hosted backend is legitimate and the live tests bind 127.0.0.1."""
        handler = _load_handler(tool)
        handler._assert_safe_url("https://backend.example.internal/api")
        handler._assert_safe_url("http://127.0.0.1:8899/api")


def _load_handler(tool: str):
    import importlib.util
    path = REPO_ROOT / "tools" / tool / "handler.py"
    spec = importlib.util.spec_from_file_location(f"_r19_{tool}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# --------------------------------------------------------------------------- #
# The sweep's positive control                                                #
# --------------------------------------------------------------------------- #
class TestTheSweepCanDetectACopy:
    """A structural sweep reporting "no offenders" is indistinguishable from a broken
    one. Round 18 established this after three guards shipped blind; INV-EGRESS-1 then
    demonstrated the softer version — a sweep that worked but looked at two files."""

    _COPY = '''
import ipaddress
from urllib.parse import urlsplit


def _assert_safe_url(url):
    """A fresh local copy of the host check — the exact defect."""
    parts = urlsplit(url)
    host = parts.hostname
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return
    if ip.is_link_local or ip.is_reserved:
        raise RuntimeError("refused")
'''

    def test_the_conjunction_flags_a_synthetic_copy(self):
        """Unit control: both halves of the predicate fire on a real copy."""
        assert _narrow_parser_calls_in(self._COPY), (
            "the narrow-parser detector cannot see ipaddress.ip_address()"
        )
        assert _range_check_attrs_in(self._COPY), (
            "the range-check detector cannot see is_link_local"
        )

    def test_the_conjunction_does_not_flag_a_classifier(self):
        """CONTROL for the control: an IOC classifier parses narrowly and must NOT be
        flagged, or the sweep is unusable and gets an allowlist that swallows the real
        cases."""
        classifier = (
            "import ipaddress\n"
            "def _looks_like_ip(s):\n"
            "    try:\n"
            "        ipaddress.ip_address(s)\n"
            "        return True\n"
            "    except ValueError:\n"
            "        return False\n"
        )
        assert _narrow_parser_calls_in(classifier)
        assert not _range_check_attrs_in(classifier), (
            "the range-check detector fires on a plain classifier, which would make "
            "this sweep produce false positives and get suppressed"
        )

    def test_the_sweep_would_have_caught_all_four_round_19_copies(self):
        """The historical check, run against the copies as they actually stood. Each is
        reconstructed from git only in SHAPE — the point is that the predicate this
        module uses classifies them as offenders, which is the claim that they were
        findable and INV-EGRESS-1 simply was not looking."""
        as_it_stood = self._COPY
        assert _narrow_parser_calls_in(as_it_stood) and _range_check_attrs_in(
            as_it_stood), (
            "the predicate does not classify a round-19 copy as an offender, so the "
            "sweep would not have found them either"
        )

    def test_a_real_copy_in_the_tree_fails_the_build(self):
        """END-TO-END control. The unit checks above prove the predicate works; only
        this proves it is wired to an assertion that RUNS.

        Round 18 drew that distinction the hard way — INV-GUARD-4 matched `ast.In` and
        missed `not in`, and the unit control shared the blind spot because both came
        from one wrong mental model. Only an end-to-end path found it.

        Writes a genuine local copy into `sentinel_harness/`, runs this file as a child,
        and asserts the failure NAMES it. The child launch goes through
        `child_pytest.run_child_suite`, which resolves a launcher that works in THIS
        environment and raises `ChildNeverRan` rather than returning a non-zero exit that
        would read as "the guard fired" — the launcher has been wrong three times, each
        time for a different environment, and each time it faked a pass.
        """
        probe = REPO_ROOT / "sentinel_harness" / "zz_r19_egress_probe.py"
        this_file = pathlib.Path(__file__).name
        try:
            probe.write_text(
                '"""A fresh local host range-check — the defect INV-EGRESS-3 forbids."""\n'
                + self._COPY,
                encoding="utf-8",
            )
            result = child_pytest.run_child_suite(
                this_file,
                deselect=(f"tests/{this_file}::TestTheSweepCanDetectACopy"
                          "::test_a_real_copy_in_the_tree_fails_the_build",),
            )
            assert result.suite_failed, (
                "a fresh local host range-check in sentinel_harness/ did NOT fail the "
                "suite — the sweep is not wired to an assertion that runs"
            )
            assert probe.name in result.output, (
                f"the suite failed but never named the offending module, so the "
                f"failure may be unrelated:\n{result.output[-600:]}"
            )
        finally:
            probe.unlink(missing_ok=True)

    def test_the_probe_leaves_nothing_behind(self):
        probe = REPO_ROOT / "sentinel_harness" / "zz_r19_egress_probe.py"
        assert not probe.exists(), (
            f"{probe.name} was left in the tree — the next collection would fail for "
            "the wrong reason, and a real copy could ship behind it"
        )

    def test_the_shared_parser_handles_what_the_narrow_one_misses(self):
        """The reason delegation is worth anything: the two parsers disagree exactly on
        the attack. If they ever agree, the sweep enforces a distinction with no
        content."""
        import ipaddress
        for spelling in ("2852039166", "0xA9FEA9FE", "0251.0376.0251.0376"):
            with pytest.raises(ValueError):
                ipaddress.ip_address(spelling)
            resolved = egress.parse_ip_literal(spelling)
            assert resolved is not None and str(resolved) == "169.254.169.254", (
                f"{spelling!r} no longer resolves to the metadata address, so "
                "delegating the parse buys nothing"
            )
