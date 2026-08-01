"""
Round-13 semantic-gap regression suite — FP-heuristic specificity & connector result-set equivalence.
=====================================================================================================
R12 asked "does a GENERATED rule / a GATE preserve the match set?". R13 pushed the
same match-set question into two more surfaces where "breadth" is judged:

1. **sigma_yara_lint's FP-proneness heuristic used rule SHAPE as a proxy for
   breadth, and mis-judged both ways at the extremes.** A surgically precise rule
   — a full path plus the 4-char Log4Shell marker `jndi`, matching zero benign
   events — collected 3 fp_warnings and was penalised as "fp_prone" (the `jndi`
   value tripped a pure length threshold, and a full-path predicate on a
   high-volume logsource still counted as "no exclusion filter"). Penalising a
   team's most precise detection pushes the library the wrong way and trains it to
   ignore the signal. (The false-NEGATIVE direction was probed too and found sound
   — checks #2 and #5 cross-cover, so a catastrophically broad rule still earns
   >=2 warnings; those cases are kept as tripwires.)

2. **The SIEM connectors did not preserve the RESULT SET across backends.** The
   same neutral query returned different result sets per backend — QRadar silently
   applied a 24h window, only some capped at 1000 rows — so a detection validated
   offline behaved differently in production. And the conformance suite passed all
   of them, because it asserted response SHAPE and never cross-connector
   EQUIVALENCE (the same "asks the wrong question" root cause as R11's coverage).

Found via a fan-out workflow (parallel probes + adversarial reproduction) and each
finding independently reproduced by hand before fixing. Every test below FAILS on
pre-R13 source. Zero network, zero AWS, zero LLM.
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


lint = _load("sigma_yara_lint_r13", "tools/sigma_yara_lint/handler.py")
sm = _load("sigma_match_r13", "tools/sigma_match/handler.py")

from sentinel_harness.connectors import (  # noqa: E402
    available_siem_connectors, available_ticketing_connectors,
    get_siem_connector, get_ticketing_connector,
)
from sentinel_harness.connectors import conformance as C  # noqa: E402


# --------------------------------------------------------------------------- #
# FP-proneness: specificity, not shape                                        #
# --------------------------------------------------------------------------- #
_BENIGN = [
    {"Image": f"C:\\Windows\\System32\\{n}", "CommandLine": f"{n} /q", "User": "alice"}
    for n in ("svchost.exe", "explorer.exe", "notepad.exe", "taskhost.exe", "conhost.exe")
]


def _rule(detection_body: str, level: str = "high", falsepositives: bool = True) -> str:
    fp = "falsepositives:\n    - legitimate usage\n" if falsepositives else ""
    return (
        "title: T\n"
        "id: 11111111-1111-1111-1111-111111111111\n"
        "status: experimental\n"
        f"level: {level}\n"
        "logsource:\n    product: windows\n    category: process_creation\n"
        f"{fp}"
        "detection:\n"
        f"{detection_body}"
        "    condition: selection\n"
    )


def _fp_warnings(rule: str):
    return lint.handler({"rule_type": "sigma", "content": rule}, None).get("fp_warnings") or []


def _is_fp_prone(rule: str) -> bool:
    return len(_fp_warnings(rule)) >= 2   # the aggregator's fp_prone threshold


def _benign_matches(rule: str) -> int:
    return sum(1 for e in _BENIGN if sm.handler({"rule": rule, "log_event": e}, None).get("matched"))


class TestPreciseRulesAreNotPenalised:
    """A rule with a self-anchoring predicate (full path / hash / long exact value)
    is NOT FP-prone, however few predicates it has or whatever its logsource."""

    def test_full_path_plus_ioc_marker_is_not_fp_prone(self):
        """The headline: a full path + the 4-char Log4Shell marker jndi, matching
        zero benign events, was scored fp_prone (3 warnings). It must not be."""
        rule = _rule("    selection:\n        Image: 'C:\\Windows\\Temp\\evil.exe'\n"
                     "        CommandLine|contains: 'jndi'\n")
        assert _benign_matches(rule) == 0
        assert not _is_fp_prone(rule), f"precise rule penalised: {_fp_warnings(rule)}"

    def test_full_sha256_single_predicate_is_not_fp_prone(self):
        rule = _rule("    selection:\n        sha256: "
                     "'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'\n")
        assert not _is_fp_prone(rule)

    def test_full_unc_path_is_not_fp_prone(self):
        rule = _rule("    selection:\n        Image: '\\\\\\\\server\\\\share\\\\payload.exe'\n")
        assert not _is_fp_prone(rule)

    def test_long_exact_commandline_is_not_fp_prone(self):
        rule = _rule("    selection:\n        CommandLine: "
                     "'powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA'\n")
        assert not _is_fp_prone(rule)

    @pytest.mark.parametrize("marker", ["jndi", "ldap", "psexec", "::$", "%%1", "-enc"])
    def test_specific_short_markers_are_not_generic(self, marker):
        """A short but specific IOC marker must not be treated as a generic noise
        value — that is the distinction a pure length check cannot make."""
        assert lint._is_generic_short_value(marker) is False

    @pytest.mark.parametrize("word", ["cmd", "tmp", "all", "abcd", "log"])
    def test_generic_short_words_are_still_generic(self, word):
        """The fix must not swing the other way: plain short English words stay
        generic."""
        assert lint._is_generic_short_value(word) is True


class TestBroadRulesAreStillCaught:
    """The false-NEGATIVE direction: a catastrophically broad rule must still be
    fp_prone. These are tripwires — the specificity exemption must not open a hole."""

    @pytest.mark.parametrize("body", [
        "    selection:\n        Image|startswith: 'C'\n",
        "    selection:\n        Image|endswith: '.exe'\n",
        "    selection:\n        Image|contains: 'System32'\n",
        "    selection:\n        Image|exists: true\n",
        "    selection:\n        CommandLine|contains: 'cmd'\n",
        "    selection:\n        Image: 'C:\\*'\n",
    ])
    def test_broad_rule_is_fp_prone(self, body):
        rule = _rule(body)
        assert _is_fp_prone(rule), f"broad rule slipped through: {_fp_warnings(rule)}"

    def test_a_wildcard_value_is_not_a_specificity_escape(self):
        """A wildcard-bearing exact value looks long but matches broadly — it must
        NOT count as a self-anchoring predicate."""
        assert lint._has_high_specificity_predicate(
            {"selection": {"Image": "C:\\Windows\\*\\evil.exe"}}) is False

    def test_contains_is_not_self_anchoring(self):
        """A |contains on a full-path-like value is a substring match, not an anchor —
        it must not earn the specificity exemption."""
        assert lint._has_high_specificity_predicate(
            {"selection": {"Image|contains": "C:\\Windows\\System32\\cmd.exe"}}) is False


class TestSpecificityHelper:
    """Direct unit tests of the self-anchoring predicate detector."""

    @pytest.mark.parametrize("sel", [
        {"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        {"Image": "C:\\Windows\\Temp\\evil.exe"},
        {"path": "/usr/local/bin/backdoor"},
        {"CommandLine": "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0A"},
    ])
    def test_anchoring_predicates_detected(self, sel):
        assert lint._has_high_specificity_predicate({"selection": sel}) is True

    @pytest.mark.parametrize("sel", [
        {"Image": "cmd.exe"},          # short, no path
        {"User": "SYSTEM"},
        {"dst_port": "445"},
        {"Image|contains": "evil"},
    ])
    def test_non_anchoring_predicates_rejected(self, sel):
        assert lint._has_high_specificity_predicate({"selection": sel}) is False


# --------------------------------------------------------------------------- #
# Connector result-set equivalence                                            #
# --------------------------------------------------------------------------- #
class TestConnectorsPreserveResultSet:
    """Every SIEM connector must emit the SAME result-set bound for the same neutral
    query — else a detection validated offline behaves differently per backend."""

    def test_all_connectors_share_the_same_bound(self):
        names = available_siem_connectors()
        bounds = {n: C._declared_result_bound(get_siem_connector(n)) for n in names}
        distinct = set(bounds.values())
        assert len(distinct) == 1, f"connectors disagree on result-set bound: {bounds}"

    def test_no_connector_invents_a_time_window(self):
        """The neutral query carries no time filter, so no connector may impose one
        (QRadar's silent 24h window dropped older true hits)."""
        for n in available_siem_connectors():
            _limit, window = C._declared_result_bound(get_siem_connector(n))
            assert window is None, f"{n} invents a {window}h time window"

    def test_every_connector_bounds_its_result_set(self):
        """An unbounded result set is its own divergence (some backends page, some
        do not); every connector must carry the shared limit."""
        from sentinel_harness.connectors.base import DEFAULT_RESULT_LIMIT
        for n in available_siem_connectors():
            limit, _window = C._declared_result_bound(get_siem_connector(n))
            assert limit == DEFAULT_RESULT_LIMIT, f"{n} limit={limit}"

    def test_conformance_now_asserts_equivalence(self):
        r = C.check_result_set_equivalence(get_siem_connector, available_siem_connectors())
        assert r.ok
        assert "result_set_equivalence" in r.checks
        assert "no_invented_time_window" in r.checks

    def test_certify_all_includes_the_cross_connector_check(self):
        res = C.certify_all(get_siem_connector, get_ticketing_connector,
                            available_siem_connectors(), available_ticketing_connectors())
        assert "_cross_connector" in res
        assert res["_cross_connector"].ok

    def test_conformance_catches_an_invented_time_window(self):
        """The check must BITE: a connector that imposes a window fails certification."""
        class _Windowed:
            name = "windowed"
            def build_request(self, s, v):
                return {"body": {"search": "search x | head 1000 | LAST 24 HOURS"}, "path": ""}
            def parse_response(self, p):  # pragma: no cover - not exercised here
                return []
        names = available_siem_connectors()

        def getter(n):
            return _Windowed() if n == "windowed" else get_siem_connector(n)
        r = C.check_result_set_equivalence(getter, list(names) + ["windowed"])
        assert r.ok is False
        assert any("time window" in f for f in r.failures)

    def test_conformance_catches_a_divergent_limit(self):
        class _Small:
            name = "small"
            def build_request(self, s, v):
                return {"body": {"query": {"size": 50}}, "path": "/_search"}
            def parse_response(self, p):  # pragma: no cover
                return []
        names = available_siem_connectors()

        def getter(n):
            return _Small() if n == "small" else get_siem_connector(n)
        r = C.check_result_set_equivalence(getter, list(names) + ["small"])
        assert r.ok is False

    def test_per_connector_shape_still_passes(self):
        """Regression: the existing per-connector shape checks are unaffected."""
        for n in available_siem_connectors():
            res = C.check_siem_connector(get_siem_connector(n))
            assert res.ok, f"{n}: {res.failures}"
