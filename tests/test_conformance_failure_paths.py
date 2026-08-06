"""INV-CONN-1 — the conformance kit's FAILURE branches are exercised, not merely present.

`sentinel_harness/connectors/conformance.py` is the certification kit an adopter runs against their
own SIEM / ticketing connector. It decides whether a connector is fit to wire into the platform, so
its value rests entirely on it being able to say NO.

`tests/test_connector_conformance.py` already proves it can: eight injected non-conformant
connectors (`_NoNameSiem`, `_BadShapeSiem`, `_SwallowsForeignSiem`, `_NoTitleCheckTicketing`,
`_SwallowsJunkSiem`, `_ThrowingSample`, `_NoSampleSiem`, plus a raising getter) are each rejected.
That is the important half and it was already covered — my first hypothesis, that the kit had never
been shown to reject anything, was WRONG and is recorded here so the next reader does not re-derive
it from a coverage report.

What WAS missing is finer: 15 statements in `conformance.py` were unexecuted by the whole suite, and
every one of them sits inside a failure branch. Measured before this module existed — **90% statement
coverage, missing `202-205, 224, 235-236, 244-245, 253, 260-261, 371-375`** — and **100% (0 missing)**
after. Each branch was reached by injection and each behaved correctly, so this module is not fixing a
defect: it converts "unverified but happens to be right" into "verified".

That distinction matters for a certification kit specifically. A branch that never runs is a branch
whose message nobody has read, and the message IS the product here: an adopter acts on
`"rejects_foreign_envelope: probe {...}: raised TypeError, expected ConnectorError"`. If a refactor
broke that string into something useless, or silently stopped recording the failure at all, every
existing test would stay green — they assert `ok is False`, which a wrong-but-still-failing check
also satisfies.

So each test below asserts the SPECIFIC named check that must fail, not just that certification
failed overall. Recorded because it bit me: probing `result.checks` for the failing entry found
nothing, and I briefly took that as the kit losing a check. `checks` holds only the names that
PASSED; failures live in `result.failures`. Reading the wrong field made a working kit look broken —
the diagnosis was my probe, not the product.

ZERO network, ZERO AWS: every connector here is a local stub.
"""
from __future__ import annotations

import pytest

from sentinel_harness.connectors.base import ConnectorError
from sentinel_harness.connectors.conformance import (
    check_siem_connector,
    check_ticketing_connector,
)

# The neutral SIEM event shape a conformant connector must emit. Kept here so a stub can be
# deliberately one field off without that looking like a typo.
_NEUTRAL_EVENT = {
    "alert_id": "a-1",
    "ts": "2026-01-01T00:00:00Z",
    "severity": "low",
    "rule_name": "r",
    "host": "h-1",
    "src_ip": None,
    "dst_ip": None,
    "technique": "",
    "summary": "",
    "false_positive": False,
}

_FOREIGN_PROBE_CHECK = "rejects_foreign_envelope"


def _failing_checks(result) -> dict:
    """{check name: detail} for every FAILED check.

    `ConformanceResult.checks` records the names that passed; failures are strings in
    `.failures`, formatted `"<check>: <detail>"`. A helper because reading the wrong one of those two
    is exactly the mistake that made a working kit look broken while writing this module.
    """
    out = {}
    for entry in result.failures:
        name, _, detail = entry.partition(": ")
        out[name] = detail
    return out


def test_the_shipped_connectors_still_certify():
    """Positive control, and it is not decorative.

    Every test below asserts that a DELIBERATELY broken connector fails. If `check_*_connector` had
    regressed into failing everything, all of them would pass while the kit had become useless. So
    the real connectors must still certify clean.
    """
    from sentinel_harness.connectors import get_siem_connector, get_ticketing_connector

    siem = check_siem_connector(get_siem_connector("splunk"))
    assert siem.ok, f"the shipped splunk connector no longer certifies: {siem.failures}"
    ticketing = check_ticketing_connector(get_ticketing_connector("jira"))
    assert ticketing.ok, f"the shipped jira connector no longer certifies: {ticketing.failures}"


# --------------------------------------------------------------------------- #
# SIEM: the foreign-envelope probe must distinguish WRONG-EXCEPTION from OK    #
# --------------------------------------------------------------------------- #
def test_a_connector_raising_the_wrong_exception_type_is_reported_as_such():
    """`conformance.py:202-205` — the branch for "rejected, but with the wrong exception".

    A connector that raises `TypeError` on a foreign envelope IS refusing the input, so a naive check
    ("did it raise?") would pass it. But the platform catches `ConnectorError` specifically; a
    `TypeError` escapes as an unhandled crash rather than a handled rejection. The kit has to tell
    those apart, and the message must name the type it actually got so the adopter can fix it.

    This branch was unexecuted by the entire suite before this test.
    """
    class WrongExceptionSiem:
        name = "wrong-exception"

        def build_request(self, query):
            return {"body": {"q": query}, "path": "/search"}

        def parse_response(self, raw):
            if not isinstance(raw, dict) or "events" not in raw:
                raise TypeError("boom")  # should be ConnectorError
            return [dict(_NEUTRAL_EVENT)]

        def sample_response(self):
            return {"events": [{}]}

    result = check_siem_connector(WrongExceptionSiem())
    assert not result.ok, "a connector raising TypeError on a foreign envelope must NOT certify"

    failures = _failing_checks(result)
    assert _FOREIGN_PROBE_CHECK in failures, (
        f"the kit did not record a {_FOREIGN_PROBE_CHECK!r} failure. It refused the connector for "
        f"other reasons ({sorted(failures)}), which means the wrong-exception branch did not fire — "
        "a connector whose only flaw is the exception TYPE would certify clean."
    )
    detail = failures[_FOREIGN_PROBE_CHECK]
    assert "TypeError" in detail and "ConnectorError" in detail, (
        f"the failure detail must name both the type raised and the type expected, or the adopter "
        f"cannot act on it. Got: {detail!r}"
    )


def test_a_connector_that_accepts_a_foreign_envelope_is_reported_differently():
    """The other side of the same probe, so the two outcomes cannot collapse into one message.

    Accepting junk and raising the wrong error are different defects with different fixes. If both
    produced the same detail string, the kit would be telling the adopter less than it knows.
    """
    class SwallowsForeignSiem:
        name = "swallows-foreign"

        def build_request(self, query):
            return {"body": {"q": query}, "path": "/search"}

        def parse_response(self, raw):
            return [dict(_NEUTRAL_EVENT)]  # accepts anything

        def sample_response(self):
            return {"events": [{}]}

    result = check_siem_connector(SwallowsForeignSiem())
    assert not result.ok
    failures = _failing_checks(result)
    assert _FOREIGN_PROBE_CHECK in failures, sorted(failures)
    detail = failures[_FOREIGN_PROBE_CHECK]
    assert "accepted" in detail.lower(), (
        f"accepting a foreign envelope must be reported as acceptance, not as a raise. Got: "
        f"{detail!r}"
    )
    assert "TypeError" not in detail, (
        "the 'accepted' and 'wrong exception' outcomes produce the same message, so the kit cannot "
        "distinguish two defects that need different fixes"
    )


# --------------------------------------------------------------------------- #
# TICKETING: the branches that were entirely unexecuted                       #
# --------------------------------------------------------------------------- #
def test_a_ticketing_connector_missing_methods_short_circuits():
    """`conformance.py:224` — the early `return` when the required methods are absent.

    Without it the kit would go on to call `build_request` on an object that has none, and the
    adopter would read an `AttributeError` traceback instead of "must expose build_request +
    parse_response". A useless message is a real failure mode for a certification tool.
    """
    class MissingMethodsTicketing:
        name = "missing-methods"

    result = check_ticketing_connector(MissingMethodsTicketing())
    assert not result.ok
    failures = _failing_checks(result)
    assert "has_methods" in failures, sorted(failures)
    assert "build_request" in failures["has_methods"], (
        f"the message must name the missing methods: {failures['has_methods']!r}"
    )
    # And it must STOP there rather than piling on cascade failures from the absent methods.
    assert "build_request_shape" not in failures, (
        "the kit kept probing after finding no methods, so its report mixes the root cause with "
        "cascade noise. The early return exists to prevent that."
    )


def test_a_ticketing_request_that_is_not_json_serialisable_fails_the_shape_check():
    """`conformance.py:235-236` — `json.dumps(req["body"])` raising.

    The request body crosses a process boundary as JSON. A connector returning a live Python object
    builds fine and fails at send time, which is the worst place to find out. This branch was
    unexecuted.
    """
    class UnjsonableTicketing:
        name = "unjsonable"

        def build_request(self, ticket):
            return {"body": {"payload": object()}, "path": "/issue"}

        def parse_response(self, raw):
            return {"ticket_id": "T-1", "status": "open", "url": "http://example.test/T-1"}

        def sample_response(self):
            return {"id": "T-1"}

    result = check_ticketing_connector(UnjsonableTicketing())
    assert not result.ok
    failures = _failing_checks(result)
    assert "build_request_shape" in failures, sorted(failures)
    assert "JSON" in failures["build_request_shape"], (
        f"the failure must say the body is not JSON-serialisable: "
        f"{failures['build_request_shape']!r}"
    )


def test_a_ticketing_connector_that_accepts_a_titleless_ticket_is_caught():
    """`conformance.py:244-245` — the "accepted a title-less request" branch.

    A ticket with no title is unusable to a human triager, so the connector must refuse it rather
    than create an untitled issue. Note this stub is otherwise well-behaved, which is the point: the
    check must fire on its own merits rather than as a side effect of some other flaw.
    """
    class AcceptsTitlelessTicketing:
        name = "accepts-titleless"

        def build_request(self, ticket):
            return {"body": dict(ticket), "path": "/issue"}  # no title validation

        def parse_response(self, raw):
            if not isinstance(raw, dict) or "id" not in raw:
                raise ConnectorError("foreign envelope")
            return {"ticket_id": raw["id"], "status": "open",
                    "url": "http://example.test/" + raw["id"]}

        def sample_response(self):
            return {"id": "T-1"}

    result = check_ticketing_connector(AcceptsTitlelessTicketing())
    assert not result.ok
    failures = _failing_checks(result)
    assert "rejects_titleless" in failures, (
        f"the kit did not flag a connector that accepts a title-less ticket: {sorted(failures)}"
    )
    assert "accepted" in failures["rejects_titleless"].lower(), (
        f"the message must say the request was accepted: {failures['rejects_titleless']!r}"
    )


def test_a_ticketing_parse_missing_neutral_keys_is_caught():
    """`conformance.py:253, 260-261` — the neutral-result assertions and their handler.

    `{"ticket_id": ...}` alone is not a neutral result: the platform reads `status` and `url` too, and
    a missing `url` means an analyst gets a ticket they cannot open. This stub refuses foreign
    envelopes and validates titles correctly, so the parse check is isolated.
    """
    class IncompleteParseTicketing:
        name = "incomplete-parse"

        def build_request(self, ticket):
            if not ticket.get("title"):
                raise ConnectorError("title is required")
            return {"body": dict(ticket), "path": "/issue"}

        def parse_response(self, raw):
            if not isinstance(raw, dict) or "id" not in raw:
                raise ConnectorError("foreign envelope")
            return {"ticket_id": raw["id"]}  # missing status + url

        def sample_response(self):
            return {"id": "T-1"}

    result = check_ticketing_connector(IncompleteParseTicketing())
    assert not result.ok
    failures = _failing_checks(result)
    assert "parse_sample_result" in failures, sorted(failures)
    assert "neutral result keys" in failures["parse_sample_result"], (
        f"the message must name what is missing: {failures['parse_sample_result']!r}"
    )
    # The other checks must have PASSED, or this test proves nothing about the parse branch.
    assert "rejects_titleless" not in failures and "build_request_shape" not in failures, (
        f"this stub was meant to fail only on parsing, but also failed {sorted(failures)} — the "
        "assertion above could be passing for the wrong reason."
    )


def test_an_empty_ticket_id_is_rejected_even_when_the_keys_are_present():
    """The subtler half of the same branch: all three keys present, `ticket_id` empty.

    A connector returning `{"ticket_id": "", ...}` satisfies a key-presence check while giving the
    platform no ticket to reference. `conformance.py` asserts non-emptiness separately, and nothing
    exercised that.
    """
    class EmptyIdTicketing:
        name = "empty-id"

        def build_request(self, ticket):
            if not ticket.get("title"):
                raise ConnectorError("title is required")
            return {"body": dict(ticket), "path": "/issue"}

        def parse_response(self, raw):
            if not isinstance(raw, dict) or "id" not in raw:
                raise ConnectorError("foreign envelope")
            return {"ticket_id": "", "status": "open", "url": "http://example.test/x"}

        def sample_response(self):
            return {"id": "T-1"}

    result = check_ticketing_connector(EmptyIdTicketing())
    assert not result.ok, "an empty ticket_id must not certify"
    failures = _failing_checks(result)
    assert "parse_sample_result" in failures, sorted(failures)
    assert "non-empty" in failures["parse_sample_result"], (
        f"the message must say ticket_id has to be non-empty: "
        f"{failures['parse_sample_result']!r}"
    )


def test_a_titleless_request_raising_the_wrong_exception_is_reported_as_such():
    """`conformance.py:244-245` — the ticketing twin of the SIEM wrong-exception branch.

    Found by re-reading coverage after the first pass: I had written a test for "accepts a title-less
    ticket" and assumed it covered this, but 244-245 stayed unexecuted. They are a DIFFERENT branch —
    the connector does refuse the ticket, just with the wrong exception type. Assuming one test
    covered both is how a branch stays unverified while a test named after it passes.
    """
    class WrongExcTicketing:
        name = "wrong-exc-ticketing"

        def build_request(self, ticket):
            if not ticket.get("title"):
                raise ValueError("title is required")  # should be ConnectorError
            return {"body": dict(ticket), "path": "/issue"}

        def parse_response(self, raw):
            if not isinstance(raw, dict) or "id" not in raw:
                raise ConnectorError("foreign envelope")
            return {"ticket_id": raw["id"], "status": "open",
                    "url": "http://example.test/" + raw["id"]}

        def sample_response(self):
            return {"id": "T-1"}

    result = check_ticketing_connector(WrongExcTicketing())
    assert not result.ok, "refusing with the wrong exception type must not certify"
    failures = _failing_checks(result)
    assert "rejects_titleless" in failures, sorted(failures)
    detail = failures["rejects_titleless"]
    assert "ValueError" in detail, (
        f"the failure must name the type actually raised so the adopter can fix it: {detail!r}"
    )
    assert "accepted" not in detail.lower(), (
        f"refusing with the wrong exception was reported as ACCEPTANCE, conflating two different "
        f"defects: {detail!r}"
    )


def test_a_connector_with_no_usable_sample_is_reported_not_crashed():
    """`conformance.py:253` — the `_NO_SAMPLE` path inside the parse check.

    An adopter's connector may ship no `sample_response()` and match no built-in fixture. The kit
    must record "cannot certify parsing" rather than raise, because a certification tool that crashes
    on an unfamiliar connector gives the adopter a traceback instead of a verdict.

    The name is deliberately unlike any shipped connector so no built-in fixture matches.
    """
    class NoSampleTicketing:
        name = "no-such-vendor-xyz"

        def build_request(self, ticket):
            if not ticket.get("title"):
                raise ConnectorError("title is required")
            return {"body": dict(ticket), "path": "/issue"}

        def parse_response(self, raw):
            if not isinstance(raw, dict) or "id" not in raw:
                raise ConnectorError("foreign envelope")
            return {"ticket_id": raw["id"], "status": "open",
                    "url": "http://example.test/" + raw["id"]}

        # no sample_response()

    result = check_ticketing_connector(NoSampleTicketing())
    assert not result.ok, "a connector whose parsing cannot be certified must not certify"
    failures = _failing_checks(result)
    assert "parse_sample_result" in failures, sorted(failures)
    assert "sample" in failures["parse_sample_result"].lower(), (
        f"the message must explain that no sample was available: "
        f"{failures['parse_sample_result']!r}"
    )


def test_a_raising_cross_connector_check_is_isolated_not_propagated():
    """`conformance.py:371-375` — the last unexecuted failure branch in the file.

    `certify_all` ends with the CROSS-connector result-set equivalence check, which round 13 added
    because a per-connector check is structurally blind to it. That call has its own `try/except` so a
    failure there is recorded under `_cross_connector` instead of destroying the whole run.

    `test_connector_conformance.py::test_certify_all_isolates_a_raising_getter` looks like it covers
    this and does not: its `KeyError` is caught by the PER-CONNECTOR loop, so execution never reaches
    the cross-connector block. Verified by coverage — 371-375 stayed unexecuted with that test
    passing. Two isolations that look alike, only one of them tested.

    Why it matters: without it an adopter running `certify_all` on a fleet gets a traceback instead of
    "these nine certified, the cross-connector check errored" — losing every per-connector verdict the
    run already computed. Degradation has to be recorded, not fatal.

    Inducing it took two wrong attempts, both recorded because each looked right:

      1. A getter that raises on its SECOND call. That failed to reach 371-375 because
         `check_result_set_equivalence` catches per-connector errors ITSELF, recording
         `bound[splunk]: raised RuntimeError`. The outer handler is a second layer of defence, so the
         inner one has to be bypassed, not merely triggered. My assertions still passed — they were
         satisfied by the INNER catch — which is a test verifying something other than its name.
      2. A non-iterable `siem_names`. That raised too EARLY, in the per-connector loop at line 358,
         before the cross-connector block was reached at all.

    What works is a `siem_names` that iterates once (for the per-connector loop) and then raises (when
    the cross-check re-iterates), so the failure lands squarely in the cross-connector phase.
    """
    from sentinel_harness.connectors import (
        available_ticketing_connectors,
        get_siem_connector,
        get_ticketing_connector,
    )
    from sentinel_harness.connectors.conformance import certify_all

    class OnceThenBoom:
        """Iterable that succeeds for the per-connector loop and raises for the cross-check."""

        def __init__(self):
            self.iterations = 0

        def __iter__(self):
            self.iterations += 1
            if self.iterations > 1:
                raise RuntimeError("names exploded on re-iteration")
            return iter(["splunk"])

    results = certify_all(
        lambda name: get_siem_connector("splunk"),
        get_ticketing_connector,
        OnceThenBoom(),
        available_ticketing_connectors(),
    )

    assert "_cross_connector" in results, (
        "certify_all did not report a _cross_connector entry at all, so a cross-check failure would "
        f"be invisible. Keys: {sorted(results)}"
    )
    cross = results["_cross_connector"]
    assert cross.ok is False, "the cross-connector check raised but was reported as passing"
    joined = " ".join(cross.failures)
    assert "RuntimeError" in joined, (
        f"the recorded failure must name the exception type so the adopter can diagnose it: "
        f"{cross.failures}"
    )
    assert "cross-connector check raised" in joined, (
        "the failure was recorded by the INNER per-connector handler inside "
        "check_result_set_equivalence, not by certify_all's outer isolation. Those are two different "
        f"branches; this test must exercise the outer one. Got: {cross.failures}"
    )

    # And the per-connector verdicts must SURVIVE — that is the whole point of isolating.
    survivors = sorted(key for key in results if key != "_cross_connector")
    assert len(survivors) >= 4, (
        f"the cross-connector failure took the per-connector results with it (survivors: "
        f"{survivors}), which is exactly what the isolation exists to prevent"
    )
    assert all(results[key].ok for key in survivors), (
        f"per-connector verdicts were corrupted by the cross-check failure: "
        f"{ {k: results[k].ok for k in survivors} }"
    )


@pytest.mark.parametrize("check_name", ["has_name", "has_methods"])
def test_the_structural_checks_are_recorded_by_name(check_name):
    """The kit's report must name checks consistently, because tests and adopters branch on them.

    Asserted against the SHIPPED connector, so a rename of a check shows up here rather than
    silently invalidating the `_failing_checks` lookups every test above relies on.
    """
    from sentinel_harness.connectors import get_siem_connector

    result = check_siem_connector(get_siem_connector("splunk"))
    assert check_name in result.checks, (
        f"the conformance report no longer records a check named {check_name!r} (records: "
        f"{result.checks}). Every assertion in this module looks checks up by name; a rename must "
        "fail here rather than quietly make those lookups miss."
    )
