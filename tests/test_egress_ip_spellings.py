"""INV-EGRESS-4 — every spelling of the metadata address is parsed, including dotted-hex.

`egress.py` exists because `ipaddress.ip_address()` parses only dotted-quad and standard IPv6, so a
numerically-spelled host slipped past a range check as if it were a DNS name. Its docstring lists the
attack it was built for — three spellings of `169.254.169.254`, the cloud metadata service:

    http://2852039166/               (decimal)
    http://0xA9FEA9FE/               (hex integer)
    http://0251.0376.0251.0376/      (octal dotted)

A fourth spelling was **not** handled, and it was allowed through:

    http://0xa9.0xfe.0xa9.0xfe/latest/meta-data/     -> ALLOWED before this round

The bug is a branch-ordering one, and coverage is what surfaced it. `parse_ip_literal` opened with

    if candidate.lower().startswith("0x"):
        value = int(candidate, 16)

which CLAIMS `0xa9.0xfe.0xa9.0xfe` — it does start with `0x` — then fails inside `int(…, 16)` because
of the dots, so the function returned `None`, and `assert_safe_url` read `None` as "a DNS name, the
runtime policy's problem" and permitted it. The dotted-hex branch written further down
(`if octet.lower().startswith("0x"): part = int(octet, 16)`) was therefore UNREACHABLE — which is
exactly why those two statements showed as uncovered. Two lines of dead code and an open SSRF path
were the same fact.

Fixed by guarding the integer branches with `"." not in candidate`. Verified:

    parse_ip_literal("0xa9.0xfe.0xa9.0xfe")  ->  169.254.169.254      (was None)
    assert_safe_url("http://0xa9.0xfe.0xa9.0xfe/latest/meta-data/")  ->  EgressError

Scope: what this guard does NOT do, re-derived rather than assumed
-----------------------------------------------------------------
While here I also broadened the range check to refuse every non-global address (loopback, RFC 1918,
CGNAT). That looked like a strict improvement. It is not, and the repo told me so: **46 tests across
10 modules failed**, and reading them showed `test_web_search_live.py` naming
`http://127.0.0.1:8080/search` a SAFE target — because an adopter points a `*_LIVE` tool at a stub or
sidecar on the runtime's own loopback. `egress.py`'s docstring draws the same line, stating that
resolution-time concerns are "the runtime network policy's job".

So the broadening was reverted. 46 failures were evidence of a deliberate contract, not of 46 latent
bugs, and editing them to match my guess would have rewritten a design decision. That reasoning is
recorded here because "the tests assert something unsafe, so fix the tests" is the tempting and wrong
move.

The tests below therefore assert BOTH directions: every metadata spelling is refused, and loopback /
private targets are still permitted, so a future broadening cannot happen silently.

ZERO network: `assert_safe_url` and `parse_ip_literal` are pure functions over a string.
"""
from __future__ import annotations

import ipaddress

import pytest

from sentinel_harness.egress import EgressError, assert_safe_url, parse_ip_literal

# Every spelling of 169.254.169.254 a browser or the OS resolver would accept. The dotted-hex entry
# is the one that was allowed through; the others were already covered by the module docstring's
# recorded attack and are kept so a regression cannot trade one spelling for another.
_METADATA_SPELLINGS = {
    "dotted-quad": "169.254.169.254",
    "decimal-integer": "2852039166",
    "hex-integer": "0xA9FEA9FE",
    "hex-integer-lower": "0xa9fea9fe",
    "octal-dotted": "0251.0376.0251.0376",
    "octal-integer": "025177524776",
    "dotted-hex": "0xa9.0xfe.0xa9.0xfe",
}

# Hosts that are genuinely NOT IP literals and must keep resolving through DNS policy. The
# digit-leading one is load-bearing: an over-eager parser that treated it as an integer would break
# real hostnames.
_REAL_HOSTNAMES = (
    "example.com",
    "search.example.internal",
    "1backend.example.com",
    "0xdeadbeef.example.com",
)


@pytest.mark.parametrize(("label", "spelling"), sorted(_METADATA_SPELLINGS.items()))
def test_every_metadata_spelling_parses_to_the_metadata_address(label, spelling):
    """The parser must recognise all of them as one address.

    Asserted on the PARSED VALUE, not merely "returned something". A parser that resolved
    `0xa9.0xfe.0xa9.0xfe` to some other address would satisfy a not-None check while still failing to
    identify the target the range check is looking for.
    """
    parsed = parse_ip_literal(spelling)
    assert parsed is not None, (
        f"{label} spelling {spelling!r} was not recognised as an IP literal at all, so "
        "assert_safe_url treats it as a DNS name and permits it. This is the bug shape that let "
        "`0xa9.0xfe.0xa9.0xfe` through: the branch written for it was unreachable."
    )
    assert parsed == ipaddress.ip_address("169.254.169.254"), (
        f"{label} spelling {spelling!r} parsed to {parsed}, not the metadata address"
    )


@pytest.mark.parametrize(("label", "spelling"), sorted(_METADATA_SPELLINGS.items()))
def test_every_metadata_spelling_is_refused_by_the_url_guard(label, spelling):
    """End to end: the URL form of each spelling must raise.

    Separate from the parser test because they can diverge — the parser could be right while the
    range check misses the class, which is how `::1` was being caught only incidentally (as
    `is_reserved`) rather than deliberately.
    """
    url = f"http://{spelling}/latest/meta-data/iam/security-credentials/"
    with pytest.raises(EgressError) as excinfo:
        assert_safe_url(url)
    message = str(excinfo.value)
    assert "non-routable" in message or "metadata" in message, (
        f"{label} was refused, but the message does not say why: {message!r}. A caller logging this "
        "needs to know it was an SSRF-shaped target rather than a transport error."
    )


def test_the_dotted_hex_spelling_specifically_regresses_loudly():
    """The exact string that was allowed, kept as its own named test.

    Parametrised coverage above would catch this too, but a regression here should name the CVE-shaped
    case directly rather than surfacing as `[dotted-hex]` in a list — the next reader should not have
    to reconstruct which spelling was the live bug.
    """
    host = "0xa9.0xfe.0xa9.0xfe"
    assert parse_ip_literal(host) == ipaddress.ip_address("169.254.169.254"), (
        "the dotted-hex metadata spelling is unparsed again. Check the branch order in "
        "`parse_ip_literal`: the integer branches must be guarded with `'.' not in candidate`, or "
        "`startswith('0x')` claims this dotted host, fails inside int(…, 16), and the function "
        "returns None — which assert_safe_url reads as a permissible DNS name."
    )
    with pytest.raises(EgressError):
        assert_safe_url(f"http://{host}/latest/meta-data/")


@pytest.mark.parametrize("hostname", _REAL_HOSTNAMES)
def test_a_real_hostname_is_not_mistaken_for_an_ip_literal(hostname):
    """The other direction: the parser must not over-claim.

    `parse_ip_literal` returning something for `1backend.example.com` would send a legitimate
    hostname into the numeric range check and refuse it. `0xdeadbeef.example.com` is the sharpest
    case — it starts with `0x`, which is precisely the prefix whose over-eager match caused the bug
    this module records.
    """
    assert parse_ip_literal(hostname) is None, (
        f"{hostname!r} was parsed as an IP literal, so a real DNS name would be range-checked as a "
        "number. The parser must return None for anything that is not an IP in some spelling."
    )
    # And it must be permitted, since resolution is the runtime policy's business.
    assert_safe_url(f"https://{hostname}/api")


@pytest.mark.parametrize("spelling", ["0177.0.0.1", "2130706433", "0x7f.0x0.0x0.0x1", "0x7f000001"])
def test_loopback_spellings_all_parse_even_though_they_are_permitted(spelling):
    """Parsing and policy are separate concerns, and this pins the separation.

    Every loopback spelling must PARSE — a parser blind to `0x7f.0x0.0x0.0x1` is blind to
    `0xa9.0xfe.0xa9.0xfe` for the same reason. Whether loopback egress is then ALLOWED is the range
    check's decision, and today it is allowed on purpose (see the next test).
    """
    assert parse_ip_literal(spelling) == ipaddress.ip_address("127.0.0.1"), (
        f"loopback spelling {spelling!r} did not parse; the same parser gap would hide a metadata "
        "address written the same way"
    )


@pytest.mark.parametrize("url", [
    "http://127.0.0.1:8080/search",
    "http://10.0.0.5/internal",
    "http://192.168.1.1/router",
])
def test_loopback_and_private_targets_stay_permitted_by_design(url):
    """The scope boundary, asserted so it cannot be tightened by accident.

    I broadened this guard to refuse every non-global address and it failed 46 tests across 10
    modules. `test_web_search_live.py` names `http://127.0.0.1:8080/search` a SAFE target: an adopter
    points a `*_LIVE` tool at a stub or sidecar on the runtime's own loopback, and `egress.py`'s
    docstring assigns resolution-time concerns to "the runtime network policy". Those 46 failures
    were evidence of a deliberate contract, not of 46 latent bugs.

    This test states that contract in one place. If a future round decides loopback egress SHOULD be
    refused, that is a legitimate design change — but it must be made deliberately, updating this
    test and the module docstring together, rather than discovered as collateral damage.
    """
    assert_safe_url(url)  # must not raise


@pytest.mark.parametrize("malformed", [
    "999.1.1.1",        # octet out of range
    "256.0.0.1",        # one past the boundary
    "1.2.3",            # too few octets
    "1.2.3.4.5",        # too many
    "4294967296",       # one past 32 bits
    "0x100000000",      # same, in hex
    "-1",
    "",
    "   ",
])
def test_a_malformed_numeric_host_is_not_parsed_as_an_address(malformed):
    """Out-of-range and mis-shaped numerics must return None, not a wrapped-around address.

    `4294967296` and `0x100000000` cover the 32-bit ceiling, and the empty/whitespace cases pin the
    early return so a blank host cannot be coerced into `0.0.0.0` (which `is_unspecified` would then
    refuse for the wrong reason).

    A recorded EQUIVALENT MUTANT, so nobody spends time on it again. Deleting the per-octet
    `0 <= part <= 255` check survives this module — and that is not a gap in these assertions.
    Measured: with the check removed, `999.1.1.1`, `256.0.0.1` and `300.300.300.300` still return
    `None`, because an out-of-range octet shifts `value` past `0xFFFFFFFF` and the 32-bit ceiling
    check below catches it. The two checks overlap by construction, so the octet one is redundant
    defence rather than the only barrier. My first version of this docstring asserted the opposite —
    that the mutation proved a hole — which was a guess about the mechanism rather than a
    measurement of it.
    """
    assert parse_ip_literal(malformed) is None, (
        f"{malformed!r} parsed as {parse_ip_literal(malformed)}. A malformed numeric host must be "
        "rejected outright: silently wrapping it into a valid address means the range check runs "
        "against an address nobody supplied."
    )


def test_the_scheme_and_host_preconditions_still_hold():
    """Adjacent guarantees, cheap to assert while here.

    A non-HTTP scheme (`file://`, `gopher://`) and a host-less URL are refused before any IP parsing
    happens, so a bypass cannot come from the parser being handed something it was never meant to
    see.
    """
    for url in ("file:///etc/passwd", "gopher://example.com/", "ftp://example.com/x"):
        with pytest.raises(EgressError) as excinfo:
            assert_safe_url(url)
        assert "scheme" in str(excinfo.value).lower(), (
            f"{url} was refused for the wrong reason: {excinfo.value}"
        )

    with pytest.raises(EgressError) as excinfo:
        assert_safe_url("http:///no-host-here")
    assert "host" in str(excinfo.value).lower(), str(excinfo.value)
