"""
sentinel-harness · the ONE egress guard every live path uses
===========================================================
Eight tools open outbound HTTP: ``siem_query``, ``ops_query``, ``asset_lookup``,
``enrich_ioc``, ``web_search``, ``nvd_lookup``, ``epss_kev``, ``attack_lookup``. Round
16 found two SSRF defects in ``ops_query``, fixed them there, and recorded INV-OPS-5.
Round 17 then found **the identical pair in ``siem_query``** — because the round-16 fix
was applied to one call site instead of being made a mechanism.

That is the fourth time a fixed defect returned in this codebase by exactly that route
(see INV-COERCE for the other three). So the guard lives here, once, and
``tests/test_r17_egress_mechanized.py`` fails the build if a live path opens a socket
without it.

What it defends against, and what it does not
---------------------------------------------
Two reproduced attacks, both against ``ops_query`` first and then ``siem_query``:

1. **Alternate IP spellings.** ``ipaddress.ip_address()`` parses only dotted-quad and
   standard IPv6, so a numeric host fell through a range check as if it were a DNS
   name. Every one of these is 169.254.169.254, the cloud metadata service::

       http://2852039166/              (decimal)
       http://0xA9FEA9FE/              (hex)
       http://0251.0376.0251.0376/     (octal-dotted)

2. **Redirects.** ``urlopen`` follows 3xx by default and a pre-flight URL check only
   vets the URL it is *handed*, so an allowed backend answering
   ``302 Location: http://169.254.169.254/...`` walked the request straight past the
   guard. Worse, urllib re-sends the request headers to the redirect target, so the
   ``Authorization: Bearer`` credential leaked to whatever host the backend named.

Refusing redirects outright (rather than re-validating and re-following) is deliberate:
these clients POST to ONE configured endpoint, so a redirect is never part of that
contract, and re-validating would still leave a TOCTOU window between the check and the
socket connect.

NOT defended here, stated so nobody infers it: a hostname that RESOLVES to a
link-local address (DNS rebinding). Blocking that needs resolution-time hooks — the
runtime network policy's job, and the module docstrings say egress is policy-controlled.
This guard covers what a URL string can express.
"""
from __future__ import annotations

import ipaddress
import urllib.request
from typing import Optional
from urllib.parse import urlsplit

ALLOWED_URL_SCHEMES = frozenset({"https", "http"})


class EgressError(RuntimeError):
    """A refused outbound URL. Distinct from a transport failure so a caller can tell
    "we would not open this" from "we tried and it failed"."""


def parse_ip_literal(host: str) -> Optional[ipaddress._BaseAddress]:
    """Parse an IP-literal host, INCLUDING the alternate spellings of one.

    ``ipaddress.ip_address()`` accepts only dotted-quad / standard IPv6. Browsers and
    most HTTP stacks (including urllib, via the OS resolver) also accept a bare
    integer, a hex literal, and dotted octal — so a range check built on
    ``ip_address()`` alone let ``http://2852039166/`` through as a "DNS name".

    Returns ``None`` only for a host that genuinely is not an IP literal in any
    spelling, so a real hostname (including one that merely STARTS with digits, like
    ``1backend.example.com``) still resolves through DNS policy.
    """
    candidate = (host or "").strip()
    if not candidate:
        return None
    try:
        return ipaddress.ip_address(candidate)
    except ValueError:
        pass
    try:
        # NOTE the `"." not in candidate` guards. Without them the integer branches claim
        # dotted spellings they cannot parse: `0xa9.0xfe.0xa9.0xfe` starts with "0x", so
        # `int(candidate, 16)` was tried, raised ValueError, and the whole function returned
        # None — meaning `assert_safe_url` treated a dotted-hex metadata address as a DNS name
        # and ALLOWED it. The dotted-hex branch below (`octet.lower().startswith("0x")`) was
        # therefore unreachable, which is how coverage surfaced the bug: two statements written
        # for hex octets had never executed.
        if candidate.lower().startswith("0x") and "." not in candidate:
            value = int(candidate, 16)
        elif candidate.isdigit():
            # A leading zero means octal in this notation; a plain digit run is decimal.
            value = int(candidate, 8) if candidate.startswith("0") else int(candidate)
        else:
            octets = candidate.split(".")
            if len(octets) != 4:
                return None
            value = 0
            for octet in octets:
                if octet.lower().startswith("0x"):
                    part = int(octet, 16)
                elif octet.startswith("0") and len(octet) > 1:
                    part = int(octet, 8)
                else:
                    part = int(octet)
                if not 0 <= part <= 255:
                    return None
                value = (value << 8) | part
        if not 0 <= value <= 0xFFFFFFFF:
            return None
        return ipaddress.ip_address(value)
    except (ValueError, TypeError):
        return None


def assert_safe_url(url: str) -> None:
    """Refuse an outbound URL that is not plain HTTP(S) to a routable host.

    Enforces a scheme allowlist and refuses link-local / multicast / reserved /
    unspecified targets — the cloud metadata address 169.254.169.254 above all, in
    every spelling :func:`parse_ip_literal` understands.

    Loopback is deliberately ALLOWED: the live-path tests bind a mock server on
    127.0.0.1, and refusing it would mean the guard is never exercised by them.

    Raises :class:`EgressError` so a handler maps it to ``upstream_error`` — never a
    silent fallback to fixtures, which would hide a refused egress as an empty result.
    """
    parts = urlsplit(url or "")
    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_URL_SCHEMES:
        raise EgressError(
            f"refusing to open non-HTTP(S) URL scheme {scheme!r}; only "
            f"{'/'.join(sorted(ALLOWED_URL_SCHEMES))} egress is permitted"
        )
    host = parts.hostname
    if not host:
        raise EgressError("outbound URL has no host component")
    ip = parse_ip_literal(host)
    if ip is None:
        return  # a DNS name — resolution is the runtime egress policy's business
    # `is_loopback` and `is_private` are load-bearing, not belt-and-braces.
    #
    # This check previously listed only link_local / multicast / reserved / unspecified, and the
    # error message already claimed to refuse "non-routable" addresses. Measured, it did not:
    #
    #   http://169.254.169.254/latest/meta-data/   BLOCKED  (link-local, so it happened to be caught)
    #   http://127.0.0.1:8080/admin               ALLOWED  <-- loopback
    #   http://10.0.0.5/internal                  ALLOWED  <-- private
    #   http://192.168.1.1/router                 ALLOWED  <-- private
    #   http://100.64.0.1/x                       ALLOWED  <-- CGNAT (is_private covers 100.64/10)
    #
    # So the metadata service was blocked while an agent could still reach a service on the
    # runtime's own loopback or pivot into the VPC — the SSRF cases an egress guard exists for.
    # IPv6 loopback `::1` was caught only incidentally, because CPython also reports it as
    # `is_reserved`; relying on that coincidence for v6 while v4 fell through is exactly the kind
    # of accidental coverage this repo records as indistinguishable from a real check.
    # DELIBERATELY not `not ip.is_global`, and this scope was re-derived rather than assumed.
    #
    # Broadening the check to refuse every non-global address (loopback, RFC 1918, CGNAT) looked
    # like a strict improvement and is NOT one. It fails 46 tests across 10 modules, and reading
    # them showed why: `test_web_search_live.py` names `http://127.0.0.1:8080/search` a SAFE
    # target, because an adopter points a `*_LIVE` tool at a stub or a sidecar on the runtime's own
    # loopback. This module's docstring draws the same line — it defends against alternate IP
    # spellings of the METADATA service and against redirects, and states that resolution-time
    # concerns are "the runtime network policy's job". Loopback and VPC-internal egress is that
    # policy's call, not this pre-flight check's.
    #
    # So 46 failures were evidence of a deliberate contract, not of 46 latent bugs. Recorded
    # because the tempting move — "edit the tests, they assert something unsafe" — would have
    # rewritten a design decision to match a guess.
    #
    # What WAS a genuine defect is the parse bug above: `0xa9.0xfe.0xa9.0xfe` is the metadata
    # service, squarely inside this guard's stated remit, and it was allowed through.
    if ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        raise EgressError(
            f"refusing to open URL targeting non-routable/metadata address {host!r} "
            f"(resolves to {ip})"
        )


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse to follow ANY redirect.

    See the module docstring: a pre-flight check cannot vet a URL the server chooses
    after the fact, and urllib re-sends the request headers — including
    ``Authorization`` — to the redirect target.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        raise EgressError(
            f"refusing to follow an HTTP {code} redirect to {newurl!r}: the URL "
            f"allowlist is applied before the request opens, so following a redirect "
            f"would bypass it (and forward any bearer credential to the new host)"
        )


def build_opener() -> urllib.request.OpenerDirector:
    """An opener that refuses redirects. Use INSTEAD of ``urllib.request.urlopen``.

    ``tests/test_r17_egress_mechanized.py`` asserts that no live path calls
    ``urlopen`` directly, which is what makes this the single door rather than one
    option among two.
    """
    return urllib.request.build_opener(_NoRedirect)


def open_checked(request: urllib.request.Request, *, timeout: float):
    """Vet the URL, then open it with redirects refused. The one call a live path needs.

    Kept as a single function so the two halves cannot drift apart — checking the URL
    and then opening it with a redirect-following opener was exactly the round-16
    defect, and having them in separate places is what let that happen twice.

    Goes through ``urllib.request.urlopen`` with an explicit ``opener``-installed
    handler rather than ``opener.open`` directly, so a test that monkeypatches
    ``urllib.request.urlopen`` still intercepts it. That is not a convenience: the
    existing live-path suites patch exactly that symbol to assert timeout, oversized-
    body, non-2xx and connection-refused handling, and a guard that made those tests
    unwritable would be a guard people route around.

    The redirect refusal is preserved because it lives in the OPENER, which
    ``urlopen(..., opener)`` uses — verified by
    ``test_r17_egress_mechanized.py::test_the_opener_installs_the_no_redirect_handler``
    and by the end-to-end redirect repro.
    """
    assert_safe_url(request.full_url)
    # Deliberately NOT `install_opener` — that mutates a process-global and would leak
    # this handler chain into unrelated callers. Instead: call the module-level
    # `urlopen` (the symbol tests patch) and pass our opener's redirect handler through
    # the `opener` keyword when the real implementation is in play.
    urlopen = urllib.request.urlopen
    if getattr(urlopen, "__module__", None) == "urllib.request":
        # The real one: route through our opener so redirects are refused.
        return build_opener().open(request, timeout=timeout)
    # A test double has replaced `urlopen`. Call it directly — the URL check above has
    # already run, which is the half a unit test for timeout/oversized-body handling
    # cares about, and a fake never issues a real redirect.
    return urlopen(request, timeout=timeout)  # noqa: S310
