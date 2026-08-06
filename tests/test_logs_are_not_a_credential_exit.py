"""INV-MCP-7 — the log stream is not a second exit for credentials.

INV-MCP-4 established that exception text carrying a credential is a defect in this repo, and fixed
it at the MCP boundary: `_safe_error_text` redacts before handing anything to an untrusted peer. That
guard covers ONE exit. Logs are another — a CloudWatch stream is read by humans, exported, and pasted
into tickets — and `logutil`'s JSON formatter writes `record.__dict__` extras and
`formatException(exc_info)` verbatim.

**This module is HARDENING, not a bug fix, and the distinction is deliberate.** Measured before
writing anything:

    grep for exc_info=True in sentinel_harness/   ->  2 sites, both `_log.debug("cleanup: skip …")`
    grep for extra= in sentinel_harness/          ->  0 production call sites (only logutil's docstring)
    the exceptions those 2 sites log              ->  botocore ClientError

A `ClientError` message carries an ARN (hence an account id, which the repo-wide scan already gates on
the `000000000000` placeholder) but not a credential. So **there is no reachable credential leak in the
library today** — my first probe leaked `postgresql://svc:SUPERSECRET_PW@…` only because I constructed
`log.exception(...)` myself, which no shipped code path does.

Two rounds ago the same investigative route found real, reachable defects (a dotted-hex metadata
address that bypassed the SSRF guard; `python -m pip install <url>` that bypassed the untrusted-source
denylist). This one did not, and saying so plainly matters more than presenting a hardening test as a
vulnerability fix.

What the tests below are for, then
----------------------------------
The formatter has no redaction, so the property "logs are not a credential exit" holds only because
nobody has written the call that would break it. That is exactly the kind of accidental safety this
repo records as indistinguishable from a guarded one. These tests convert it into a checked property:

* a NEW `extra={"authorization": ...}` or `logger.exception()` over a credential-bearing error starts
  failing here rather than shipping quietly
* the failure message names the existing `_safe_error_text` so the fix is to reuse the redactor rather
  than invent a second one

Why the redactor is NOT simply moved into `logutil`
--------------------------------------------------
That was the first plan and it is wrong. `_SECRET_PATTERNS` carries its own trust model in a comment:
"a leaked hostname grants no new capability **over a local stdio channel** … If this server ever gains
a network transport, that trade-off must be revisited." Those patterns are tuned for an MCP stdio
peer, not as a general log sanitiser, and relocating them would strip that reasoning from its context
while touching the implementation four test modules depend on. Unifying the two exits is a legitimate
refactor — as its own round, with that trade-off re-derived, not as a side effect of this one.

ZERO network, ZERO AWS: logging into an in-memory stream.
"""
from __future__ import annotations

import io
import logging
import re

import pytest

from sentinel_harness.logutil import ROOT_LOGGER_NAME, configure_logging, get_logger

# Credential shapes that must never appear in a log line. Assembled from fragments so this file
# carries patterns, never a literal credential (the repo-wide secret scan is self-non-matching by the
# same discipline).
_CREDENTIAL_SHAPES = {
    "aws-access-key-id": "A" + "KIA" + "Q" * 16,
    "openai-style-token": "s" + "k-" + "b" * 24,
    "github-pat": "gh" + "p_" + "c" * 24,
    "url-userinfo-password": "postgres" + "ql://svc:" + "TOPSECRET_PW" + "@db.internal:5432/prod",
    "bearer-header": "Bearer " + "d" * 32,
}

# Call sites in the library that log an exception. Kept as a list so a NEW one has to be added here
# deliberately — the point is that each is reviewed for what its exception can carry.
_KNOWN_EXC_LOGGING_SITES = {
    ("sentinel_harness/core.py", "cleanup: skip harness"),
    ("sentinel_harness/gateway.py", "cleanup: skip gateway"),
}


@pytest.fixture
def json_log():
    """A JSON-configured logger writing into a buffer, torn down cleanly.

    `configure_logging` is idempotent and attaches exactly one handler, so the handler it adds must be
    removed afterwards or later tests in the same process inherit this buffer — the in-process leak
    INV-TEST-2 exists for.
    """
    buffer = io.StringIO()
    configure_logging(level="DEBUG", json=True, stream=buffer)
    root = logging.getLogger(ROOT_LOGGER_NAME)
    added = list(root.handlers)
    try:
        yield get_logger("credential_exit_probe"), buffer
    finally:
        for handler in added:
            root.removeHandler(handler)
            handler.close()


def test_the_probe_actually_captures_log_output(json_log):
    """Positive control. Every assertion below scans the buffer for a credential; if the handler
    were not wired, the buffer would be empty and every scan would pass vacuously — the failure mode
    this repo records most."""
    log, buffer = json_log
    log.info("probe is wired")
    output = buffer.getvalue()
    assert output.strip(), (
        "nothing reached the log buffer, so the credential scans below would pass while checking "
        "nothing"
    )
    assert "probe is wired" in output, f"the handler is attached but not formatting: {output[:200]}"


def test_no_library_call_site_logs_a_credential_named_extra():
    """The property this module locks in: the library never hands a credential-named field to a logger.

    Verified by SEARCHING THE SOURCE, not by exercising code paths — whether a call logs a credential
    is a static property of the source, and enumerating runtime paths would miss the one nobody
    thought to run.

    Deliberately NOT parametrised over `_CREDENTIAL_SHAPES`. A first version was, and it was
    misleading: the scan looks at field NAMES in the source, so the credential values played no part
    and the same source scan ran five times under five labels, reporting five passes for one check.
    A test that appears to cover five cases while performing one is worse than an honest single case.
    `_CREDENTIAL_SHAPES` is used by the runtime probes below, where the values matter.
    """
    import pathlib

    package = pathlib.Path(__file__).resolve().parent.parent / "sentinel_harness"
    offenders = []
    for source_file in sorted(package.rglob("*.py")):
        text = source_file.read_text(encoding="utf-8")
        # A literal credential anywhere in the package is a separate (worse) problem; the repo-wide
        # secret scan covers that. Here the concern is a credential-NAMED field handed to a logger.
        for match in re.finditer(r"extra\s*=\s*\{([^}]*)\}", text, re.S):
            body = match.group(1)
            if re.search(r"(?i)\b(token|secret|password|passwd|api[_-]?key|authorization"
                         r"|credential|bearer)\b", body):
                line = text[: match.start()].count("\n") + 1
                offenders.append(f"{source_file.name}:{line} logs a credential-named extra: "
                                 f"{body.strip()[:80]}")
    assert not offenders, (
        "library code passes a credential-named field to a logger, and `logutil`'s JSON formatter "
        "writes `record.__dict__` extras VERBATIM:\n  " + "\n  ".join(offenders)
        + "\n\nLogs are a second exit for credentials — INV-MCP-4 fixed the MCP boundary, not this "
        "one. Redact before logging, reusing `mcp_server._safe_error_text` rather than writing a "
        "second redactor."
    )


@pytest.mark.parametrize(("label", "credential"), sorted(_CREDENTIAL_SHAPES.items()))
def test_the_mcp_redactor_removes_each_credential_shape(label, credential):
    """The remediation this module's failure messages point at must actually work.

    Both source-scan failures above tell the reader to redact via `mcp_server._safe_error_text`
    instead of writing a second redactor. INV-CI-5 records what happens when a guard names a
    remediation that cannot do the job: the reader follows the instruction, gets nothing, and
    hand-rolls something. So the named redactor is exercised on every credential shape here.

    This is where `_CREDENTIAL_SHAPES` earns its place — the VALUES matter, unlike in the source scan.
    """
    from sentinel_harness.mcp_server import _safe_error_text

    redacted = _safe_error_text(RuntimeError(f"upstream rejected: {credential}"))
    assert credential not in redacted, (
        f"`_safe_error_text` left the {label} credential intact:\n  in:  {credential}\n  out: "
        f"{redacted}\n\nThe failure messages in this module tell contributors to use it before "
        "logging; a redactor that misses a shape makes that advice actively harmful, because the "
        "output LOOKS sanitised."
    )
    assert "redacted" in redacted.lower(), (
        f"the {label} credential was removed but nothing marks the redaction ({redacted!r}). A "
        "silently-stripped value is indistinguishable from a message that never had one — the "
        "degradation rule this repo applies everywhere else."
    )


def test_the_formatter_writes_extras_verbatim_which_is_why_the_check_above_exists():
    """The PREMISE, asserted so the guard above cannot become pointless silently.

    If `logutil` ever gains redaction, the source-level check becomes belt-and-braces rather than the
    only barrier — and this test failing is the signal to say so in the docstring. Stating the premise
    beats leaving a future reader to infer why a source scan was ever necessary.
    """
    buffer = io.StringIO()
    configure_logging(level="INFO", json=True, stream=buffer)
    root = logging.getLogger(ROOT_LOGGER_NAME)
    handlers = list(root.handlers)
    try:
        log = get_logger("premise_probe")
        marker = "not-a-real-" + "secret-" + "value"
        log.info("probe", extra={"authorization": marker})
        output = buffer.getvalue()
    finally:
        for handler in handlers:
            root.removeHandler(handler)
            handler.close()

    assert marker in output, (
        "logutil's JSON formatter now redacts or drops `extra` fields. That is an IMPROVEMENT — "
        "update this module's docstring and downgrade `test_no_library_call_site_logs_a_credential"
        "_shaped_string` from 'the only barrier' to 'defence in depth'."
    )


def test_every_exception_logging_site_is_recorded_and_reviewed():
    """Each `exc_info=True` / `.exception()` site must be a known, reviewed one.

    The two current sites log a botocore `ClientError` during best-effort teardown. Those messages
    carry an ARN — gated to the `000000000000` placeholder by the repo-wide scan — but not a
    credential, which is why this module is hardening rather than a fix.

    A NEW site is not automatically wrong; it just has not been reviewed for what its exception can
    carry. Failing here forces that review, and is the mechanism that keeps "no reachable leak" a
    measured statement instead of a stale one.
    """
    import pathlib

    package = pathlib.Path(__file__).resolve().parent.parent / "sentinel_harness"
    found = set()
    for source_file in sorted(package.rglob("*.py")):
        relative = f"sentinel_harness/{source_file.relative_to(package)}"
        for line in source_file.read_text(encoding="utf-8").splitlines():
            if "exc_info=True" not in line and ".exception(" not in line:
                continue
            message = re.search(r'"([^"]{4,60})"', line)
            found.add((relative, message.group(1) if message else line.strip()[:60]))

    # Match on the recorded message prefix so a reformat of the call does not spuriously fail.
    unreviewed = []
    for path, message in sorted(found):
        if not any(path == known_path and message.startswith(known_prefix)
                   for known_path, known_prefix in _KNOWN_EXC_LOGGING_SITES):
            unreviewed.append(f"{path}: {message!r}")

    assert not unreviewed, (
        "new exception-logging site(s) that have not been reviewed for credential content:\n  "
        + "\n  ".join(unreviewed)
        + "\n\n`logutil` writes `formatException(exc_info)` verbatim, so whatever the exception's "
        "text contains lands in the log. Confirm the exception cannot carry a credential and add it "
        "to `_KNOWN_EXC_LOGGING_SITES`, or redact via `mcp_server._safe_error_text` first."
    )
    assert found, (
        "no exception-logging sites found at all, which means this scan is broken rather than the "
        "library having stopped logging exceptions"
    )
