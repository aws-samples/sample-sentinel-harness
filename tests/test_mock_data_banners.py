"""INV-TOOL-1 — a tool whose default reply is a STUB says so in its README.

Every `tools/*/handler.py` with a `*_LIVE` seam returns fictional data by default and marks it
honestly in the payload (`"source": "stub"`). The README is where a human decides whether to trust
the tool, and four of the nine such READMEs carried no warning at all while one actively contradicted
the code.

Measured by CALLING each handler with no `*_LIVE` set and reading the `source` field it returns —
not by grepping for the word "mock", which is what makes the result trustworthy:

    asset_lookup    source=stub   banner absent
    attack_lookup   source=stub   banner absent
    epss_kev        source=stub   banner absent
    nvd_lookup      source=stub   banner absent
    web_search      source=stub   banner absent
    siem_query / enrich_ioc / ops_query / create_ticket   source=stub   banner PRESENT

So the repo already had the right pattern — `siem_query`'s banner says the tool "returns **no** real
threat intelligence" — and five siblings never got it. "A fix applied to one call site is not an
invariant", on a claim a SecOps reader acts on.

The worst of the five was `nvd_lookup`, whose Purpose read:

    "return authoritative vulnerability metadata (description, CVSS v3 score/severity, CWE
     identifiers, references) sourced from the NVD"

with no condition, while the default reply is `{"source": "stub", …}`. That is not a missing warning,
it is a false statement in the one direction that matters: an analyst — or an agent — reading a
fictional CVSS score as grounds to defer a real patch. Now conditioned on `NVD_LIVE=1`.

Why the scan is behavioural, and what the naive version got wrong
----------------------------------------------------------------
A first pass grepped handlers for `mock|stub|fake` and reported **8** offenders. Three were false:
`allowlist_optimizer`, `detection_translate` and `sigma_yara_lint` merely mention those words (in
comments, or as a rule-title fixture) and return deterministic COMPUTATION over caller-supplied
input — they have no `source` field because there is no external source. Demanding a MOCK-DATA
banner there would tell a reader that a real Sigma-to-KQL translation is fictional, which is worse
than saying nothing.

So the predicate is: *the handler's own default reply declares a stub source*. That is the tool
admitting it in the only place it cannot be wrong about itself. The six `tools/detection_*` handlers
have no README at all and are deliberately out of scope for the same reason — they are deterministic
detection-engineering logic, not intelligence feeds; `test_cyber_skills.py` and
`test_cli_detection_audit.py` cover them.

ZERO network, ZERO AWS: the handlers are called in their default (non-live) mode, which by contract
performs no egress — `tests/test_r17_egress_mechanized.py` and `test_mcp_boundary_hardening.py`
enforce that separately.
"""
from __future__ import annotations

import contextlib
import importlib
import io
import json
import os
import re
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS_DIR = os.path.join(REPO_ROOT, "tools")

# Values of the reply's `source` field that mean "this is fictional".
_STUB_SOURCES = {"stub", "mock", "mockdata", "synthetic", "fixture"}

# Event shapes to try, in order, until one produces a reply carrying a `source` field. Tools take
# different keys; probing rather than hard-coding per tool keeps this from silently skipping a tool
# whose signature changes.
# Ordered most-specific first. Several tools require EXACTLY ONE recognised key and refuse anything
# else (`siem_query`: "unknown query key(s) […]; expected exactly one of host, technique, …"), so a
# single catch-all dict cannot satisfy them — hence one entry per accepted shape.
#
# This list is why the positive control below is load-bearing. A first version omitted the
# `siem_query` / `ops_query` / `create_ticket` shapes; those three returned a validation refusal with
# no `source` field, the probe classified them as non-stub, and the control failed at 6 < 8. The fix
# was to teach the probe their signatures, NOT to lower the threshold — a threshold tuned down to
# match a blind probe is how a check keeps passing while covering less.
_PROBE_EVENTS = (
    {"cve_id": "CVE-2021-44228"},
    {"indicator": "192.0.2.1"},
    {"host": "host-0001"},                    # siem_query
    # ops_query accepts exactly one of account/query/finding_type, but only `account` reaches the
    # stub path — the other two need fixture data this probe does not supply. Placeholder account id
    # per the repo-wide rule that every account id is 000000000000.
    {"account": "000000000000"},
    {"title": "t", "description": "d", "severity": "low"},  # create_ticket
    {"host_id": "host-0001"},
    {"asset_id": "host-0001"},
    {"technique_id": "T1059"},
    {"technique": "T1059"},
    {"query": "example"},
    {"q": "example"},
    {},
)

# A banner must actually WARN, not merely contain the word. These are the load-bearing phrases the
# established `siem_query` banner uses.
_BANNER_RE = re.compile(r"MOCK[\s-]?DATA", re.I)


def _tool_dirs() -> list:
    return sorted(
        name for name in os.listdir(TOOLS_DIR)
        if os.path.isfile(os.path.join(TOOLS_DIR, name, "handler.py"))
    )


def _default_source(tool: str):
    """The `source` value a tool reports with NO `*_LIVE` env var set, or None.

    Imported by path under a unique module name: every tool ships a module literally called
    `handler`, so a plain import would collide across tools in one pytest process (the trap
    `test_cve_intel_container.py` records for specialists' `agent_a2a`).

    Deliberately NO `sys.path.insert`. A first version added one out of habit, and
    `test_zz_suite_hygiene.py::test_the_documented_sys_path_figures_are_current` failed — it counts
    insert sites and requires INV-TEST-2 to state how many are unguarded. Investigating instead of
    bumping the documented figure showed the insert was simply UNNECESSARY:
    `spec_from_file_location` loads from an explicit path and never consults `sys.path`. So the fix
    was to delete it, leaving the suite's `sys.path` footprint unchanged — the guard was pointing at
    real redundancy, not asking for a number.
    """
    tool_path = os.path.join(TOOLS_DIR, tool)
    module_name = f"_inv_tool_1_{tool}_handler"
    try:
        spec = importlib.util.spec_from_file_location(
            module_name, os.path.join(tool_path, "handler.py")
        )
        if spec is None or spec.loader is None:  # pragma: no cover - defensive
            return None
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        try:
            spec.loader.exec_module(module)
        except Exception:  # pragma: no cover - a tool that cannot import is another test's problem
            return None

        handler = getattr(module, "handler", None)
        if handler is None:
            return None

        for event in _PROBE_EVENTS:
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    reply = handler(event, None)
            except Exception:
                continue
            if isinstance(reply, str):
                try:
                    reply = json.loads(reply)
                except json.JSONDecodeError:
                    continue
            if isinstance(reply, dict) and "source" in reply:
                return str(reply["source"]).lower()
        return None
    finally:
        sys.modules.pop(module_name, None)


@pytest.fixture(autouse=True)
def _no_live_seams(monkeypatch):
    """Ensure NO `*_LIVE` variable leaks in from the environment.

    Without this the probe could hit a live path on a developer machine that happens to export one —
    the reply would then say `source: nvd` and the tool would be judged as not needing a banner, i.e.
    the check would silently invert on exactly the machine most likely to have those vars set.
    """
    for key in list(os.environ):
        if key.endswith("_LIVE"):
            monkeypatch.delenv(key, raising=False)


def test_the_probe_reaches_handlers_and_finds_stub_sources():
    """Positive control, and the reason it is not optional.

    Every assertion below depends on `_default_source` actually invoking a handler. If the import
    shim broke it would return None for all 20 tools, no tool would be classified as stub-serving,
    and the module would report green while checking nothing — the vacuous-pass shape this repo
    records most.
    """
    tools = _tool_dirs()
    assert len(tools) >= 20, f"only {len(tools)} tools discovered: {tools}"

    sources = {tool: _default_source(tool) for tool in tools}
    stub_serving = [tool for tool, src in sources.items() if src in _STUB_SOURCES]
    assert len(stub_serving) >= 8, (
        f"only {len(stub_serving)} tool(s) reported a stub source: {stub_serving}\n"
        f"all sources: {sources}\n"
        "Either the probe stopped reaching handlers or the tools stopped declaring `source` — both "
        "must fail loudly rather than empty the check."
    )


@pytest.mark.parametrize("tool", _tool_dirs())
def test_a_stub_serving_tool_warns_in_its_readme(tool):
    """THE defect: five tools returned `source: stub` with no warning in their README.

    The predicate is BEHAVIOURAL — the handler's own default reply declares a stub source — because a
    keyword grep over handlers reported three false positives (`allowlist_optimizer`,
    `detection_translate`, `sigma_yara_lint` merely MENTION mock/stub while returning deterministic
    computation over caller input). Demanding a MOCK-DATA banner on those would tell a reader that a
    real Sigma translation is fictional.

    A tool with no README is not failed here: the six `tools/detection_*` handlers ship none by
    design and serve no external data. Only a tool that BOTH declares a stub source AND documents
    itself must carry the warning.
    """
    source = _default_source(tool)
    if source not in _STUB_SOURCES:
        pytest.skip(
            f"{tool} does not report a stub source by default (source={source!r}); it serves "
            "computation rather than a simulated feed, so a MOCK-DATA banner would misinform."
        )

    readme_path = os.path.join(TOOLS_DIR, tool, "README.md")
    if not os.path.isfile(readme_path):
        pytest.skip(
            f"{tool} ships no README.md, so there is no document to carry the warning. (The "
            "detection_* tools are in this category by design.)"
        )

    with open(readme_path, encoding="utf-8") as fh:
        readme = fh.read()

    assert _BANNER_RE.search(readme), (
        f"tools/{tool}/README.md has no MOCK-DATA warning, but the handler returns "
        f'`"source": "{source}"` by default — fictional data.\n\n'
        "A SecOps reader acts on this: a fictional CVSS score, a fictional 'not in KEV', or a "
        "fictional 'not internet-facing' can each justify NOT fixing something real. Mirror the "
        "banner in tools/siem_query/README.md, naming this tool's own `*_LIVE` variable and what "
        "the stub actually contains."
    )


@pytest.mark.parametrize("tool", _tool_dirs())
def test_a_stub_serving_readme_does_not_claim_authority_unconditionally(tool):
    """The banner is necessary but not sufficient — the prose must not contradict it.

    `nvd_lookup` had the worst version of this: its Purpose said "return **authoritative**
    vulnerability metadata … **sourced from the NVD**" with no condition, while every default reply
    is `{"source": "stub"}`. A banner higher up does not undo a false sentence lower down; a reader
    skimming for what the tool does lands on Purpose.

    So an authority word may appear only if the same sentence names the live seam that makes it
    true. Checked per sentence rather than per file, because "authoritative" and "NVD_LIVE=1"
    co-occurring somewhere in a long README proves nothing about the claim a reader reads.
    """
    source = _default_source(tool)
    if source not in _STUB_SOURCES:
        pytest.skip(f"{tool} is not stub-serving by default (source={source!r})")

    readme_path = os.path.join(TOOLS_DIR, tool, "README.md")
    if not os.path.isfile(readme_path):
        pytest.skip(f"{tool} ships no README.md")

    with open(readme_path, encoding="utf-8") as fh:
        readme = fh.read()

    # Sentence-ish split: prose in these READMEs wraps, so join lines within a paragraph first.
    paragraphs = re.split(r"\n\s*\n", readme)
    offenders = []
    for paragraph in paragraphs:
        if paragraph.lstrip().startswith(">"):
            continue  # the banner itself is allowed to discuss authority in order to deny it
        if paragraph.lstrip().startswith("```"):
            continue  # code blocks are not prose claims
        flat = " ".join(paragraph.split())
        for sentence in re.split(r"(?<=[.!?])\s+", flat):
            if not re.search(r"\bauthoritative\b", sentence, re.I):
                continue
            # Permitted only when the same sentence conditions it on the live seam.
            if re.search(r"_LIVE\b|\bunder\b.*\bLIVE\b", sentence):
                continue
            offenders.append(sentence.strip()[:200])

    assert not offenders, (
        f"tools/{tool}/README.md calls its output authoritative without naming the `*_LIVE` seam "
        f"that would make it so, while the default reply is `\"source\": \"{source}\"`:\n  "
        + "\n  ".join(offenders)
        + "\n\nCondition the sentence (\"under `X_LIVE=1` that metadata is authoritative; by "
        "default it is the fictional stub\") rather than deleting the word — the live path really "
        "does return authoritative data, and saying so is useful."
    )


def test_the_established_banner_pattern_still_exists_to_copy():
    """Guard the reference the failure messages point at.

    Both messages above tell the reader to mirror `tools/siem_query/README.md`. If that banner were
    ever removed, the advice would point at nothing — the INV-CI-5 defect (a guard whose remediation
    does not exist) in miniature.
    """
    reference = os.path.join(TOOLS_DIR, "siem_query", "README.md")
    assert os.path.isfile(reference), (
        "tools/siem_query/README.md is gone, but this module's failure messages cite it as the "
        "banner to copy. Point them at another example or restore it."
    )
    with open(reference, encoding="utf-8") as fh:
        text = fh.read()
    assert _BANNER_RE.search(text), (
        "tools/siem_query/README.md no longer carries a MOCK-DATA banner, so the pattern this "
        "module tells contributors to mirror no longer exists."
    )
    assert re.search(r"\bno\b.*real threat intelligence", text, re.I), (
        "the siem_query banner no longer states plainly that it returns no real threat "
        "intelligence — that sentence is what makes it a warning rather than a label."
    )
