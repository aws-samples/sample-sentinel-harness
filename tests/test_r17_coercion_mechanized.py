"""
Round-17 — mechanizing the invariants that RECURRED.
====================================================
Nine audit rounds produced 106 invariants. Three of them came back after being
"fixed", and every recurrence had the same cause: the invariant was written down as
a CONVENTION, so the next author — or the same author on a different code path —
reimplemented the trap.

    INV-BOUNDARY-1  (round 14)  bare bool() on external data, in asset_lookup
      -> INV-GATE-3 (round 15)  the SAME defect in run_evaluation, one round later
      -> INV-COERCE-1 (here)    the SAME defect in siem_query's OFFLINE normalizer,
                                sitting in the file whose LIVE normalizer R13b fixed

    INV-PROMOTE-2   (M18)       approval not bound to a subject, in agent_loop
      -> INV-PLAY-6 (round 16)  the SAME hole in simulation's per-step gate

A pattern that returns twice will return a third time. It already did: the
siem_query offline path was found by an AST sweep written for this module, after two
rounds of hand-auditing that file had missed it — because it was in the file the fix
had already landed in, which is the last place anyone looks.

So this module does not test behaviour. It tests the CODEBASE, structurally:

  INV-COERCE-1  no bare bool() is applied to externally-sourced data; those sites
                delegate to the authoritative coercion
  INV-COERCE-2  every coercion helper in the repo agrees with that authority
  INV-COERCE-3  a callback whose contract says `-> bool` is not silently widened
                to accept truthy strings

Why a structural test and not more unit tests
--------------------------------------------
A unit test proves one call site is right today. It says nothing about the next one.
These assertions fail when a NEW violation is introduced anywhere in the package,
which is the only thing that stops a fourth recurrence — and they name the file and
line, so the fix is mechanical.

The allowlist below is the interesting part. Every entry is a site where bare bool()
is CORRECT, with the reason recorded. An entry is a claim that the value is not
external, and a reviewer can check it. Keeping the list explicit is what makes the
sweep honest: a blanket "skip the tools directory" would have hidden the siem_query
defect.

Zero network, zero AWS, zero LLM: this reads source with `ast`.
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

# Directories whose code runs against data we do not control.
_SCANNED_TREES = ("sentinel_harness", "tools", "intake")

# Call/attribute names that mean "this value came out of a payload we parsed, an
# environment variable, or a file" — i.e. it can be a string even when the shape
# says boolean. `.get(` is the dominant one: every recurrence so far was
# `bool(<something>.get("field"))`.
_EXTERNAL_MARKERS = ("get", "environ", "getenv", "loads", "load", "read",
                     "fromjson", "json")

# Sites where bare bool() is CORRECT, keyed by "<relpath>::<the exact expression>".
#
# THE GRANULARITY IS THE POINT, and my first attempt got it wrong: keying by FILE
# exempted the whole file forever. A positive control proved it — injecting
# `bool(payload.get("looks_malicious"))` into feedback.py was NOT caught, because that
# file already held one legitimate `bool(withheld)`. I had built a fail-open into a
# mechanism whose entire purpose is to prevent fail-open, which is the same shape as
# the rule "a lint-exempt directory is a directory that never gets fixed".
#
# Keying by expression rather than line number is deliberate too: a line number drifts
# on every edit above it, which would turn this into churn and train people to
# rubber-stamp it. An expression is stable, readable in a diff, and — the property
# that matters — NEW code cannot accidentally match an existing entry.
# Only FOUR entries, and that is the healthy state: the structural matcher flags a
# reader call (`.get()`, `.loads()`, `os.environ`), not every variable reference, so
# `bool(items)` and `bool(a > b)` never reach this list. Each remaining entry is a
# genuine payload field with the argument for why bare bool() is right there.
_ALLOWED_BARE_BOOL = {
    "sentinel_harness/eval_datasets.py::row.get('safety_flag')":
        "a repo-owned dataset field: eval/datasets/*.json is version-controlled here "
        "and tests/test_eval_datasets.py asserts isinstance(flag, bool)",
    "sentinel_harness/feedback.py::r.get('fp_alert_ids')":
        "presence test on a LIST built by this package's own detection tools — not a "
        "third-party boolean, so string-truthiness cannot arise",
    "tools/attack_lookup/handler.py::obj.get('revoked')":
        "STIX booleans are JSON true/false per the ATT&CK spec; a string here is an "
        "upstream schema violation, and INV-BOUNDARY-7 wants presence as the signal",
    "tools/attack_lookup/handler.py::obj.get('x_mitre_deprecated')":
        "same STIX contract as `revoked`",
    "tools/attack_lookup/handler.py::obj.get('x_mitre_is_subtechnique')":
        "same STIX contract as `revoked`",
}


def _python_files() -> list[pathlib.Path]:
    out = []
    for tree in _SCANNED_TREES:
        base = REPO_ROOT / tree
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*.py")):
            if "__pycache__" in path.parts or "build" in path.parts:
                continue
            out.append(path)
    return out


def _looks_external(node: ast.AST) -> bool:
    """True if this expression plausibly came from outside the process.

    Walks the AST STRUCTURE rather than substring-matching `ast.dump()`. The first
    version did the latter and was silently broken: every variable reference carries
    `ctx=Load()`, so the marker `"load"` matched *everything*. The sweep classified
    all expressions as external and only looked clean because the allowlist happened
    to cover them all — a matcher that flags everything is as useless as one that
    flags nothing, and this one hid its own failure.

    That is the FIFTH time substring-matching stood in for a structural judgement in
    this repo (INV-FP-3, R13b's exclusion filter, INV-GATE-1, INV-GATE-6, and now the
    guard written to stop such recurrences). Recorded because the lesson clearly needs
    repeating: if the question is "what KIND of node is this", ask the tree.

    External means: a call to a reader method (`.get()`, `.loads()`, `.read()`), or an
    attribute access into a known environment mapping (`os.environ[...]`).
    """
    _READER_METHODS = {"get", "getenv", "loads", "load", "read", "read_text",
                       "json", "fromjson"}
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            func = sub.func
            # `<something>.get(...)` / `json.loads(...)` / `path.read_text()`
            if isinstance(func, ast.Attribute) and func.attr in _READER_METHODS:
                return True
            # a bare `getenv(...)` brought in by `from os import getenv`
            if isinstance(func, ast.Name) and func.id in _READER_METHODS:
                return True
        if isinstance(sub, ast.Attribute) and sub.attr == "environ":
            return True
        if isinstance(sub, ast.Subscript):
            # os.environ["FLAG"] — the subscript target is the environ attribute
            value = sub.value
            if isinstance(value, ast.Attribute) and value.attr == "environ":
                return True
    return False


def _bare_bool_on_external() -> list[tuple[str, str, int, str]]:
    """Every `bool(<external>)`, as (allowlist_key, relpath, line, expr)."""
    findings = []
    for path in _python_files():
        rel = str(path.relative_to(REPO_ROOT))
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:  # pragma: no cover - defensive
            continue
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == "bool"
                    and node.args):
                continue
            if not _looks_external(node.args[0]):
                continue
            expr = ast.unparse(node.args[0])
            findings.append((f"{rel}::{expr}", rel, node.lineno, expr))
    return findings


# --------------------------------------------------------------------------- #
# INV-COERCE-1 — no bare bool() on externally-sourced data                    #
# --------------------------------------------------------------------------- #
class TestNoBareBoolOnExternalData:
    """The sweep that found the third recurrence.

    `bool("false") is True`, so a backend, judge, or feed that serializes booleans
    as strings inverts the value — and every recurrence so far inverted it toward
    the UNSAFE answer (a denial read as approval, a real alert dropped as noise, a
    patched host read as vulnerable).
    """

    def test_the_sweep_finds_a_nontrivial_number_of_sites(self):
        """Guard the guard: a broken scanner reports nothing and passes everything.

        Without this, a typo in `_EXTERNAL_MARKERS` or a wrong tree name would make
        every assertion below vacuously true — the vacuous-pass failure mode this
        repo has now hit five times.
        """
        assert len(_python_files()) > 40, "the file walk is not finding the package"
        # There ARE bare bool() calls in the trees (all allowlisted); if this drops to
        # zero the AST matcher has stopped matching.
        all_bool = 0
        for path in _python_files():
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"))
            except SyntaxError:
                continue
            all_bool += sum(
                1 for n in ast.walk(tree)
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                and n.func.id == "bool" and n.args
            )
        assert all_bool >= 10, f"only {all_bool} bool() calls seen — matcher broken"

    def test_no_unreviewed_bare_bool_on_external_data(self):
        """Every `bool(<external>)` site must be allowlisted WITH A REASON.

        A new one is not automatically a defect — it is automatically unreviewed,
        which for this pattern is the same thing until someone looks. Add the file to
        `_ALLOWED_BARE_BOOL` with why the value cannot be a string, or delegate to
        `connectors.base._coerce_bool`.
        """
        offenders = [
            (key, rel, line, expr)
            for key, rel, line, expr in _bare_bool_on_external()
            if key not in _ALLOWED_BARE_BOOL
        ]
        assert not offenders, (
            "bare bool() applied to externally-sourced data at:\n"
            + "\n".join(f"  {rel}:{line}  bool({expr})"
                        for _key, rel, line, expr in offenders)
            + "\n\n`bool(\"false\") is True`. Delegate to "
              "`sentinel_harness.connectors.base._coerce_bool`, or add the EXACT key "
              "below to _ALLOWED_BARE_BOOL with the reason the value cannot be a "
              "string:\n"
            + "\n".join(f'    "{key}":' for key, _r, _l, _e in offenders)
            + "\n\nINV-BOUNDARY-1 / INV-GATE-3 / INV-COERCE-1 are the same defect "
              "found three times; this assertion exists so there is no fourth."
        )

    def test_the_allowlist_has_no_dead_entries(self):
        """An allowlist entry for a file with no bare bool() left is stale, and stale
        exemptions are how a denylist rots into a blanket skip."""
        live = {key for key, _rel, _line, _expr in _bare_bool_on_external()}
        dead = sorted(set(_ALLOWED_BARE_BOOL) - live)
        assert not dead, (
            f"allowlist entries no longer needed (that exact bool() is gone): {dead}. "
            "Remove them so the list keeps meaning something — a stale exemption is "
            "how an allowlist rots into a blanket skip."
        )

    def test_every_allowlist_entry_states_a_reason(self):
        for path, reason in _ALLOWED_BARE_BOOL.items():
            assert isinstance(reason, str) and len(reason) > 15, (
                f"allowlist entry {path} has no usable reason: {reason!r}"
            )

    def test_the_siem_query_regression_specifically(self):
        """The third recurrence, pinned as behaviour as well as structure.

        R13b fixed `_normalize_live_event` and left `_normalize_event` — in the same
        file — on a bare bool(). The two normalizers therefore disagreed about the
        same bytes, which is verbatim the defect R13b recorded.
        """
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "siem_query_r17", REPO_ROOT / "tools" / "siem_query" / "handler.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules["siem_query_r17"] = module
        spec.loader.exec_module(module)

        alert_base = {"alert_id": "a1", "ts": "2026-01-01T00:00:00Z",
                      "severity": "high", "rule_name": "r", "host": "h",
                      "technique": "T1059"}
        for value in ["false", "False", "no", "0", "f", "n"]:
            offline = module._normalize_event({**alert_base, "false_positive": value})
            live = module._normalize_live_event({"false_positive": value})
            assert offline["false_positive"] is False, (
                f"offline path read {value!r} as a false positive — a genuine alert "
                "would be dropped as noise"
            )
            assert offline["false_positive"] == live["false_positive"], (
                f"the two normalizers disagree on {value!r}: "
                f"offline={offline['false_positive']} live={live['false_positive']}"
            )

    def test_the_two_siem_paths_agree_on_truthy_values_too(self):
        """CONTROL: agreement must not have been achieved by making both False."""
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "siem_query_r17b", REPO_ROOT / "tools" / "siem_query" / "handler.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules["siem_query_r17b"] = module
        spec.loader.exec_module(module)
        alert_base = {"alert_id": "a1", "ts": "t", "severity": "high",
                      "rule_name": "r", "host": "h", "technique": "T1059"}
        for value in ["true", "True", "yes", "1", True]:
            offline = module._normalize_event({**alert_base, "false_positive": value})
            live = module._normalize_live_event({"false_positive": value})
            assert offline["false_positive"] is True, value
            assert offline["false_positive"] == live["false_positive"], value


# --------------------------------------------------------------------------- #
# INV-COERCE-2 — every local coercion helper agrees with the authority        #
# --------------------------------------------------------------------------- #
class TestLocalCoercionHelpersAgree:
    """Several modules ship their own truthiness helper — sometimes for a good reason
    (a path-loaded tool cannot import the package cleanly). Duplication is tolerable;
    DIVERGENCE is not, because it recreates the two-paths-one-answer defect.

    BUT the rule is scoped by DOMAIN, and getting that wrong was my first mistake
    here. A blanket "every truthiness helper must match the authority" is too strong:

      * `connectors.base._coerce_bool` interprets a value a BACKEND serialized. Its
        alphabet is whatever real SIEMs emit — "true"/"yes"/"1"/"t"/"y" — because it
        must survive a JSON encoder that stringified a bool.
      * `sigma_match._coerce_bool` interprets a Sigma `|exists` OPERAND, and
        `sigma_yara_lint._coerce_truthy` a YAML boolean inside a rule. Those are
        grammars with their own legal values; `"t"` is not a Sigma boolean, and
        accepting it would make the linter more permissive than the spec.

    So the invariant is: **every helper on a BACKEND-RESPONSE value agrees with the
    authority, and every other helper declares which grammar it parses.** The sweep
    below enforces exactly that split, and the enforcement is what surfaced a fifth
    helper I did not know existed (`sigma_match._coerce_bool`).
    """

    _VALUES = ["false", "False", "FALSE", "no", "NO", "0", "f", "n",
               "true", "True", "yes", "1", "t", "y",
               "", "  ", True, False, 0, 1, None]

    @staticmethod
    def _authority():
        from sentinel_harness.connectors.base import _coerce_bool
        return _coerce_bool

    @staticmethod
    def _load_tool(name: str):
        import importlib.util
        path = REPO_ROOT / "tools" / name / "handler.py"
        spec = importlib.util.spec_from_file_location(f"{name}_r17c", path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[f"{name}_r17c"] = module
        spec.loader.exec_module(module)
        return module

    def test_siem_query_coerce_fp_matches_the_authority(self):
        helper = self._load_tool("siem_query")._coerce_fp
        authority = self._authority()
        for value in self._VALUES:
            assert helper(value) == authority(value), (
                f"_coerce_fp({value!r}) = {helper(value)} but the authority says "
                f"{authority(value)}"
            )

    def test_run_evaluation_coerce_pass_matches_on_scalars(self):
        """`_coerce_pass` deliberately DIVERGES on structured values — a dict/list
        where a boolean belongs means the reply is not the schema we asked for
        (INV-GATE-3). It must still agree on every scalar."""
        helper = self._load_tool("run_evaluation")._coerce_pass
        authority = self._authority()
        for value in self._VALUES:
            assert helper(value) == authority(value), (
                f"_coerce_pass({value!r}) diverges from the authority on a SCALAR"
            )
        # ...and the deliberate divergence is preserved.
        for structured in ({"nested": True}, ["x"], (1,)):
            assert helper(structured) is False, (
                "a structured value where a boolean belongs must not promote"
            )

    # Helpers that parse a DIFFERENT grammar, with the grammar named. These are
    # allowed to have their own alphabet — and are required to REJECT the backend
    # alphabet, because accepting "t"/"y" would make a Sigma parser more permissive
    # than the Sigma spec.
    _GRAMMAR_SCOPED = {
        "tools/sigma_match/handler.py": "Sigma `|exists` operand (spec: true/false)",
        "tools/sigma_yara_lint/handler.py": "YAML boolean inside a Sigma rule",
    }

    @pytest.mark.parametrize("rel,grammar", sorted(_GRAMMAR_SCOPED.items()))
    def test_a_grammar_scoped_helper_rejects_the_backend_alphabet(self, rel, grammar):
        """A Sigma/YAML boolean parser must NOT accept the loose backend spellings.

        This is the other direction of the same invariant: divergence from the
        authority is fine here, but only in the STRICTER direction. If one of these
        started accepting `"t"` it would silently widen the grammar it validates.
        """
        module = self._load_tool(rel.split("/")[1])
        helper = getattr(module, "_coerce_bool", None) or module._coerce_truthy
        for loose in ("t", "y", "f", "n"):
            assert helper(loose) is False, (
                f"{rel} ({grammar}) accepts {loose!r}, which is not a legal value in "
                f"that grammar — it must be stricter than the backend coercion, "
                f"never looser"
            )
        # ...while the values the grammar DOES define still work.
        for legal in ("true", "True", True):
            assert helper(legal) is True, legal
        for legal in ("false", "False", False):
            assert helper(legal) is False, legal

    def test_the_helper_inventory_is_current(self):
        """Guard the guard: a NEW coercion helper must be classified above.

        Sweeps the trees for functions whose name says truthiness and asserts each is
        either pinned to the authority or declared grammar-scoped. Without this the
        class silently stops covering the codebase as it grows — and it earned its
        keep immediately, surfacing `sigma_match._coerce_bool`, a fifth helper I had
        not found by reading.
        """
        import re
        pattern = re.compile(r"^def (_coerce_\w*(?:bool|fp|pass|truthy)\w*)",
                             re.MULTILINE)
        found = {}
        for path in _python_files():
            for name in pattern.findall(path.read_text(encoding="utf-8")):
                found[str(path.relative_to(REPO_ROOT))] = name
        # Pinned to the authority: these all interpret a BACKEND-RESPONSE value.
        backend_scoped = {
            "sentinel_harness/connectors/base.py",   # the authority itself
            "tools/siem_query/handler.py",
            "tools/run_evaluation/handler.py",
        }
        classified = backend_scoped | set(self._GRAMMAR_SCOPED)
        unclassified = sorted(set(found) - classified)
        assert not unclassified, (
            f"unclassified truthiness helper(s): "
            f"{[(p, found[p]) for p in unclassified]}. Either pin it to "
            "`connectors.base._coerce_bool` (if it reads a backend response) or add "
            "it to _GRAMMAR_SCOPED naming the grammar it parses. An unclassified "
            "helper is how INV-BOUNDARY-1 recurred twice."
        )
        assert len(found) >= 5, (
            f"only {len(found)} helpers found — the regex has stopped matching"
        )


# --------------------------------------------------------------------------- #
# INV-COERCE-3 — a `-> bool` callback contract is enforced, not widened       #
# --------------------------------------------------------------------------- #
class TestApprovalCallbackContract:
    """`approve_fn` is typed `Callable[..., bool]` at both promotion-approval sites,
    so a string return is the CALLER violating the contract — not the same defect as
    INV-BOUNDARY-1.

    But `bool()` accepts the violation silently and leans toward APPROVED, and the
    obvious ways to implement an approval callback (argparse, an env var, an HTTP
    form field) all produce strings natively. A type annotation is not enforced at
    runtime.

    The right answer is NOT to coerce — that would make strings a supported input and
    widen the contract on the most security-sensitive callback in the platform. It is
    to REFUSE a non-bool, loudly, so a miswired integration fails closed instead of
    approving.
    """

    def test_the_contract_is_declared_as_bool(self):
        """Pin the premise this whole class rests on."""
        import inspect
        from sentinel_harness import agent_loop
        source = inspect.getsource(agent_loop)
        assert "HitlApproveFn = Callable[[Dict[str, Any]], bool]" in source, (
            "the approve_fn contract changed; re-derive whether refusing a non-bool "
            "is still the right policy"
        )

    @pytest.mark.parametrize("returned", ["false", "no", "0", "", "yes", "true",
                                          1, 0, None, {}, []])
    def test_a_non_bool_approval_never_promotes(self, returned):
        """A callback returning anything other than a real bool must not be read as
        approval. `"false"`, `"no"` and `"0"` are the dangerous ones — `bool()` made
        every one of them True."""
        from sentinel_harness import agent_loop

        def bad_callback(_tool_input):
            return returned

        decision = agent_loop._witness_approval(bad_callback, {"harness_id": "h"})
        assert decision is False, (
            f"a callback returning {returned!r} was treated as {decision}"
        )

    @pytest.mark.parametrize("returned", [True, False])
    def test_a_real_bool_is_honoured(self, returned):
        """CONTROL: the supported contract must keep working exactly."""
        from sentinel_harness import agent_loop
        decision = agent_loop._witness_approval(lambda _t: returned,
                                                {"harness_id": "h"})
        assert decision is returned

    def test_a_missing_callback_is_a_refusal(self):
        """CONTROL, and the pre-existing fail-closed rule (INV-PROMOTE-8)."""
        from sentinel_harness import agent_loop
        assert agent_loop._witness_approval(None, {"harness_id": "h"}) is False

    def test_a_raising_callback_propagates(self):
        """A broken approval integration is an error, not a denial: the repo forbids
        swallowing exceptions, and silently reading a crash as "no" would hide a
        misconfiguration that needs fixing."""
        from sentinel_harness import agent_loop

        def boom(_tool_input):
            raise RuntimeError("approval service unreachable")

        with pytest.raises(RuntimeError, match="unreachable"):
            agent_loop._witness_approval(boom, {"harness_id": "h"})


# --------------------------------------------------------------------------- #
# The sweep's own positive control — the test that makes the rest meaningful   #
# --------------------------------------------------------------------------- #
class TestTheSweepCanActuallyDetectAViolation:
    """A structural test that finds nothing is worthless until you show it CAN find
    something. This synthesizes a violation and asserts the matcher names it.

    It also pins the GRANULARITY, which is where my first attempt was wrong. Keying
    `_ALLOWED_BARE_BOOL` by FILE exempted the whole file forever: injecting
    `bool(payload.get("looks_malicious"))` into `feedback.py` was NOT caught, because
    that file already held one legitimate `bool(withheld)`. I had built a fail-open
    into a mechanism whose only purpose is to prevent fail-open — the same shape as
    "a lint-exempt directory is a directory that never gets fixed".

    Keys are therefore `<relpath>::<exact expression>`. The tests below prove both
    halves of that choice: a new violation in an already-allowlisted FILE is caught,
    and the existing legitimate expression in that same file still passes.
    """

    _SYNTHETIC = (
        "\n\ndef _synthetic_violation(payload):\n"
        '    return bool(payload.get("looks_malicious"))\n'
    )

    def _sweep_keys(self, extra_source: str = "", target: str = "feedback.py"):
        """Run the matcher over a temporary copy of the tree's source text.

        Parses the real module's source PLUS an appended snippet, rather than writing
        to the repo — a test that mutates tracked files would be a defect of its own.
        """
        path = REPO_ROOT / "sentinel_harness" / target
        source = path.read_text(encoding="utf-8") + extra_source
        tree = ast.parse(source)
        keys = []
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == "bool"
                    and node.args):
                continue
            if not _looks_external(node.args[0]):
                continue
            keys.append(f"sentinel_harness/{target}::{ast.unparse(node.args[0])}")
        return keys

    def test_a_new_violation_in_an_allowlisted_file_is_caught(self):
        """THE control. `feedback.py` has an allowlisted entry, and a NEW bare bool()
        in it must still be reported — that is what file-level keying got wrong."""
        keys = self._sweep_keys(self._SYNTHETIC)
        unreviewed = [k for k in keys if k not in _ALLOWED_BARE_BOOL]
        assert unreviewed == [
            "sentinel_harness/feedback.py::payload.get('looks_malicious')"
        ], (
            "the sweep did not flag a synthetic violation in an already-allowlisted "
            f"file — granularity has regressed to file level. Unreviewed: {unreviewed}"
        )

    def test_the_existing_legitimate_expression_still_passes(self):
        """CONTROL for the control: without the injection, the same file is clean."""
        keys = self._sweep_keys("")
        unreviewed = [k for k in keys if k not in _ALLOWED_BARE_BOOL]
        assert unreviewed == [], (
            f"the real tree is not clean, so the test above proves nothing: "
            f"{unreviewed}"
        )

    @pytest.mark.parametrize("snippet,should_flag", [
        ('\n\ndef f(p):\n    return bool(p.get("x"))\n', True),
        ('\n\ndef f(d):\n    return bool(d.get("x", False))\n', True),
        ('\n\nimport os\n\ndef f():\n    return bool(os.environ.get("FLAG"))\n', True),
        ('\n\nimport json\n\ndef f(s):\n    return bool(json.loads(s))\n', True),
        # Not external: a local name, a comparison, a literal.
        ('\n\ndef f(items):\n    return bool(items)\n', False),
        ('\n\ndef f(a, b):\n    return bool(a > b)\n', False),
        ('\n\ndef f():\n    return bool(1)\n', False),
    ])
    def test_the_provenance_matcher_classifies_correctly(self, snippet, should_flag):
        """The matcher must catch the external shapes and NOT flag local ones —
        over-flagging is how a guard gets disabled by the people it annoys."""
        keys = self._sweep_keys(snippet)
        new = [k for k in keys if k not in _ALLOWED_BARE_BOOL]
        assert bool(new) is should_flag, (
            f"snippet {snippet.strip()!r}: flagged={bool(new)} expected={should_flag}"
        )
