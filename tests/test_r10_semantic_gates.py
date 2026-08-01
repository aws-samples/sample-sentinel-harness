"""
Round-10 semantic-gap regression suite.
========================================
Round 9 asked "was the invariant ever asked?" of governance surfaces. Round 10
put the same question to three places where a plausible-looking output can be
semantically WRONG in a way no syntactic check notices:

  - the Sigma → SIEM translators (does a translated rule keep the original's
    MATCH SET, or does it silently match a different — even disjoint — set?),
  - the InvokeHarness stream parser (does a malformed/duplicated stream corrupt
    the HITL resume contract?),
  - the Strands exporter (does the generated skeleton distinguish a
    human-approval SAFETY GATE from an ordinary tool, or invite an adopter to
    drop the gate?).

The headline finding is a false NEGATIVE, the worst kind for a detection: a Sigma
`CommandLine|base64: 'whoami'` rule — written to catch the base64-OBFUSCATED
command `d2hvYW1p` — was translated to Splunk `CommandLine="whoami"`, which
matches the PLAINTEXT. A rule meant to catch obfuscation was silently turned into
one that only catches its absence, with a caveat that named the wrong target
languages ("no YARA/Suricata equivalent" on an SPL translation).

Every test below FAILS on pre-R10 source. Zero network, zero AWS, zero LLM.
"""
from __future__ import annotations

import ast
import importlib.util
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

os.environ.setdefault("SENTINEL_REGION", "us-east-1")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("SENTINEL_EXECUTION_ROLE_ARN",
                      "arn:aws:iam::000000000000:role/test-harness-role")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")

from sentinel_harness import core                    # noqa: E402
from sentinel_harness.exporter import export_harness_to_strands  # noqa: E402


def _load(unique_name: str, rel_path: str):
    path = os.path.join(REPO_ROOT, rel_path)
    spec = importlib.util.spec_from_file_location(unique_name, path)
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[unique_name] = module
    spec.loader.exec_module(module)
    return module


dt = _load("detection_translate_r10", "tools/detection_translate/handler.py")


def _translate(sigma: str, targets):
    return dt.handler({"sigma": sigma, "targets": targets}, None)


def _sigma(body: str) -> str:
    """Wrap predicate line(s) into a minimal Sigma rule. ``body`` lines are the
    field predicates under ``selection`` (indented 8 spaces)."""
    return (
        "title: R10 Rule\n"
        "detection:\n"
        "    selection:\n"
        f"{body}"
        "    condition: selection\n"
    )


def _stream(*events):
    for e in events:
        yield e


def _tu_start(tuid, name):
    return {"contentBlockStart": {"start": {"toolUse": {"toolUseId": tuid, "name": name}}}}


def _tu_delta(payload):
    return {"contentBlockDelta": {"delta": {"toolUse": {"input": payload}}}}


_STOP = {"contentBlockStop": {}}
_PAUSE = {"messageStop": {"stopReason": "tool_use"}}


# ========================================================================== #
# R10-A / INV-TRANSLATE-1 — a field-aware translation keeps the MATCH SET    #
# ========================================================================== #
class TestBase64ModifierIsNotEmittedAsPlaintext:
    """PRE-R10 (the headline false negative): `CommandLine|base64: 'whoami'`
    became Splunk `CommandLine="whoami"`. The Sigma rule matches the base64 of
    'whoami' (`d2hvYW1p`); the translation matches the plaintext — a DISJOINT set.
    A rule written to catch obfuscated commands silently caught only un-obfuscated
    ones."""

    def test_splunk_does_not_emit_a_plaintext_field_match_for_base64(self):
        out = _translate(_sigma("        CommandLine|base64: 'whoami'\n"), ["splunk"])
        spl = out["translations"]["splunk"]
        assert 'CommandLine="whoami"' not in spl, (
            "base64 modifier emitted as a plaintext field match — a false negative"
        )
        assert 'CommandLine="*whoami*"' not in spl

    def test_elastic_does_not_emit_a_plaintext_match_for_base64(self):
        out = _translate(_sigma("        CommandLine|base64: 'whoami'\n"), ["elastic"])
        eql = out["translations"]["elastic"]
        assert 'like~ "whoami"' not in eql
        assert "whoami" not in eql  # neither literal nor wildcard form

    def test_base64_is_flagged_untranslatable_with_target_native_guidance(self):
        out = _translate(_sigma("        CommandLine|base64: 'whoami'\n"), ["splunk", "elastic"])
        blob = " ".join(out["untranslatable"])
        assert "base64" in blob
        # The caveat must point at the RIGHT remedy, not "no YARA/Suricata equivalent".
        assert "regex" in blob or "decode" in blob

    def test_byte_scanner_keeps_a_labelled_best_effort_literal(self):
        """YARA/Suricata are byte scanners: a labelled literal IS honest best-effort
        there (every match is a byte substring), so it is still emitted — the fix is
        scoped to field-aware targets, not a blanket removal."""
        out = _translate(_sigma("        CommandLine|base64: 'whoami'\n"), ["yara"])
        assert "whoami" in out["translations"]["yara"]
        assert any("base64" in u for u in out["untranslatable"])


class TestRegexModifierIsNotEmittedAsLiteral:
    """PRE-R10: `Image|re: '^cmd.*'` became Splunk `Image="^cmd.*"` — matching the
    literal characters ^, c, m, d, *, not the regex. SPL has `| regex` and EQL has
    `regex~`; the literal form is a different (and near-empty) match set."""

    def test_splunk_does_not_emit_a_literal_for_a_regex_modifier(self):
        out = _translate(_sigma("        Image|re: '^cmd.*'\n"), ["splunk"])
        assert 'Image="^cmd.*"' not in out["translations"]["splunk"]

    def test_elastic_does_not_emit_a_literal_for_a_regex_modifier(self):
        out = _translate(_sigma("        Image|re: '^cmd.*'\n"), ["elastic"])
        assert '^cmd' not in out["translations"]["elastic"]

    def test_regex_caveat_names_the_native_operator(self):
        out = _translate(_sigma("        Image|re: '^cmd.*'\n"), ["splunk", "elastic"])
        assert any("regex" in u for u in out["untranslatable"])


class TestFieldAwareNotesSurfaceWithheldPredicates:
    """A withheld predicate must be LOUD, not a silent omission — otherwise the
    engineer reads a clean-looking query and assumes full coverage."""

    def test_a_note_records_what_was_withheld_from_the_query(self):
        out = _translate(_sigma("        CommandLine|base64: 'whoami'\n"), ["splunk"])
        assert any("WITHHELD" in n for n in out["notes"])


class TestFaithfulTranslationsStillWork:
    """Regression: the faithful modifiers (contains/startswith/endswith/plain) must
    be UNAFFECTED — the fix must not over-withhold."""

    def test_contains_and_startswith_still_emit_for_all_targets(self):
        out = _translate(
            _sigma("        c-uri|contains: 'jndi'\n        ua|startswith: 'curl'\n"),
            ["splunk", "elastic", "yara", "suricata"],
        )
        spl = out["translations"]["splunk"]
        assert '"*jndi*"' in spl and '"curl*"' in spl
        eql = out["translations"]["elastic"]
        assert 'like~ "*jndi*"' in eql and 'like~ "curl*"' in eql

    def test_mixed_rule_keeps_faithful_and_withholds_lossy(self):
        """A faithful predicate alongside a lossy one: the faithful half is emitted,
        the lossy half withheld — the query is partial-but-correct, never wrong."""
        out = _translate(
            _sigma("        c-uri|contains: 'jndi'\n        CommandLine|base64: 'whoami'\n"),
            ["splunk"],
        )
        spl = out["translations"]["splunk"]
        assert '"*jndi*"' in spl              # faithful predicate present
        assert "whoami" not in spl            # lossy predicate withheld
        assert any("WITHHELD" in n for n in out["notes"])

    def test_case_insensitive_equality_preserved_on_elastic(self):
        """Regression on a prior fix: EQL plain equality uses case-insensitive
        like~, not ==, so cmd.exe still matches CMD.EXE."""
        out = _translate(_sigma("        Image: 'cmd.exe'\n"), ["elastic"])
        assert "like~" in out["translations"]["elastic"]
        assert "==" not in out["translations"]["elastic"]

    def test_negation_still_flagged_untranslatable(self):
        """Regression on the R9-era negation guard."""
        sigma = ("title: Neg\ndetection:\n    selection:\n        a: 'x'\n"
                 "    filter:\n        b: 'y'\n    condition: selection and not filter\n")
        out = _translate(sigma, ["splunk"])
        assert any("NEGATION" in u for u in out["untranslatable"])


# ========================================================================== #
# R10-B / INV-STREAM-1 — a repeated toolUseId cannot corrupt the resume       #
# ========================================================================== #
class TestStreamDedupesToolUseId:
    """PRE-R10: `_consume_stream` appended every completed tool_use block to
    `pending` unconditionally. A stream that repeated a toolUseId produced two
    pending entries, and `invoke_with_tool_results` would then emit two
    toolResults for the SAME id — which the Bedrock protocol rejects (every
    toolUseId in a turn must be unique), corrupting the resume."""

    def test_duplicate_tool_use_id_is_collapsed_to_one(self):
        result = core._consume_stream(_stream(
            _tu_start("dup", "gate"), _tu_delta('{"n": 1}'), _STOP,
            _tu_start("dup", "gate"), _tu_delta('{"n": 2}'), _STOP,
            _PAUSE,
        ))
        ids = [t["toolUseId"] for t in result["tool_uses"]]
        assert ids == ["dup"], f"duplicate toolUseId leaked into pending: {ids}"

    def test_the_first_block_wins_not_the_last(self):
        """Keeping the first (completed) block is deterministic and avoids letting a
        later duplicate silently rewrite the analyst-facing input."""
        result = core._consume_stream(_stream(
            _tu_start("dup", "gate"), _tu_delta('{"n": 1}'), _STOP,
            _tu_start("dup", "gate"), _tu_delta('{"n": 2}'), _STOP,
            _PAUSE,
        ))
        assert result["tool_uses"][0]["input"] == {"n": 1}

    def test_distinct_parallel_ids_are_all_kept(self):
        """The dedupe must not touch legitimate parallel gates with distinct ids —
        that was the whole point of accumulating a list in the first place."""
        result = core._consume_stream(_stream(
            _tu_start("a", "g"), _STOP,
            _tu_start("b", "h"), _STOP,
            _PAUSE,
        ))
        assert [t["toolUseId"] for t in result["tool_uses"]] == ["a", "b"]

    def test_resume_contract_answers_each_id_exactly_once(self):
        """End-to-end: the deduped tool_uses, fed to the resume builder, produce one
        toolResult per unique id — the contract the protocol requires."""
        import json
        result = core._consume_stream(_stream(
            _tu_start("dup", "g"), _tu_delta('{"n": 1}'), _STOP,
            _tu_start("dup", "g"), _tu_delta('{"n": 2}'), _STOP,
            _PAUSE,
        ))
        # Mirror invoke_with_tool_results' assembly without a network call.
        answers = [(tu, {"ok": True}) for tu in result["tool_uses"]]
        result_ids = [
            {"id": tu["toolUseId"], "res": json.dumps(res)} for tu, res in answers
        ]
        ids = [r["id"] for r in result_ids]
        assert len(ids) == len(set(ids)), "resume would emit two toolResults for one id"


# ========================================================================== #
# R10-C / INV-EXPORT-1 — the export marks HITL gates as safety guardrails     #
# ========================================================================== #
class TestExporterFlagsHitlGatesAsGuardrails:
    """PRE-R10: the exporter listed `request_*_approval` gates in the same comment
    block as ordinary tools and initialised `tools=[]`. An adopter wiring the
    business tools would naturally skip the approval gate — shipping an agent that
    takes high-stakes actions WITHOUT the sign-off the harness required, with
    nothing calling that out."""

    def _cfg(self, allowed_tools):
        return {
            "name": "alert_triage",
            "system_prompt": "Triage alerts; never contain without approval.",
            "model": {"bedrockModelConfig": {"modelId": "global.anthropic.claude-sonnet-4-6"}},
            "allowed_tools": allowed_tools,
        }

    def test_hitl_gate_is_marked_as_a_safety_gate(self):
        code = export_harness_to_strands(
            self._cfg(["siem_query", "request_containment_approval"]))
        assert "SAFETY GATE" in code
        assert "request_containment_approval" in code

    def test_builder_warns_when_a_gate_is_present(self):
        code = export_harness_to_strands(
            self._cfg(["siem_query", "request_publish_approval"]))
        assert "WARNING" in code
        assert "without" in code.lower() and "approval" in code.lower()

    def test_no_gate_means_no_safety_noise(self):
        """A harness with no HITL gate must not sprout a spurious warning."""
        code = export_harness_to_strands(self._cfg(["siem_query", "@gateway/asset_lookup"]))
        assert "SAFETY GATE" not in code
        assert "WARNING" not in code

    def test_exported_code_is_always_valid_python(self):
        """The added comments/warnings must never break the module — an export that
        does not parse is useless."""
        for allowed in (
            ["siem_query", "request_containment_approval", "request_publish_approval"],
            ["siem_query"],
            [],
            ["request_promotion_approval"],
        ):
            code = export_harness_to_strands(self._cfg(allowed))
            ast.parse(code)  # raises SyntaxError on failure

    def test_business_tools_still_listed_and_reproduced(self):
        """Regression: the business tools must still appear in ALLOWED_TOOLS and the
        comment block — the guardrail split must not drop them."""
        code = export_harness_to_strands(
            self._cfg(["siem_query", "@gateway/asset_lookup", "request_publish_approval"]))
        assert "siem_query" in code
        assert "@gateway/asset_lookup" in code
        # The executable list keeps every entry, gates included.
        assert code.count("request_publish_approval") >= 1

    def test_control_char_in_tool_name_stays_inert(self):
        """Regression on the pre-existing comment-injection guard: a newline in a
        tool name must not break out of its comment line."""
        code = export_harness_to_strands(self._cfg(["siem_query\nimport os", "x"]))
        ast.parse(code)
