"""detection_translate — deterministic Sigma → YARA / Suricata / Splunk / Elastic translator.

SecOps purpose
--------------
A detection engineer often authors ONE rule (typically in Sigma, the vendor-neutral
format) but must deploy across engines: a network IDS wants Suricata, a
file/memory scanner wants YARA, a SIEM wants Splunk SPL or Elastic EQL. Hand-porting
is error-prone. This tool DETERMINISTICALLY translates the *translatable subset* of a
Sigma detection into SKELETONS a human then reviews — and is HONEST about what does
not carry over (a lossy modifier has no faithful equivalent, so it is surfaced in
``untranslatable``, never silently dropped).

Two target families:
  - CONTENT matchers (``yara``, ``suricata``) — byte/string content matches; a log
    FIELD predicate has no true field semantics here, so it degrades to a content
    match + a note.
  - FIELD-AWARE queries (``splunk`` SPL, ``elastic`` EQL) — the Sigma field predicate
    maps to a REAL field term (``field="*value*"`` / ``field like~ "*value*"``), a
    more faithful translation; the OR-flatten boolean caveat still applies.

This tool is DETERMINISTIC and LLM-FREE: no model, no tokens, no network. Same
Sigma in → same output out. It pairs with ``sigma_yara_lint`` (which validates the
emitted YARA/Suricata) and reuses ``sigma_match``'s selection parsing so the
detection tools agree on what a Sigma detection means.

What it translates (the honest, faithful subset)
-------------------------------------------------
- string-literal / ``contains`` / ``startswith`` / ``endswith`` field predicates →
  a YARA ``strings:`` entry + condition, and a Suricata ``content:`` match;
- the selection/condition names carry into the emitted rule as comments so the
  human reviewer sees the provenance.

What it does NOT translate (surfaced in ``notes``, never silently dropped)
--------------------------------------------------------------------------
- regex (``|re``), numeric comparisons, and aggregation (``count() by``) — these
  have no clean YARA/Suricata content equivalent, so the field/value is emitted as
  a best-effort content match with a note that a human must verify the semantics;
- complex boolean conditions beyond ``and``/``or`` of selections are noted.

Input contract
--------------
event = {"sigma": "<sigma rule yaml text>", "targets": ["yara", "suricata", "splunk", "elastic"]}
    ``targets`` optional; defaults to ["yara", "suricata"] (back-compat). Valid
    targets: yara, suricata, splunk, elastic.

Output contract
---------------
{
  "ok": True,
  "title": "<sigma title>",
  "translations": {"yara": "<rule text>", "suricata": "<rule text>"},
  "notes": ["...human-review caveats..."],
  "untranslatable": ["...predicates with no faithful equivalent..."],
}

Egress & secrets posture
------------------------
ZERO egress, ZERO tokens, ZERO secrets. Pure Python; deterministic.
"""
from __future__ import annotations

import importlib.util
import os
import re
from typing import Any, Dict, List, Tuple

# --------------------------------------------------------------------------- #
# Reuse the shared YAML parser from the sibling sigma_yara_lint tool so all    #
# detection tools parse Sigma identically (tools/ is a scripts tree, not a     #
# package — load by absolute path).                                            #
# --------------------------------------------------------------------------- #
def _load_yaml_parser():
    sibling = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "sigma_yara_lint", "handler.py",
    )
    spec = importlib.util.spec_from_file_location("_syl_for_translate", sibling)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _parse_yaml(text: str) -> Any:
    """Parse Sigma YAML via the shared parser (PyYAML or the minimal fallback)."""
    return _load_yaml_parser()._parse_yaml(text)


# Sigma string modifiers this translator maps FAITHFULLY to a content match.
_FAITHFUL_MODIFIERS = {"contains", "startswith", "endswith", None}
# Modifiers we cannot faithfully carry to YARA/Suricata content matching.
_LOSSY_MODIFIERS = {"re", "base64", "base64offset", "cidr", "gt", "gte", "lt", "lte"}

_VALID_TARGETS = {"yara", "suricata", "splunk", "elastic"}


# --------------------------------------------------------------------------- #
# Grammar-aware escaping — a Sigma value/title is UNTRUSTED text interpolated  #
# into a YARA/Suricata rule. Without escaping, a value containing the target   #
# grammar's metacharacters ("  \\  newline  ;  |  {  }) breaks out of the      #
# emitted literal and corrupts (or injects into) the rule — the exact class of #
# defect an output-injection audit hunts for. These make the emitted rule      #
# ALWAYS syntactically valid for any input.                                    #
# --------------------------------------------------------------------------- #
def _yara_escape(text: str) -> str:
    """Escape untrusted text for a YARA double-quoted text string.

    Backslash and double-quote are backslash-escaped; ``\\t``/``\\n``/``\\r`` use
    their YARA escapes; every other non-printable or non-ASCII byte becomes a
    ``\\xHH`` escape (per-UTF-8-byte). The result can never contain a raw quote,
    backslash, or newline, so it cannot break the string literal."""
    out: List[str] = []
    for ch in text:
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif 0x20 <= ord(ch) <= 0x7E:
            out.append(ch)
        else:
            out.extend("\\x%02x" % b for b in ch.encode("utf-8"))
    return "".join(out)


def _suricata_content_escape(text: str) -> str:
    """Encode untrusted text as a valid Suricata ``content:`` string.

    Printable ASCII other than the content metacharacters (``"`` ``;`` ``\\``
    ``|``) is kept literal; every metacharacter, control char, and non-ASCII byte
    is hex-encoded inside a ``|..|`` block (consecutive bytes coalesced). This
    guarantees the value cannot break the quoted literal, the ``;`` option
    separator, or the ``|`` hex-block delimiter — e.g. ``a|b`` → ``a|7C|b``."""
    special = set('"|;\\')
    out: List[str] = []
    hexrun: List[str] = []

    def _flush() -> None:
        if hexrun:
            out.append("|" + " ".join(hexrun) + "|")
            hexrun.clear()

    for ch in text:
        for b in ch.encode("utf-8"):
            if 0x20 <= b <= 0x7E and chr(b) not in special:
                _flush()
                out.append(chr(b))
            else:
                hexrun.append("%02X" % b)
    _flush()
    return "".join(out)


def _suricata_msg_escape(text: str) -> str:
    """Escape an untrusted title for a Suricata ``msg:"..."`` string.

    Control chars (incl. newlines) collapse to a space so a single-line rule stays
    single-line; backslash and double-quote are backslash-escaped so the value
    cannot close the quoted literal. ``;``/``(``/``)`` are left as-is: they are
    harmless INSIDE the quoted msg once the linter is quote-aware."""
    cleaned = "".join(c if 0x20 <= ord(c) <= 0x7E else " " for c in text)
    return cleaned.replace("\\", "\\\\").replace('"', '\\"')


class _TranslateError(ValueError):
    """Malformed request (bad input shape). Distinct from a translation caveat."""


def _validate(event: Dict[str, Any]) -> Tuple[str, List[str]]:
    if not isinstance(event, dict):
        raise _TranslateError("event must be a dict")
    sigma = event.get("sigma")
    if not isinstance(sigma, str) or not sigma.strip():
        raise _TranslateError("missing required non-empty string field 'sigma'")
    targets = event.get("targets", ["yara", "suricata"])
    if not isinstance(targets, list) or not targets:
        raise _TranslateError("'targets' must be a non-empty list")
    bad = [t for t in targets if t not in _VALID_TARGETS]
    if bad:
        raise _TranslateError(f"unknown target(s) {bad}; expected subset of {sorted(_VALID_TARGETS)}")
    return sigma, targets


def _iter_predicates(detection: Dict[str, Any]):
    """Yield (selection_name, field, modifier, modifiers, value) per leaf predicate.

    A selection is a map of ``field`` or ``field|mod1|mod2...`` → value(s). A list
    value yields one predicate per element (Sigma OR semantics). ``modifier`` is the
    FIRST modifier (back-compat / primary value-transform); ``modifiers`` is the
    FULL chain (``parts[1:]``) so an aggregator like ``|all`` is not silently lost.
    Deterministic order: selections then fields as authored (dict preserves order)."""
    for sel_name, sel in detection.items():
        if sel_name == "condition" or not isinstance(sel, dict):
            continue
        for key, value in sel.items():
            parts = key.split("|")
            field = parts[0]
            modifiers = parts[1:]
            modifier = modifiers[0] if modifiers else None
            values = value if isinstance(value, list) else [value]
            for v in values:
                yield sel_name, field, modifier, modifiers, v


def _yara_rule_name(title: str) -> str:
    """Derive a YARA-legal identifier from a Sigma title.

    A YARA rule name must match ``[A-Za-z_]\\w*`` — it may NOT start with a digit.
    Sigma titles routinely do ('404 anomaly', '4625 brute force'), so a bare
    ``\\W→_`` substitution yielded names the engine (and this project's own linter)
    rejects. Prefix ``r_`` when the sanitized name does not start with a letter or
    underscore."""
    safe = re.sub(r"\W", "_", title).strip("_") or "translated_rule"
    if not re.match(r"[A-Za-z_]", safe):
        safe = "r_" + safe
    return safe


def _emit_yara(title: str, predicates: List[tuple], notes: List[str]) -> str:
    """Build a YARA rule skeleton from the string predicates.

    Each faithful predicate becomes a ``$s<N>`` string; the condition is the OR of
    all strings (a human tightens to AND / ordering as needed — noted). All
    untrusted text (values AND the title) is grammar-escaped so the emitted rule is
    always syntactically valid regardless of input."""
    safe_name = _yara_rule_name(title)
    esc_title = _yara_escape(title)
    strings: List[str] = []
    for i, (sel, field, modifier, value) in enumerate(predicates, 1):
        esc = _yara_escape(str(value))
        strings.append(f'        $s{i} = "{esc}"  // from {sel}.{field}'
                       + (f"|{modifier}" if modifier else ""))
    if not strings:
        strings = ['        $s1 = "REPLACE_ME"  // no string predicate translated']
    cond = " or ".join(f"$s{i}" for i in range(1, len(strings) + 1))
    notes.append("YARA: condition is the OR of all strings — review and tighten "
                 "(AND / ordering / filesize) to match the Sigma intent.")
    return (
        f"rule {safe_name}\n"
        f"{{\n"
        f"    meta:\n"
        f'        description = "Auto-translated from Sigma: {esc_title}"\n'
        f'        source = "detection_translate (skeleton — human review required)"\n'
        f"    strings:\n"
        + "\n".join(strings) + "\n"
        f"    condition:\n"
        f"        {cond}\n"
        f"}}\n"
    )


def _emit_suricata(title: str, predicates: List[tuple], notes: List[str]) -> str:
    """Build a Suricata rule skeleton from the string predicates.

    Each faithful predicate becomes a ``content:`` (with a ``startswith``/
    ``endswith`` modifier where applicable). sid is a placeholder the engineer
    MUST replace with an allocated id (noted)."""
    contents: List[str] = []
    for sel, field, modifier, value in predicates:
        esc = _suricata_content_escape(str(value))
        piece = f'content:"{esc}";'
        if modifier == "startswith":
            piece += " startswith;"
        elif modifier == "endswith":
            piece += " endswith;"
        piece += f" // from {sel}.{field}" + (f"|{modifier}" if modifier else "")
        contents.append(piece)
    if not contents:
        contents = ['content:"REPLACE_ME"; // no string predicate translated']
    content_block = " ".join(c.split(" //")[0] for c in contents)
    notes.append("Suricata: sid:1000000 is a PLACEHOLDER — allocate a real sid "
                 "from your managed range before deploy; verify proto/ports.")
    esc_msg = _suricata_msg_escape(title)
    return (
        f'alert ip any any -> any any '
        f'(msg:"Auto-translated from Sigma: {esc_msg}"; '
        f"{content_block} "
        f"classtype:misc-activity; sid:1000000; rev:1;)\n"
    )


# --------------------------------------------------------------------------- #
# Splunk SPL + Elastic EQL — FIELD-AWARE query languages                      #
# --------------------------------------------------------------------------- #
# Unlike YARA/Suricata (content matching over bytes), SPL and EQL are field-aware:
# a Sigma `field|contains: value` maps to a real field predicate, so the translation
# is MORE faithful than content matching. Both share the OR-flatten caveat (the
# condition boolean structure is not reconstructed — noted). Values are grammar-
# escaped so an untrusted value can never break out of the quoted literal.
def _spl_field(field: str) -> str:
    """Sanitize a Sigma field name for an SPL/EQL field token. Sigma fields are dotted
    identifiers (``winlog.event_data.Image``); we keep alnum/underscore/dot and drop
    anything else so a crafted field name cannot inject query syntax. A field that
    reduces to empty falls back to a clearly-fake placeholder."""
    safe = re.sub(r"[^A-Za-z0-9_.]", "", field)
    return safe or "UNKNOWN_FIELD"


def _dq_escape(text: str) -> str:
    """Escape untrusted text for a double-quoted SPL/EQL string literal: backslash
    then double-quote are backslash-escaped, control chars (newline/CR/tab) are
    stripped to spaces, and the BACKTICK is removed entirely.

    The backtick is dropped because it is a metacharacter in Splunk BOTH as the
    triple-backtick comment delimiter (a title placed in an SPL provenance comment
    could otherwise close the comment and inject a live ``| delete`` — an audited
    output-injection) AND as the search-macro trigger; no legitimate detection value
    needs a literal backtick, so removing it is the safe, context-independent fix."""
    cleaned = "".join(
        c if (0x20 <= ord(c) <= 0x7E or ord(c) > 0x7F) and c != "`" else (" " if c != "`" else "")
        for c in text
    )
    return cleaned.replace("\\", "\\\\").replace('"', '\\"')


def _spl_value(modifier: str, value: str) -> str:
    """Render an SPL match value for a modifier. SPL ``field="..."`` supports ``*``
    wildcards inside the quotes; contains/startswith/endswith become wildcard
    positions. The value is escaped; any literal ``*`` in the value is itself
    escaped so it is not mistaken for a wildcard we did not intend."""
    esc = _dq_escape(value).replace("*", "\\*")   # neutralize value-borne wildcards
    if modifier == "contains":
        return f'"*{esc}*"'
    if modifier == "startswith":
        return f'"{esc}*"'
    if modifier == "endswith":
        return f'"*{esc}"'
    return f'"{esc}"'  # plain equality


def _emit_splunk(title: str, predicates: List[tuple], notes: List[str]) -> str:
    """Build a Splunk SPL search skeleton. Each faithful predicate becomes a
    ``field=<value>`` term; terms are AND-joined (the common single-selection case).
    The OR-flatten caveat is noted. Returns a one-line ``search`` command."""
    terms: List[str] = []
    for sel, field, modifier, value in predicates:
        terms.append(f"{_spl_field(field)}={_spl_value(modifier, str(value))}")
    if not terms:
        terms = ['REPLACE_ME="*"']
    notes.append("Splunk: terms are AND-joined (single-selection assumption); a "
                 "multi-selection condition (OR / NOT) must be reconstructed by hand. "
                 "Prepend your index/sourcetype (e.g. `index=... sourcetype=...`).")
    # `search` prefix + a provenance comment line (``` ```comment``` is SPL comment).
    return f"search {' '.join(terms)}  ```Auto-translated from Sigma: {_dq_escape(title)}```\n"


def _eql_value(modifier: str, value: str) -> str:
    """Render an EQL match for a modifier. ALL arms use ``like~`` — EQL's
    CASE-INSENSITIVE wildcard operator — including plain equality, because Sigma's
    default string match is case-insensitive; using EQL's case-SENSITIVE ``==`` for
    equality silently under-matched (``cmd.exe`` would miss ``CMD.EXE``, a false
    negative) and was inconsistent with the other arms.

    Value-borne ``*``/``?`` are neutralized to LITERALS — matching what
    ``_spl_value`` does for SPL — so the SAME Sigma value matches identically across
    both targets (they previously diverged: SPL literal vs EQL live-wildcard, with no
    note). The ``*`` we add for contains/startswith/endswith positions stays a real
    ``like~`` wildcard."""
    # Neutralize value-borne like~ wildcards AFTER _dq_escape (identical ordering to
    # _spl_value) so the '\' we add for '\*'/'\?' is not itself doubled by
    # _dq_escape's backslash handling — keeping SPL and EQL byte-for-byte consistent.
    esc = _dq_escape(value).replace("*", "\\*").replace("?", "\\?")
    if modifier == "contains":
        return f'like~ "*{esc}*"'
    if modifier == "startswith":
        return f'like~ "{esc}*"'
    if modifier == "endswith":
        return f'like~ "*{esc}"'
    return f'like~ "{esc}"'  # plain equality — case-insensitive, no positional wildcard


def _emit_elastic(title: str, predicates: List[tuple], notes: List[str]) -> str:
    """Build an Elastic EQL query skeleton. Each faithful predicate becomes a
    ``field <op> "value"`` condition, AND-joined inside ``any where ...``. The
    ``like~`` operator gives case-insensitive wildcard matching for the
    contains/startswith/endswith modifiers. OR-flatten caveat noted."""
    conds: List[str] = []
    for sel, field, modifier, value in predicates:
        conds.append(f"{_spl_field(field)} {_eql_value(modifier, str(value))}")
    if not conds:
        conds = ['REPLACE_ME == "*"']
    notes.append("Elastic EQL: conditions are AND-joined under `any where` (single-"
                 "selection assumption); a multi-selection condition (OR / NOT) must "
                 "be reconstructed. `any` matches any event category — narrow it "
                 "(e.g. `process where ...`) to the real logsource.")
    return f"any where {' and '.join(conds)}\n"


def _classify_condition(condition: str, untranslatable: List[str], notes: List[str]) -> None:
    """Inspect the Sigma ``condition`` and record how faithfully the OR-flatten
    skeleton preserves it.

    NEGATION is the load-bearing case: ``selection and not filter`` means "match
    selection but EXCLUDE filter". The skeleton OR-flattens every selection, so a
    ``not`` is not merely lost — it is INVERTED (an exclusion becomes an extra
    inclusion). That silently changes matching semantics, so it MUST land in
    ``untranslatable`` (the tool's honesty ledger), not just ``notes``. A regex
    char-class check missed this because ``not``/``and`` are pure word chars; we
    tokenize instead. Other non-trivial boolean structure (aggregates, parens,
    pipes) is a softer ``notes`` caveat — order preserved, no inversion."""
    cond = condition.strip()
    if not cond:
        return
    tokens = re.split(r"[\s()]+", cond.lower())
    if "not" in tokens:
        untranslatable.append(
            f"condition {condition!r} uses NEGATION ('not'): the OR-flatten skeleton "
            f"does NOT preserve exclusion — a negated selection is inverted into an "
            f"inclusion. A human MUST re-model the exclusion."
        )
    # Anything beyond a bare 'and'/'or' of selection names (aggregates, pipes,
    # wildcards, near/count) is a softer flatten caveat.
    if not re.fullmatch(r"[\w\s()|*]+", cond) or any(
        t in tokens for t in ("of", "them", "count", "near")
    ):
        notes.append(f"condition {condition!r} contains operators beyond the "
                     "and/or-of-selections subset — the emitted skeleton flattens "
                     "it; a human must reconstruct the boolean logic.")


def _translate(sigma_text: str, targets: List[str]) -> Dict[str, Any]:
    """Translate one Sigma rule to the requested targets. PURE, deterministic."""
    parsed = _parse_yaml(sigma_text)
    if not isinstance(parsed, dict):
        raise _TranslateError("sigma content did not parse to a mapping")
    title = str(parsed.get("title", "untitled"))
    detection = parsed.get("detection")
    if not isinstance(detection, dict):
        raise _TranslateError("sigma rule has no 'detection' mapping")

    predicates: List[tuple] = []
    untranslatable: List[str] = []
    notes: List[str] = []
    for sel, field, modifier, modifiers, value in _iter_predicates(detection):
        # A null/absent Sigma value ('field:' with no value) or a non-string
        # scalar has no faithful literal content equivalent — a Sigma null means
        # "field must be absent/null", NOT the literal text 'None'. Route to
        # untranslatable rather than emitting a bogus content match for 'None'/'123'.
        if value is None or not isinstance(value, str):
            untranslatable.append(
                f"{sel}.{field} = {value!r}: null/absence or non-string predicate has "
                f"no faithful content equivalent — NOT emitted; a human must model it."
            )
            continue
        if value == "":
            untranslatable.append(
                f"{sel}.{field} = '': empty-string predicate has no valid content/"
                f"string match (engines reject an empty literal) — NOT emitted."
            )
            continue
        # An aggregator like '|all' (BOTH values must match — AND) beyond the value
        # transform cannot be carried by the OR-flatten skeleton: flag it loudly.
        aggregators = [m for m in modifiers[1:] if m in ("all",)]
        if aggregators:
            untranslatable.append(
                f"{sel}.{field}|{'|'.join(modifiers)} = {value!r}: the '|all' aggregator "
                f"(ALL values must match — AND) is NOT preserved by the OR skeleton; a "
                f"human must reconstruct the AND grouping."
            )
        if modifier in _LOSSY_MODIFIERS:
            # Emit a best-effort content match for the value but flag it loudly.
            untranslatable.append(
                f"{sel}.{field}|{modifier} = {value!r}: '{modifier}' has no faithful "
                f"YARA/Suricata content equivalent — emitted as a literal content "
                f"match; a human MUST verify the semantics."
            )
            predicates.append((sel, field, modifier, value))
        elif modifier in _FAITHFUL_MODIFIERS:
            predicates.append((sel, field, modifier, value))
        else:
            untranslatable.append(
                f"{sel}.{field}|{modifier} = {value!r}: unknown modifier "
                f"{modifier!r}; skipped (no content emitted)."
            )

    _classify_condition(str(detection.get("condition", "")), untranslatable, notes)

    translations: Dict[str, str] = {}
    if "yara" in targets:
        translations["yara"] = _emit_yara(title, predicates, notes)
    if "suricata" in targets:
        translations["suricata"] = _emit_suricata(title, predicates, notes)
    if "splunk" in targets:
        translations["splunk"] = _emit_splunk(title, predicates, notes)
    if "elastic" in targets:
        translations["elastic"] = _emit_elastic(title, predicates, notes)

    return {
        "ok": True,
        "title": title,
        "translations": translations,
        "notes": notes,
        "untranslatable": untranslatable,
    }


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Translate a Sigma rule into YARA/Suricata skeletons. Pure, deterministic.

    Never raises: a malformed request is a ``validation_error``; a Sigma that
    parses but is structurally unusable is a ``translation_error``. The emitted
    skeletons are for HUMAN REVIEW — the ``notes``/``untranslatable`` lists state
    exactly what did not carry over faithfully."""
    try:
        sigma_text, targets = _validate(event)
    except _TranslateError as exc:
        return {"ok": False, "error": "validation_error", "message": str(exc)}
    try:
        return _translate(sigma_text, targets)
    except _TranslateError as exc:
        return {"ok": False, "error": "translation_error", "message": str(exc)}


if __name__ == "__main__":
    import json

    sample = """
title: Log4Shell JNDI Exploit Attempt
logsource:
    category: proxy
detection:
    selection:
        c-uri|contains: '${jndi:ldap'
        cs-user-agent|startswith: 'curl'
    condition: selection
"""
    print(json.dumps(handler({"sigma": sample, "targets": ["yara", "suricata"]}, None), indent=2))
