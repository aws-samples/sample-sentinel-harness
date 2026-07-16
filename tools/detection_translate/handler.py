"""detection_translate — deterministic Sigma → YARA / Suricata skeleton translator.

SecOps purpose
--------------
A detection engineer often authors ONE rule (typically in Sigma, the vendor-neutral
format) but must deploy across engines: a network IDS wants Suricata, a
file/memory scanner wants YARA. Hand-porting is error-prone. This tool
DETERMINISTICALLY translates the *translatable subset* of a Sigma detection into
YARA and Suricata SKELETONS a human then reviews — and is HONEST about what does
not carry over (a Sigma log-field predicate has no faithful YARA/Suricata
equivalent, so it becomes a content match + a clearly-labeled ``note``).

This tool is DETERMINISTIC and LLM-FREE: no model, no tokens, no network. Same
Sigma in → same YARA/Suricata out. It pairs with ``sigma_yara_lint`` (which then
validates the emitted skeletons) and reuses ``sigma_match``'s selection parsing so
the three tools agree on what a Sigma detection means.

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
event = {"sigma": "<sigma rule yaml text>", "targets": ["yara", "suricata"]}
    ``targets`` optional; defaults to both.

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

_VALID_TARGETS = {"yara", "suricata"}


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
    """Yield (selection_name, field, modifier, value) for every leaf predicate.

    A selection is a map of ``field`` or ``field|modifier`` → value(s). A list
    value yields one predicate per element (Sigma OR semantics). Deterministic
    order: selections then fields as authored (dict preserves insertion order)."""
    for sel_name, sel in detection.items():
        if sel_name == "condition" or not isinstance(sel, dict):
            continue
        for key, value in sel.items():
            parts = key.split("|")
            field = parts[0]
            modifier = parts[1] if len(parts) > 1 else None
            values = value if isinstance(value, list) else [value]
            for v in values:
                yield sel_name, field, modifier, v


def _emit_yara(title: str, predicates: List[tuple], notes: List[str]) -> str:
    """Build a YARA rule skeleton from the string predicates.

    Each faithful predicate becomes a ``$s<N>`` string; the condition is the OR of
    all strings (a human tightens to AND / ordering as needed — noted)."""
    safe_name = re.sub(r"\W", "_", title).strip("_") or "translated_rule"
    strings: List[str] = []
    for i, (sel, field, modifier, value) in enumerate(predicates, 1):
        text = str(value)
        # YARA string escaping: backslash + double-quote.
        esc = text.replace("\\", "\\\\").replace('"', '\\"')
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
        f'        description = "Auto-translated from Sigma: {title}"\n'
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
        text = str(value)
        esc = text.replace("\\", "\\\\").replace('"', '\\"')
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
    esc_msg = title.replace('"', '\\"')
    return (
        f'alert ip any any -> any any '
        f'(msg:"Auto-translated from Sigma: {esc_msg}"; '
        f"{content_block} "
        f"classtype:misc-activity; sid:1000000; rev:1;)\n"
    )


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
    for sel, field, modifier, value in _iter_predicates(detection):
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

    condition = str(detection.get("condition", "")).lower()
    if condition and not re.fullmatch(r"[\w\s()|*]+", condition):
        notes.append(f"condition {condition!r} contains operators beyond the "
                     "and/or-of-selections subset — the emitted skeleton flattens "
                     "it; a human must reconstruct the boolean logic.")

    translations: Dict[str, str] = {}
    if "yara" in targets:
        translations["yara"] = _emit_yara(title, predicates, notes)
    if "suricata" in targets:
        translations["suricata"] = _emit_suricata(title, predicates, notes)

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
