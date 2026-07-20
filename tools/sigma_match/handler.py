"""sigma_match — deterministic, offline Sigma detection MATCHER.

SecOps purpose
--------------
A sibling tool ``tools/sigma_yara_lint`` LINTS a Sigma rule: it decides
whether the *rule* is structurally well-formed. It does NOT answer the
question a detection engineer actually cares about during Breach & Attack
Simulation (BAS) replay:

    "Given this log EVENT, does this Sigma RULE fire?"

That is what this tool does. It parses a Sigma rule, evaluates its
``detection`` block (selections + condition) against a single normalized
log event, and reports whether the rule matched, which selections matched,
and the condition string that was evaluated. This is the engine the BAS
detection-replay loop uses to enumerate *detection blind spots*: run each
simulated attack telemetry event against the current rule set and flag the
techniques that no rule catches.

Provable core
-------------
This tool is DETERMINISTIC and LLM-FREE. It uses no model, consumes no
tokens, and makes no network calls. Same ``(rule, log_event)`` always yields
the same result. The boolean condition is evaluated by a small hand-written
tokenizer + recursive-descent parser — there is NO use of ``eval()`` or any
other dynamic execution. That makes it safe to run as an automated gate: an
LLM may draft rules or synthesize BAS telemetry, but this matcher — not
another LLM — decides whether an event is caught.

Supported Sigma matching semantics
-----------------------------------
Selections are maps of ``field`` -> value, or ``field|modifier`` -> value.
Implemented modifiers (the widely-used subset):
  - ``contains``   : field value contains the given substring.
  - ``startswith`` : field value starts with the given substring.
  - ``endswith``   : field value ends with the given substring.
  - ``re``         : the given value is a regex searched against the field.
  - ``cidr``       : rule value is a network (``10.0.0.0/8``); field is an IP
                     that must fall inside it. A non-IP field never matches.
  - ``base64``     : encode the PATTERN as base64 and substring-match the
                     encoded form against the (already base64) field value.
  - ``base64offset``: like ``base64`` but matches the pattern encoded at byte
                     offsets 0/1/2 so it is found mid-stream regardless of
                     alignment (Sigma's standard 3-offset expansion).
  - ``windash``    : match a command-line flag token spelled with either a
                     ``-`` or a ``/`` dash variant (e.g. ``-enc`` or ``/enc``).
  - ``gt`` / ``gte`` / ``lt`` / ``lte`` : numeric comparison. A non-numeric
                     field or expected value never matches and records a caveat.
  - ``exists``     : value ``true`` matches when the field is PRESENT (any
                     value, incl. None); value ``false`` matches when ABSENT.
  - ``cased``      : case-SENSITIVE exact match (overrides the default
                     case-insensitive comparison). Composable with contains/
                     startswith/endswith.
  - ``all``        : the value is a LIST and EVERY element must match (AND).
                     Composable, e.g. ``field|contains|all: [a, b]``.
  - (plain)        : equality. A LIST value means OR (any element matches).
Value comparison is CASE-INSENSITIVE by default (Sigma's default behavior).
A field that is ABSENT from the log event makes that key fail to match — no
crash. ``field: null`` is the exception: it matches when the field is ABSENT
or its value is None. A selection matches only if ALL of its keys match (AND
across keys).

Unknown modifiers do NOT silently degrade to equality. Any modifier the engine
cannot handle records a caveat and forces the whole match to be inconclusive
(``matched: False`` with a populated ``caveats`` list), so a BAS blind-spot
verdict never counts an un-evaluable rule as "covered".

Condition expression (over selection names):
  - ``and`` / ``or`` / ``not`` with parentheses.
  - ``1 of them`` / ``any of them`` / ``all of them``.
  - ``1 of selection_*`` / ``all of selection_*`` (wildcard by prefix).
  - a bare selection name resolves to whether that selection matched.

Egress & secrets posture
------------------------
- ZERO egress. No network, no external services, no tokens.
- ZERO secrets. Nothing is read from credential storage.
- Execution role / region are referenced via ``SENTINEL_EXECUTION_ROLE_ARN``,
  ``SENTINEL_REGION`` and ``AWS_PROFILE`` for consistency with the rest of the
  harness, though this tool needs no AWS access to run.

Input contract
--------------
event = {
    "rule": <sigma yaml string OR an already-parsed dict>,
    "log_event": {<field>: <value>, ...},
}

Output contract (on success)
----------------------------
{
    "ok": True,
    "matched": True | False,          # did the rule fire on this event?
    "matched_selections": ["sel_a"],  # selections that individually matched
    "condition": "sel_a and not sel_b",
    "caveats": [                      # empty when the rule was fully evaluable
        {"field": "Count", "modifier": "gt", "reason": "non_numeric_value"},
        {"field": "X", "modifier": "frobnicate", "reason": "unsupported_modifier"},
    ],
}
When ``caveats`` is non-empty the match is INCONCLUSIVE: ``matched`` is forced
False and callers (e.g. BAS blind-spot analysis) must exclude the rule from the
covered / blind-spot verdict rather than trust the boolean.
On bad input:
{"ok": False, "error": "validation_error", "message": "..."}
"""

from __future__ import annotations

import base64
import importlib.util
import ipaddress
import os
import re
from typing import Any, Dict, List, Tuple

# --------------------------------------------------------------------------
# YAML parsing — REUSE the sigma_yara_lint approach.
#
# The tool handlers live under tools/<name>/handler.py (a scripts tree, not
# an installed package), so we load the sibling module by path and reuse its
# ``_parse_yaml`` (PyYAML with a dependency-free minimal fallback). If that
# sibling ever becomes unavailable, we fall back to a small local copy of the
# same minimal parser so this tool stays self-contained and fully offline.
# Attribution: parser design ported from tools/sigma_yara_lint/handler.py.
# --------------------------------------------------------------------------
def _load_sibling_parse_yaml():
    """Import ``_parse_yaml`` from the sibling sigma_yara_lint handler by path.

    We import by absolute path rather than as a package because tools/ is a
    flat scripts tree. Failure to locate the sibling is non-fatal: the caller
    falls back to the local minimal parser copy.
    """
    sibling = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "sigma_yara_lint",
        "handler.py",
    )
    if not os.path.exists(sibling):
        return None
    spec = importlib.util.spec_from_file_location("_sigma_yara_lint_handler", sibling)
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return getattr(mod, "_parse_yaml", None)


def _parse_yaml(text: str) -> Any:
    """Parse a YAML string into Python objects, deterministically and offline.

    Prefers the sibling sigma_yara_lint parser (which uses PyYAML if present,
    else its minimal fallback). Any import problem degrades to the local
    minimal parser so this tool never depends on the sibling being present.
    """
    fn = _load_sibling_parse_yaml()
    if fn is not None:
        return fn(text)
    return _parse_yaml_minimal(text)


def _parse_yaml_minimal(text: str) -> Any:
    """Minimal YAML parser for the Sigma subset (local fallback copy).

    Ported from tools/sigma_yara_lint/handler.py::_parse_yaml_minimal. Handles
    nested mappings by indentation, simple scalars, and inline/block lists.
    Kept here so the matcher is self-contained with zero third-party deps.
    """
    lines = [
        ln.rstrip()
        for ln in text.splitlines()
        if ln.strip() and not ln.lstrip().startswith("#")
    ]

    def scalar(v: str) -> Any:
        v = v.strip()
        if v == "":
            return None
        if (v.startswith('"') and v.endswith('"')) or (
            v.startswith("'") and v.endswith("'")
        ):
            return v[1:-1]
        if v.startswith("[") and v.endswith("]"):
            inner = v[1:-1].strip()
            if not inner:
                return []
            return [scalar(x) for x in inner.split(",")]
        low = v.lower()
        if low in ("true", "false"):
            return low == "true"
        if low in ("null", "~"):
            return None
        try:
            return int(v)
        except ValueError:
            pass
        try:
            return float(v)
        except ValueError:
            pass
        return v

    def indent_of(ln: str) -> int:
        return len(ln) - len(ln.lstrip(" "))

    def parse_block(idx: int, min_indent: int) -> Tuple[Any, int]:
        if idx < len(lines) and lines[idx].lstrip().startswith("- "):
            result_list: List[Any] = []
            while idx < len(lines):
                cur = lines[idx]
                ci = indent_of(cur)
                if ci < min_indent or not cur.lstrip().startswith("- "):
                    break
                item = cur.lstrip()[2:].strip()
                result_list.append(scalar(item))
                idx += 1
            return result_list, idx

        result: Dict[str, Any] = {}
        while idx < len(lines):
            cur = lines[idx]
            ci = indent_of(cur)
            if ci < min_indent:
                break
            stripped = cur.strip()
            if ":" not in stripped:
                idx += 1
                continue
            key, _, rest = stripped.partition(":")
            key = key.strip()
            rest = rest.strip()
            if rest:
                result[key] = scalar(rest)
                idx += 1
            else:
                child_indent = ci + 1
                if idx + 1 < len(lines):
                    child_indent = indent_of(lines[idx + 1])
                child, idx = parse_block(idx + 1, child_indent)
                result[key] = child
        return result, idx

    parsed, _ = parse_block(0, 0)
    return parsed


# --------------------------------------------------------------------------
# Input validation
# --------------------------------------------------------------------------
def _validate(event: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Validate input; return (parsed_rule_dict, log_event_dict).

    ``rule`` may be a YAML string or an already-parsed mapping. Raises
    ValueError on any malformed input so the handler can surface a
    validation_error without swallowing the reason.
    """
    if not isinstance(event, dict):
        raise ValueError("event must be a dict")

    rule = event.get("rule")
    if isinstance(rule, str):
        if not rule.strip():
            raise ValueError("'rule' string is empty")
        try:
            parsed = _parse_yaml(rule)
        except Exception as exc:  # surface parse failure, don't swallow
            raise ValueError(f"could not parse 'rule' YAML: {exc}") from exc
    elif isinstance(rule, dict):
        parsed = rule
    else:
        raise ValueError("'rule' must be a YAML string or a parsed dict")

    if not isinstance(parsed, dict):
        raise ValueError("'rule' must resolve to a mapping at the top level")

    detection = parsed.get("detection")
    if not isinstance(detection, dict):
        raise ValueError("rule 'detection' block must be a mapping")
    if "condition" not in detection:
        raise ValueError("rule 'detection' must contain a 'condition'")
    selections = [k for k in detection if k != "condition"]
    if not selections:
        raise ValueError("rule 'detection' must define at least one selection")

    log_event = event.get("log_event")
    if not isinstance(log_event, dict):
        raise ValueError("'log_event' must be a dict of field -> value")

    return parsed, log_event


# --------------------------------------------------------------------------
# Value / field matching
# --------------------------------------------------------------------------
def _as_text(value: Any, cased: bool = False) -> str:
    """Normalize a scalar log/rule value to a string for comparison.

    Sigma matching is case-insensitive by default, so we lowercase unless the
    ``cased`` modifier is in effect. Bools are rendered as ``true``/``false``
    to match how they appear in YAML rules.
    """
    if isinstance(value, bool):
        text = "true" if value else "false"
    else:
        text = str(value)
    return text if cased else text.lower()


def _to_number(value: Any) -> Tuple[bool, float]:
    """Coerce a scalar to a float for numeric comparison.

    Returns ``(ok, number)``. Bools are rejected (``ok=False``) because a
    numeric Sigma comparison against a boolean is almost always a rule mistake,
    and silently treating True as 1 would hide it.
    """
    if isinstance(value, bool):
        return False, 0.0
    if isinstance(value, (int, float)):
        return True, float(value)
    try:
        return True, float(str(value).strip())
    except (TypeError, ValueError):
        return False, 0.0


def _coerce_bool(value: Any) -> bool:
    """Interpret a Sigma ``exists`` operand as a boolean presence requirement."""
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("true", "1", "yes")


def _base64_variants(pattern: str, with_offsets: bool) -> List[str]:
    """Return the base64 encoding(s) to substring-match against the field.

    ``with_offsets`` False -> the single straight base64 of the pattern.

    True (base64offset) -> the three encodings of the pattern prefixed with
    0/1/2 pad bytes, each trimmed to ONLY the base64 characters whose every
    source byte belongs to the pattern (dropping chars contaminated by the
    leading pad bytes and by the unknown byte that trails the pattern
    mid-stream). Keeping exactly the "pure pattern" characters guarantees that
    at least one variant is a substring of the field's base64 no matter what
    byte alignment the pattern lands on inside a larger blob — the property
    blind-spot detection relies on (never miss a real match).
    """
    raw = pattern.encode("utf-8")
    if not with_offsets:
        return [base64.b64encode(raw).decode("ascii")]

    length = len(raw)
    variants: List[str] = []
    for pad in range(3):
        enc = base64.b64encode(b" " * pad + raw).decode("ascii")
        start = None
        end = None
        for pos, ch in enumerate(enc):
            if ch == "=":  # padding chars carry no pure pattern bits
                break
            # base64 char `pos` encodes bits of source bytes [first, last].
            first = (6 * pos) // 8
            last = (6 * pos + 5) // 8
            if all(pad <= b < pad + length for b in range(first, last + 1)):
                if start is None:
                    start = pos
                end = pos + 1
        variants.append(enc[start:end] if start is not None else "")
    return variants


def _windash_variants(token: str) -> List[str]:
    """Return the dash-variant spellings of a command-line flag token.

    Windows accepts both ``-flag`` and ``/flag``; Sigma's ``windash`` modifier
    matches either. We generate the token with all dashes flipped to slashes
    and vice-versa so a rule written one way still catches the other.
    """
    variants = {token, token.replace("-", "/"), token.replace("/", "-")}
    return list(variants)


def _match_one_value(
    field_value: Any,
    modifier: str,
    expected: Any,
    cased: bool,
    field: str,
    caveats: List[Dict[str, Any]],
) -> bool:
    """Match a single log field value against one expected value + modifier.

    ``field_value`` is the value present in the log event (never a "missing"
    sentinel — absence is handled by the caller). Numeric/CIDR modifiers that
    receive un-comparable operands record a caveat and return False rather than
    crashing or silently degrading to equality.
    """
    if modifier == "re":
        flags = 0 if cased else re.IGNORECASE
        return re.search(str(expected), str(field_value), flags) is not None

    if modifier == "cidr":
        try:
            network = ipaddress.ip_network(str(expected), strict=False)
        except ValueError:
            caveats.append({"field": field, "modifier": modifier, "reason": "invalid_cidr_value"})
            return False
        try:
            addr = ipaddress.ip_address(str(field_value).strip())
        except ValueError:
            return False  # non-IP field value => no match (not a rule caveat)
        return addr in network

    if modifier in ("base64", "base64offset"):
        # Base64 is case-SENSITIVE by nature; compare against the raw field text.
        haystack = str(field_value)
        for variant in _base64_variants(str(expected), modifier == "base64offset"):
            if variant and variant in haystack:
                return True
        return False

    if modifier == "windash":
        fv = _as_text(field_value, cased)
        return any(_as_text(v, cased) in fv for v in _windash_variants(str(expected)))

    if modifier in ("gt", "gte", "lt", "lte"):
        ok_f, fv_num = _to_number(field_value)
        ok_e, ev_num = _to_number(expected)
        if not (ok_f and ok_e):
            caveats.append({"field": field, "modifier": modifier, "reason": "non_numeric_value"})
            return False
        if modifier == "gt":
            return fv_num > ev_num
        if modifier == "gte":
            return fv_num >= ev_num
        if modifier == "lt":
            return fv_num < ev_num
        return fv_num <= ev_num

    fv = _as_text(field_value, cased)
    ev = _as_text(expected, cased)
    if modifier == "contains":
        return ev in fv
    if modifier == "startswith":
        return fv.startswith(ev)
    if modifier == "endswith":
        return fv.endswith(ev)
    # Plain equality (default).
    return fv == ev


# Modifiers that select HOW a value is compared (at most one applies per key).
_VALUE_MODIFIERS = (
    "contains", "startswith", "endswith", "re", "cidr",
    "base64", "base64offset", "windash", "gt", "gte", "lt", "lte",
)
# Modifiers that flag a mode rather than select a comparison operator.
_FLAG_MODIFIERS = ("all", "cased", "exists")
_KNOWN_MODIFIERS = frozenset(_VALUE_MODIFIERS + _FLAG_MODIFIERS)


def _match_key(
    field_spec: str,
    expected: Any,
    log_event: Dict[str, Any],
    caveats: List[Dict[str, Any]],
) -> bool:
    """Evaluate one ``field|modifier -> expected`` entry against the event.

    - The field name is the part before the first ``|``; remaining pipe
      segments are modifiers (e.g. ``field|contains|all``).
    - An UNKNOWN modifier records an ``unsupported_modifier`` caveat and fails
      the key (never silently degrades to equality).
    - ``exists`` checks field presence regardless of value.
    - ``field: null`` matches when the field is ABSENT or its value is None.
    - A field ABSENT from ``log_event`` otherwise never matches (no raise).
    - ``all`` means the expected LIST must ALL match (AND); otherwise a list
      value means OR (any element matches).
    """
    parts = field_spec.split("|")
    field = parts[0]
    modifiers = [p.strip().lower() for p in parts[1:] if p.strip()]

    unknown = [m for m in modifiers if m not in _KNOWN_MODIFIERS]
    if unknown:
        for m in unknown:
            caveats.append({"field": field, "modifier": m, "reason": "unsupported_modifier"})
        return False  # inconclusive key => cannot claim a match

    # ``exists`` is presence-only and ignores the field's value.
    if "exists" in modifiers:
        return (field in log_event) == _coerce_bool(expected)

    require_all = "all" in modifiers
    cased = "cased" in modifiers
    value_modifier = ""
    for m in modifiers:
        if m in _VALUE_MODIFIERS:
            value_modifier = m
            break

    # Normalize the expected side to a list so OR/AND logic is uniform.
    if isinstance(expected, (list, tuple)):
        expected_values = list(expected)
    else:
        expected_values = [expected]

    if field not in log_event:
        # An absent field can only satisfy an explicit ``null`` (no value
        # modifier); everything else fails to match without crashing.
        return value_modifier == "" and any(ev is None for ev in expected_values)
    field_value = log_event[field]

    def _one(ev: Any) -> bool:
        # ``field: null`` matches a present-but-None value too.
        if ev is None and value_modifier == "":
            return field_value is None
        return _match_one_value(field_value, value_modifier, ev, cased, field, caveats)

    if require_all:
        return all(_one(ev) for ev in expected_values)  # list AND
    return any(_one(ev) for ev in expected_values)  # list OR / plain equality


def _match_selection(
    selection: Any,
    log_event: Dict[str, Any],
    caveats: List[Dict[str, Any]],
) -> bool:
    """Evaluate one selection against the log event.

    A selection is normally a mapping of field->value; ALL keys must match
    (AND across keys). A selection may also be a LIST of such mappings, in
    which case ANY sub-map matching is enough (Sigma "list of maps" = OR).
    An empty/non-mapping selection cannot match and returns False rather than
    raising, keeping the matcher robust against odd rule shapes.
    """
    if isinstance(selection, list):
        # Evaluate every sub-map (no short-circuit) so a caveat in a later
        # sub-map is still recorded even once an earlier one has matched.
        return any([_match_selection(sub, log_event, caveats) for sub in selection])
    if not isinstance(selection, dict) or not selection:
        return False
    # Materialize before all() so a failing early key does not hide a caveat
    # that a later key would have recorded.
    return all([
        _match_key(str(field_spec), expected, log_event, caveats)
        for field_spec, expected in selection.items()
    ])


# --------------------------------------------------------------------------
# Condition evaluation — safe boolean parser (NO eval()).
#
# Grammar (case-insensitive keywords):
#   expr   := term ( "or" term )*
#   term   := factor ( "and" factor )*
#   factor := "not" factor
#           | "(" expr ")"
#           | quantifier
#           | NAME
#   quantifier := ("1" | "any" | "all") "of" ("them" | NAME_with_wildcard)
# --------------------------------------------------------------------------
_QUANTIFIERS = {"1", "any", "all"}


def _tokenize_condition(condition: str) -> List[str]:
    """Split a condition string into tokens: names, keywords, parentheses."""
    # Insert spaces around parentheses so they tokenize cleanly, then split.
    spaced = condition.replace("(", " ( ").replace(")", " ) ")
    return [t for t in spaced.split() if t]


class _ConditionEvaluator:
    """Recursive-descent evaluator over which selections matched.

    Constructed with the set of selection names and the set of names that
    matched. ``evaluate(condition)`` returns a bool. Any structural problem
    in the condition raises ValueError (never silently returns a default).
    """

    def __init__(self, selection_names: List[str], matched: set) -> None:
        self._names = selection_names
        self._matched = matched
        self._tokens: List[str] = []
        self._pos = 0

    def evaluate(self, condition: str) -> bool:
        self._tokens = _tokenize_condition(condition)
        self._pos = 0
        if not self._tokens:
            raise ValueError("empty condition")
        value = self._parse_expr()
        if self._pos != len(self._tokens):
            raise ValueError(
                f"unexpected trailing token in condition: {self._tokens[self._pos]!r}"
            )
        return value

    # -- token helpers ----------------------------------------------------
    def _peek(self) -> str:
        return self._tokens[self._pos] if self._pos < len(self._tokens) else ""

    def _next(self) -> str:
        tok = self._tokens[self._pos]
        self._pos += 1
        return tok

    # -- grammar ----------------------------------------------------------
    def _parse_expr(self) -> bool:
        value = self._parse_term()
        while self._peek().lower() == "or":
            self._next()
            rhs = self._parse_term()
            value = value or rhs
        return value

    def _parse_term(self) -> bool:
        value = self._parse_factor()
        while self._peek().lower() == "and":
            self._next()
            rhs = self._parse_factor()
            value = value and rhs
        return value

    def _parse_factor(self) -> bool:
        tok = self._peek()
        low = tok.lower()
        if low == "not":
            self._next()
            return not self._parse_factor()
        if tok == "(":
            self._next()
            value = self._parse_expr()
            if self._peek() != ")":
                raise ValueError("unbalanced parentheses in condition")
            self._next()
            return value
        if low in _QUANTIFIERS:
            return self._parse_quantifier()
        if not tok:
            raise ValueError("unexpected end of condition")
        # A bare selection-name reference.
        self._next()
        return self._resolve_name(tok)

    def _parse_quantifier(self) -> bool:
        quant = self._next().lower()  # "1" | "any" | "all"
        if self._peek().lower() != "of":
            raise ValueError(f"expected 'of' after {quant!r} in condition")
        self._next()  # consume 'of'
        target = self._peek()
        if not target:
            raise ValueError(f"expected target after '{quant} of' in condition")
        self._next()

        selected = self._resolve_group(target)
        if not selected:
            # No selection matches the group pattern -> quantifier over an
            # empty set. "all of <empty>" is vacuously True in set logic, but
            # Sigma authors expect a non-existent group to simply not fire, so
            # we treat an empty group as False for both 1/any and all.
            return False
        hits = [name for name in selected if name in self._matched]
        if quant == "all":
            return len(hits) == len(selected)
        return len(hits) >= 1  # "1 of" / "any of"

    # -- resolution -------------------------------------------------------
    def _resolve_name(self, name: str) -> bool:
        if name not in self._names:
            raise ValueError(f"condition references undefined selection: {name!r}")
        return name in self._matched

    def _resolve_group(self, target: str) -> List[str]:
        """Resolve a quantifier target to the list of selection names it covers.

        ``them`` covers every selection. A trailing ``*`` matches by prefix
        (e.g. ``selection_*``). Otherwise the target must be one exact name.
        """
        if target.lower() == "them":
            return list(self._names)
        if target.endswith("*"):
            prefix = target[:-1]
            return [n for n in self._names if n.startswith(prefix)]
        if target in self._names:
            return [target]
        raise ValueError(
            f"condition quantifier references undefined selection: {target!r}"
        )


# --------------------------------------------------------------------------
# Handler
# --------------------------------------------------------------------------
def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Deterministically decide whether a log EVENT is caught by a Sigma RULE.

    Pure Python: no LLM, no tokens, no network, no secrets. Same
    ``(rule, log_event)`` always produces the same output, which is what makes
    it safe as the core of BAS detection-replay blind-spot analysis.
    """
    try:
        rule, log_event = _validate(event)
    except ValueError as exc:
        return {"ok": False, "error": "validation_error", "message": str(exc)}

    detection = rule["detection"]
    condition = detection["condition"]
    # Sigma allows a list of conditions (implicit OR); normalize to a single
    # expression by OR-joining so a single evaluator handles both shapes.
    if isinstance(condition, list):
        condition_str = " or ".join(f"({c})" for c in condition if str(c).strip())
    else:
        condition_str = str(condition)

    selection_names = [k for k in detection if k != "condition"]
    caveats: List[Dict[str, Any]] = []
    matched_selections = [
        name
        for name in selection_names
        if _match_selection(detection[name], log_event, caveats)
    ]

    evaluator = _ConditionEvaluator(selection_names, set(matched_selections))
    try:
        matched = evaluator.evaluate(condition_str)
    except ValueError as exc:
        # A malformed condition is a validation problem with the rule, not a
        # match result — surface it instead of returning a misleading bool.
        return {"ok": False, "error": "validation_error", "message": str(exc)}

    # Any caveat means the rule could not be fully evaluated (unsupported
    # modifier, non-numeric comparison, bad CIDR). The boolean is then
    # meaningless, so we force it False and let callers exclude the rule from
    # the covered / blind-spot verdict rather than trust an un-evaluable match.
    if caveats:
        matched = False

    return {
        "ok": True,
        "matched": bool(matched),
        "matched_selections": matched_selections,
        "condition": condition_str,
        "caveats": caveats,
    }


if __name__ == "__main__":
    import json

    sample_rule = """
title: Suspicious PowerShell Encoded Command
id: 7e2b1c9a-1111-2222-3333-444455556666
status: experimental
level: high
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\\powershell.exe'
        CommandLine|contains: '-enc'
    condition: selection
"""
    sample_event = {
        "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell.exe -enc SQBFAFgA",
    }
    print(json.dumps(handler({"rule": sample_rule, "log_event": sample_event}, None), indent=2))
