"""sigma_yara_lint — deterministic detection-rule linter (reference template).

SecOps purpose
--------------
Before a detection engineer publishes a Sigma or YARA rule, a security
operations team wants a cheap, deterministic structural check: are the
required fields present, is the logic well-formed, does every condition
reference a defined selection? This tool provides that as PURE PYTHON.

This tool is intentionally DETERMINISTIC and LLM-FREE. It uses no model,
consumes no tokens, and makes no network calls. Same input always yields
the same output. That makes it safe to run as a mandatory gate in an
automated detection pipeline: an LLM may draft a rule, but this linter —
not another LLM — decides whether the rule is structurally valid.

What it checks
--------------
Sigma (implemented here, functional):
  - Valid YAML (uses PyYAML if available, else a minimal built-in parser).
  - Required top-level keys: ``title``, ``logsource``, ``detection``.
  - ``detection`` must contain a ``condition`` plus at least one selection.
  - Every identifier referenced in ``condition`` must be a defined
    selection (or the ``them``/``all of``/``1 of`` aggregates).
  - Warnings for missing recommended fields (``id``, ``level``, ``status``,
    ``logsource.product``/``category``).
  - ``level`` must be one of the Sigma-defined values when present.

YARA (implemented here, lightweight structural check):
  - Presence of at least one ``rule <name> { ... }`` block.
  - Each rule has a ``condition:`` section.
  - Balanced braces.
  - Warns if ``strings:`` is absent while the condition references ``$``.

Suricata (implemented here, network-IDS rule grammar):
  - Header is ``action proto src sport <dir> dst dport`` (>=7 tokens, a ``->``
    or ``<>`` direction operator, action in the known set alert/drop/reject/…).
  - A balanced ``( ... )`` option block is present.
  - Required options ``msg``, ``sid``, ``rev`` are present; ``sid`` is numeric.
  - Warns on a missing ``classtype``. Handles multi-rule files, ``#`` comments,
    and ``\\`` line continuations.

Egress & secrets posture
------------------------
- ZERO egress. No network, no external services, no tokens.
- ZERO secrets. Nothing is read from credential storage.
- Execution role / region are referenced via
  ``SENTINEL_EXECUTION_ROLE_ARN``, ``SENTINEL_REGION`` and ``AWS_PROFILE``
  for consistency with the rest of the harness, though this tool needs no
  AWS access to run.

Input contract
--------------
event = {"rule_type": "sigma" | "yara" | "suricata", "content": "<rule text>"}

Output contract
---------------
{
    "ok": True,                 # True if the tool ran (not "rule is valid")
    "rule_type": "sigma",
    "valid": True | False,      # whether the rule passed all hard checks
    "errors": ["..."],          # hard failures (rule is invalid)
    "warnings": ["..."],        # non-fatal style/best-practice issues
}
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

_VALID_SIGMA_LEVELS = {"informational", "low", "medium", "high", "critical"}
_CONDITION_KEYWORDS = {
    "and", "or", "not", "of", "them", "all", "1", "any",
    "|", "count", "by", "gt", "gte", "lt", "lte", "near",
}


# --------------------------------------------------------------------------
# Input validation
# --------------------------------------------------------------------------
_SUPPORTED_RULE_TYPES = {"sigma", "yara", "suricata"}

# Suricata rule actions (the first token of a rule). The IPS-only actions
# (drop/reject/…) are valid too; alert is by far the most common.
_SURICATA_ACTIONS = {"alert", "drop", "reject", "pass", "log", "rejectsrc",
                     "rejectdst", "rejectboth"}
# Options that MUST appear in a well-formed Suricata rule's option block.
_SURICATA_REQUIRED_OPTS = ("msg", "sid", "rev")


def _validate(event: Dict[str, Any]) -> Tuple[str, str]:
    """Validate input; return (rule_type, content)."""
    if not isinstance(event, dict):
        raise ValueError("event must be a dict")
    rule_type = event.get("rule_type")
    if not isinstance(rule_type, str) or rule_type.lower() not in _SUPPORTED_RULE_TYPES:
        raise ValueError(
            f"'rule_type' must be one of: {sorted(_SUPPORTED_RULE_TYPES)}"
        )
    content = event.get("content")
    if not isinstance(content, str) or not content.strip():
        raise ValueError("missing required non-empty string field 'content'")
    return rule_type.lower(), content


# --------------------------------------------------------------------------
# Minimal YAML parser fallback (only used if PyYAML is unavailable).
# Handles the subset of YAML that Sigma rules use: nested mappings by
# indentation, simple scalars, and inline/block lists. This keeps the tool
# dependency-free and fully offline.
# --------------------------------------------------------------------------
def _parse_yaml(text: str) -> Any:
    try:
        import yaml  # type: ignore

        return yaml.safe_load(text)
    except ImportError:
        return _parse_yaml_minimal(text)


def _parse_yaml_minimal(text: str) -> Any:
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
        # List block?
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
                # Nested block belongs to this key.
                child_indent = ci + 1
                if idx + 1 < len(lines):
                    child_indent = indent_of(lines[idx + 1])
                child, idx = parse_block(idx + 1, child_indent)
                result[key] = child
        return result, idx

    parsed, _ = parse_block(0, 0)
    return parsed


# --------------------------------------------------------------------------
# Sigma linter
# --------------------------------------------------------------------------
def _lint_sigma(content: str) -> Tuple[List[str], List[str]]:
    errors: List[str] = []
    warnings: List[str] = []

    try:
        doc = _parse_yaml(content)
    except Exception as exc:  # surface parse failure, don't swallow
        return ([f"YAML parse error: {exc}"], warnings)

    if not isinstance(doc, dict):
        return (["rule must be a YAML mapping at the top level"], warnings)

    # Required top-level keys.
    for key in ("title", "logsource", "detection"):
        if key not in doc:
            errors.append(f"missing required top-level key: '{key}'")

    # Recommended keys.
    for key in ("id", "level", "status"):
        if key not in doc:
            warnings.append(f"missing recommended key: '{key}'")

    # level value check.
    level = doc.get("level")
    if isinstance(level, str) and level.lower() not in _VALID_SIGMA_LEVELS:
        errors.append(
            f"invalid 'level': {level!r}; expected one of "
            f"{sorted(_VALID_SIGMA_LEVELS)}"
        )

    # logsource sanity.
    logsource = doc.get("logsource")
    if isinstance(logsource, dict):
        if not any(k in logsource for k in ("product", "category", "service")):
            warnings.append(
                "'logsource' should specify at least one of "
                "product/category/service"
            )
    elif "logsource" in doc:
        errors.append("'logsource' must be a mapping")

    # detection block.
    detection = doc.get("detection")
    if isinstance(detection, dict):
        if "condition" not in detection:
            errors.append("'detection' must contain a 'condition'")
        selections = [k for k in detection.keys() if k != "condition"]
        if not selections:
            errors.append(
                "'detection' must define at least one selection besides "
                "'condition'"
            )
        # Validate that condition identifiers reference defined selections.
        cond = detection.get("condition")
        if isinstance(cond, str):
            errors.extend(_check_condition_refs(cond, set(selections)))
        elif isinstance(cond, list):
            for c in cond:
                if isinstance(c, str):
                    errors.extend(_check_condition_refs(c, set(selections)))
    elif "detection" in doc:
        errors.append("'detection' must be a mapping")

    return errors, warnings


# --------------------------------------------------------------------------
# FP-proneness heuristics (WARNING class — informational, never an error)
# --------------------------------------------------------------------------
# Ported from specialists/adversarial-reviewer logic (no_fp_scoping,
# broad_selection, fp_risk). These fire on structurally valid rules that are
# likely to produce excessive false positives in production. The output is a
# separate "fp_warnings" list so existing errors/warnings counts are unaffected.
_HIGH_VOLUME_CATEGORIES = frozenset({
    "process_creation", "network_connection", "dns_query", "file_event",
    "image_load", "registry_event", "pipe_created",
})

_GENERIC_SHORT_VALUES = frozenset({
    "cmd", "tmp", "temp", "log", "run", "bin", "usr", "var", "etc", "net",
    "sys", "win", "app", "get", "set", "put", "del", "new", "old", "all",
})

# Short values that are HIGH-SPECIFICITY IOC markers, not generic noise. A pure
# length threshold cannot tell `cmd` (in every command line ever) from `jndi` (the
# Log4Shell marker, and the core detection in this repo's own evidence): both are
# 3-4 chars. Flagging the latter penalises a surgically precise rule and trains the
# team to ignore the fp_prone signal — so the length rule needs a specificity
# escape hatch.
#
# Two ways a short value earns it: it is a KNOWN marker (below), or it is not
# plain lowercase alphanumerics (a value carrying punctuation/mixed case — `::$`,
# `%%1`, `-enc`, `/c ` — is a syntactic artefact, not an English word, and English
# words are what make a short value generic).
_SPECIFIC_SHORT_VALUES = frozenset({
    "jndi", "ldap", "rmi", "iiop",          # Log4Shell / JNDI injection vectors
    "psexec", "wmic", "certutil", "bitsadmin",  # LOLBins (also >4 but kept together)
    "mimi", "kerb", "asrep", "spn",         # credential-access markers
    "b374k", "r57", "c99",                  # webshell families
    "nc.exe", "ncat",
})


def _has_exclusion_filter(condition: str) -> bool:
    """True only if the condition genuinely EXCLUDES something. PURE.

    The old test was `"not " in condition or "filter" in condition` — a raw substring
    scan, which round 13 showed accepts two things that exclude nothing:
      - `selection or filter_extra` — an OR *WIDENS* the match set, yet the word
        "filter" appearing anywhere satisfied the check, so an actively broader rule
        was credited with having an exclusion filter;
      - a selection merely NAMED `filter_*` that the condition never negates.
    It was also case-sensitive, so an idiomatic `selection AND NOT filter` (upper
    case) was read as having no filter at all.

    An exclusion requires the token `not` in a conjunctive position, i.e. `... and
    not <something>`. That is what we look for, case-insensitively."""
    cond = " ".join(str(condition).lower().split())
    if not cond:
        return False
    # `and not X` / `and not(X)` — the canonical Sigma exclusion.
    if re.search(r"\band\s+not\b", cond):
        return True
    # A leading `not X and ...` also excludes (rare but valid).
    if re.match(r"^not\s+", cond) and " and " in cond:
        return True
    return False


def _iter_predicates(selections: dict):
    """Yield ``(sel_name, field_key, value)`` for EVERY predicate in every selection.

    Handles both selection shapes Sigma allows: a MAP of field→value, and a LIST of
    maps (the standard OR-of-maps form). Round 13 found the breadth checks skipped
    the list form entirely (`isinstance(sel_body, dict)` → `continue`), so a rule
    could evade every breadth check just by wrapping its selection in a list — a
    cosmetic edit that provably does not change the match set."""
    for sel_name, sel_body in selections.items():
        bodies = sel_body if isinstance(sel_body, list) else [sel_body]
        for body in bodies:
            if not isinstance(body, dict):
                continue
            for field_key, field_val in body.items():
                for v in (field_val if isinstance(field_val, list) else [field_val]):
                    yield sel_name, field_key, v


def _match_everything_reason(field_key: str, value) -> str:
    """Return WHY a predicate matches (nearly) every event, or "" if it is selective.

    THE round-13 fix. The old breadth checks keyed on the literal substring
    ``"|contains"`` in the field name, so every other way of spelling
    match-anything was invisible: `Image: '*'`, `|re: '.*'`, `|exists: true`,
    `|gt: 0`, a 1-char `|startswith`. Six such predicates each matched 5/5 benign
    events while scoring ZERO warnings — and worse, the scoring was SIGN-INVERTED on
    a subset relation: `Image: '*'` (a strict superset of `Image|contains: 'cmd'`)
    scored strictly FEWER warnings than the narrower rule.

    So the test is now on the SELECTIVITY OF THE VALUE, whatever modifier spells it.
    Deliberately NOT flagged (they would trade false negatives for false positives on
    idiomatic rules): a normal `|endswith: '.exe'`, or a 3+ char anchor."""
    key = str(field_key)
    mods = [m.strip().lower() for m in key.split("|")[1:]]

    # A presence test alone says only "the field exists" — true of every event that
    # carries the field at all.
    if "exists" in mods and _coerce_truthy(value):
        return f"'{key}' is a presence test only — matches every event carrying the field"

    if isinstance(value, str):
        raw = value.strip()
        # A bare wildcard (any modifier, incl. plain equality) matches everything.
        if raw and set(raw) <= {"*", "?"}:
            return f"'{key}' value {value!r} is a bare wildcard — matches every event"
        if "re" in mods:
            # A regex that accepts any input: .*, .+, ^.*$, (.*) and friends.
            stripped = raw.strip("^$()")
            if stripped in (".*", ".+", ".*?", "") or set(stripped) <= {".", "*", "+", "?"}:
                return f"'{key}' regex {value!r} matches any value"
        # A 1-2 char prefix/suffix anchor is barely narrower than no filter at all.
        if ("startswith" in mods or "endswith" in mods) and 0 < len(raw) <= 2:
            return f"'{key}' anchor {value!r} is only {len(raw)} char(s) — near-universal"

    # A numeric floor at or below the domain minimum excludes nothing. Event ids and
    # counters are non-negative, so `>= 0` / `> -1` is a no-op filter.
    if any(m in mods for m in ("gt", "gte")) and isinstance(value, (int, float)):
        if not isinstance(value, bool):
            floor_excludes_nothing = (value <= 0) if "gt" in mods else (value <= 0)
            if floor_excludes_nothing:
                return f"'{key}' numeric floor {value!r} excludes nothing (non-negative domain)"
    return ""


def _coerce_truthy(value) -> bool:
    """Sigma-ish truthiness for an ``|exists`` flag (``true``/``yes``/1)."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("true", "yes", "1")
    return bool(value)


def _has_high_specificity_predicate(selections: dict) -> bool:
    """True if any selection carries a predicate specific enough to stand alone. PURE.

    Checks #2 (high-volume logsource without an exclusion filter) and #5 (high
    severity with few predicates) both use the ABSENCE OF A SHAPE as a proxy for
    "not specific enough". That proxy misfires on the most precise rules there are:
    a full absolute path or a complete file hash IS its own filter, and needs
    neither an `and not` clause nor extra predicates. Penalising those pushes an
    engineer to loosen a surgical rule, and teaches the team to ignore the
    fp_prone signal.

    High-specificity evidence (any one is enough):
      - a full file hash as an exact value (32/40/64 hex chars — md5/sha1/sha256);
      - an exact (unmodified) value that looks like a full absolute path
        (a drive-letter/UNC Windows path or a rooted POSIX path with >=2 segments);
      - a long exact value (>=24 chars) — a GUID, a full command line, a URL.
    Only EXACT predicates count: a `|contains` on the same text is a substring
    match and is not self-anchoring."""
    for sel_body in selections.values():
        if not isinstance(sel_body, dict):
            continue
        for field_key, field_val in sel_body.items():
            key = str(field_key)
            mods = [m.strip().lower() for m in key.split("|")[1:]]
            # Two DIFFERENT sources of anchoring, and conflating them was a real
            # regression I introduced and the tests caught:
            #
            #  (a) THE VALUE IS INTRINSICALLY UNIQUE — a full md5/sha1/sha256. A hash
            #      identifies one artifact no matter where it sits in the field, so
            #      `Hashes|contains: SHA256=<64 hex>` (the standard Sigma idiom for the
            #      multi-hash `Hashes` field) IS anchored. Round 13 showed the
            #      exact-only rule rejected it and penalised a hash-pinned rule.
            #  (b) THE POSITION PROVIDES THE ANCHORING — a full path / long literal.
            #      Here the modifier matters: `Image: 'C:\\...\\cmd.exe'` pins the whole
            #      field, but `Image|contains: 'C:\\Windows\\System32\\cmd.exe'` is a
            #      SUBSTRING test that fires on any command line quoting that path, and
            #      `Image|endswith: '\\cmd.exe'` matches every cmd.exe launch. Those are
            #      broad, so only an EXACT (unmodified / |cased) predicate qualifies.
            widening = any(m in mods for m in
                           ("re", "gt", "gte", "lt", "lte", "exists", "cidr"))
            if widening:
                continue
            exact_only = not [m for m in mods if m != "cased"]
            for v in (field_val if isinstance(field_val, list) else [field_val]):
                if not isinstance(v, str):
                    continue
                s = v.strip()
                if not s or "*" in s or "?" in s:
                    continue          # a wildcard value is not specific
                low = s.lower()
                # (a) a full hash anchors under ANY non-widening modifier. Tolerate a
                # `SHA256=` style prefix, which the Sigma `Hashes` field uses.
                for token in re.split(r"[=,;\s]+", low):
                    if len(token) in (32, 40, 64) and all(c in "0123456789abcdef" for c in token):
                        return True
                if not exact_only:
                    continue          # (b) needs an exact predicate
                is_win_path = (len(s) > 3 and s[1:3] == ":\\") or s.startswith("\\\\")
                is_posix_path = s.startswith("/") and s.count("/") >= 2
                if (is_win_path or is_posix_path) and len(s) >= 8:
                    return True       # full absolute path, exactly matched
                if len(s) >= 24:
                    return True       # GUID / full command line / URL
    return False


def _is_generic_short_value(value: str) -> bool:
    """True if a short ``|contains`` value is GENERIC (noise-prone), not a specific
    IOC marker. PURE.

    A value is generic when it is short AND reads like a plain English/ASCII word:
    lowercase alphanumerics only, and not on the known-specific list. Anything
    carrying punctuation, mixed case, or a known-marker name is treated as specific
    — it is a syntactic artefact or a named IOC, which is exactly the kind of short
    value a precise rule legitimately keys on."""
    v = value.lower().strip()
    if v in _SPECIFIC_SHORT_VALUES:
        return False
    if v in _GENERIC_SHORT_VALUES:
        return True
    if len(v) > 4:
        return False
    # Short: generic only if it is a bare lowercase-alnum token (an English-looking
    # word). Punctuation / symbols / digits-with-symbols mean a specific artefact.
    return v.isalnum() and v.isascii() and v == value.strip().lower()


def _fp_heuristics_sigma(doc: dict) -> List[str]:
    """Deterministic FP-proneness heuristics for a parsed Sigma rule.

    Returns a list of warning strings (may be empty). These are separate from
    the structural errors/warnings — they assess operational noise risk, not
    correctness. A rule with >=2 fp_warnings is classified as "fp_prone" by the
    audit aggregator for health-score impact."""
    fp: List[str] = []
    if not isinstance(doc, dict):
        return fp

    detection = doc.get("detection")
    if not isinstance(detection, dict):
        return fp

    logsource = doc.get("logsource") or {}
    category = str(logsource.get("category", "")).lower()
    level = str(doc.get("level", "")).lower()
    condition = str(detection.get("condition", ""))

    # Gather all selection values for breadth analysis.
    selections = {k: v for k, v in detection.items() if k != "condition"}

    # 1. Missing falsepositives field entirely.
    if "falsepositives" not in doc:
        fp.append("no 'falsepositives' field — undocumented FP sources")

    # A full path / full hash / long exact value IS its own filter and its own
    # specificity — checks #2 and #5 must not penalise a rule that has one, or the
    # heuristic pushes engineers to loosen their most precise detections.
    specific = _has_high_specificity_predicate(selections)

    # 2. High-volume logsource with no exclusion filter in condition.
    if category in _HIGH_VOLUME_CATEGORIES and not specific:
        if not _has_exclusion_filter(condition):
            fp.append(
                f"high-volume logsource '{category}' with no exclusion filter "
                f"in condition (prone to noise without 'and not <filter>')"
            )

    # 3. Low-selectivity values — ANY modifier, not just |contains.
    #    Two distinct problems, reported separately:
    #      (a) a predicate that matches (nearly) everything, however it is spelled;
    #      (b) a short/generic |contains value.
    #    (a) is what the pre-R13b check could not see at all: it keyed on the literal
    #    substring "|contains", so `Image: '*'` / `|re: '.*'` / `|exists: true` /
    #    `|gt: 0` were invisible — and the scoring was sign-inverted on a subset
    #    relation (a strict superset scored FEWER warnings than its subset).
    seen_broad: set = set()
    for sel_name, field_key, v in _iter_predicates(selections):
        reason = _match_everything_reason(field_key, v)
        if reason and (sel_name, str(field_key)) not in seen_broad:
            seen_broad.add((sel_name, str(field_key)))
            fp.append(f"match-everything predicate in {sel_name}: {reason}")
            # MONOTONICITY: a match-everything predicate is DECISIVE evidence of
            # breadth, not one shape signal among several. Emitting a single warning
            # left the scoring sign-inverted on a subset relation — `Image: '*'`
            # (matches every event) scored 2 while `Image|contains: 'cmd'` (a strict
            # SUBSET of it, matching 1/5) scored 3, because the narrower rule stacked
            # two extra SHAPE warnings. A rule that matches everything must never
            # score below one that matches a subset of it, so this counts for enough
            # to dominate any stack of shape heuristics.
            fp.append(
                f"selection '{sel_name}' cannot be more specific than match-everything "
                f"— this predicate alone makes the rule fire on (nearly) every event"
            )

    seen_generic: set = set()
    for sel_name, field_key, v in _iter_predicates(selections):
        if "|contains" not in str(field_key) or not isinstance(v, str):
            continue
        if _is_generic_short_value(v) and (sel_name, str(field_key)) not in seen_generic:
            seen_generic.add((sel_name, str(field_key)))   # one per field is enough
            fp.append(
                f"short/generic contains value '{v}' in {sel_name}.{field_key}"
            )

    # 4. Selection whose ONLY predicate is a single contains (no anchoring).
    #    Skipped when the rule carries a self-anchoring predicate: a lone
    #    `Hashes|contains: SHA256=<64 hex>` IS anchored by its value, and calling it
    #    "low specificity" is the same false positive checks #2/#5 were exempted from.
    for sel_name, sel_body in selections.items():
        if not isinstance(sel_body, dict) or specific:
            continue
        if len(sel_body) == 1:
            key = next(iter(sel_body))
            if "|contains" in str(key) and "|all" not in str(key):
                fp.append(
                    f"selection '{sel_name}' has only a single contains predicate "
                    f"(low specificity, no anchoring)"
                )

    # 5. Critical/high level with low-specificity selections.
    #    Skipped when a predicate is self-anchoring (full path / hash / long exact):
    #    "few predicates" only implies low specificity if none of them is precise.
    if level in ("critical", "high") and not specific:
        total_predicates = sum(
            len(v) if isinstance(v, dict) else 0 for v in selections.values()
        )
        if total_predicates <= 2:
            fp.append(
                f"level '{level}' with only {total_predicates} predicate(s) "
                f"(high severity + low specificity = noise)"
            )

    return fp


def _check_condition_refs(condition: str, selections: set) -> List[str]:
    """Ensure every identifier used in a condition is a defined selection."""
    errors: List[str] = []
    # Tokenize on operators / whitespace / parentheses / pipe.
    tokens = re.split(r"[\s()]+", condition.strip())
    for tok in tokens:
        if not tok:
            continue
        low = tok.lower()
        if low in _CONDITION_KEYWORDS:
            continue
        if low.isdigit():
            continue
        # Wildcard selection references like 'selection_*' — match by prefix.
        if tok.endswith("*"):
            prefix = tok[:-1]
            if any(s.startswith(prefix) for s in selections):
                continue
            errors.append(
                f"condition references undefined selection pattern: {tok!r}"
            )
            continue
        if tok not in selections:
            errors.append(f"condition references undefined selection: {tok!r}")
    return errors


# --------------------------------------------------------------------------
# YARA linter (lightweight structural check)
# --------------------------------------------------------------------------
def _strip_yara_noise(content: str) -> str:
    """Return ``content`` with the spans that may hold non-structural braces blanked
    (replaced by spaces, newlines preserved): double-quoted strings, ``//`` and
    ``/* */`` comments, hex-string blocks ``{ .. }``, and ``/regex/`` literals.

    WHY: brace balancing and rule-body extraction must see only STRUCTURAL braces
    (a rule's own ``{ }``). A YARA string can hold ``{``/``}`` (``"${jndi:ldap"``),
    a comment can, a hex string IS ``{ E2 34 }``, and a regex literal can (``/a}b/``)
    — counting or extracting across those produced false 'unbalanced braces' /
    'missing condition' errors on valid rules. A tiny state machine skips every such
    span. Regex-free (no catastrophic-backtrack risk).

    Hex-string braces are blanked to SPACES (dropped from the structural count) since
    they are a self-contained token, not a rule delimiter; this keeps both the
    balance count and the depth-based body extraction correct."""
    out: List[str] = []
    i, n = 0, len(content)
    in_str = False
    esc = False
    while i < n:
        ch = content[i]
        if in_str:
            out.append(" ")
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            i += 1
            continue
        # not in a string: check for comment starts
        if ch == '"':
            in_str = True
            out.append(" ")
            i += 1
            continue
        if ch == "/" and i + 1 < n and content[i + 1] == "/":
            while i < n and content[i] != "\n":
                out.append(" ")
                i += 1
            continue
        if ch == "/" and i + 1 < n and content[i + 1] == "*":
            while i < n and not (content[i] == "*" and i + 1 < n and content[i + 1] == "/"):
                out.append("\n" if content[i] == "\n" else " ")
                i += 1
            # blank the closing */ too (if present)
            out.append("  ")
            i += 2
            continue
        # A YARA regex literal /.../ (YARA has no division, so a bare '/' that is
        # not a comment starts a regex). Blank through the closing unescaped '/'.
        if ch == "/":
            out.append(" ")
            i += 1
            r_esc = False
            while i < n:
                rc = content[i]
                out.append("\n" if rc == "\n" else " ")
                i += 1
                if r_esc:
                    r_esc = False
                elif rc == "\\":
                    r_esc = True
                elif rc == "/":
                    break
            continue
        # A hex-string block '{ ... }' holds hex bytes / wildcards, not structural
        # braces. Blank the whole span (braces included) so it drops out of both the
        # balance count and body extraction. Only treat '{' as a hex block when it is
        # NOT the rule-body opener: a hex block's brace is preceded (ignoring space)
        # by '=' ; the rule body's '{' follows a rule header. We detect a hex block by
        # scanning its content — only hex digits, whitespace, and the wildcard/jump
        # tokens [] ? - ( ) | . If anything else appears it is a real body, kept.
        if ch == "{":
            j = i + 1
            ok = True
            depth = 0
            while j < n:
                cj = content[j]
                if cj == "}" and depth == 0:
                    break
                if cj in "([":
                    depth += 1
                elif cj in ")]":
                    depth = max(0, depth - 1)
                elif not (cj.isspace() or cj in "0123456789abcdefABCDEF?-|.~"):
                    ok = False
                    break
                j += 1
            if ok and j < n and content[j] == "}":
                # blank the hex block inclusive of both braces
                for k in range(i, j + 1):
                    out.append("\n" if content[k] == "\n" else " ")
                i = j + 1
                continue
        out.append(ch)
        i += 1
    return "".join(out)


def _extract_rule_body(structural: str, name: str) -> str:
    """Return the body between a rule's opening ``{`` and its MATCHING ``}`` via
    brace-depth counting on the already-noise-stripped text.

    A non-greedy ``\\{(.*?)\\}`` regex stopped at the first ``}`` — which, once hex
    blocks/regexes are stripped, is usually fine, but depth-matching is robust to
    any nested structural braces and is what makes the 'missing condition' check
    trustworthy. Returns '' if the rule header/body cannot be located."""
    m = re.search(r"\brule\s+" + re.escape(name) + r"\s*(?::[^{]*)?\{", structural)
    if not m:
        return ""
    start = m.end()  # first char after the opening '{'
    depth = 1
    i, n = start, len(structural)
    while i < n and depth > 0:
        c = structural[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return structural[start:i]
        i += 1
    return structural[start:]  # unbalanced — caller already flags the imbalance


def _lint_yara(content: str) -> Tuple[List[str], List[str]]:
    errors: List[str] = []
    warnings: List[str] = []

    # Count only STRUCTURAL braces (strings/comments blanked) so a brace inside a
    # string literal (e.g. "${jndi:ldap") is not a false imbalance.
    structural = _strip_yara_noise(content)
    open_braces = structural.count("{")
    close_braces = structural.count("}")
    if open_braces != close_braces:
        errors.append(
            f"unbalanced braces: {open_braces} '{{' vs {close_braces} '}}'"
        )

    # Header + body extraction run on the STRUCTURAL text (strings/comments blanked)
    # so a '{' or '}' inside a string/comment cannot truncate a rule body — the
    # keywords 'condition:'/'strings:' and '$' refs survive blanking (they are not
    # inside string literals), so presence checks stay accurate.
    rule_headers = re.findall(r"\brule\s+([A-Za-z_]\w*)\s*(?::[^{]*)?\{", structural)
    if not rule_headers:
        errors.append("no 'rule <name> { ... }' block found")
        return errors, warnings

    for name in rule_headers:
        body = _extract_rule_body(structural, name)
        if "condition:" not in body:
            errors.append(f"rule {name!r} is missing a 'condition:' section")
        if "strings:" not in body and "$" in body:
            warnings.append(
                f"rule {name!r} references string identifiers ($) but has no "
                "'strings:' section"
            )
    return errors, warnings


# --------------------------------------------------------------------------
# Suricata linter (structural check of the network-IDS rule grammar)
# --------------------------------------------------------------------------
def _split_suricata_rules(content: str) -> List[str]:
    """Split rule text into individual rules, skipping blank lines + # comments.

    Suricata rules are one-per-line (a trailing ``\\`` continues a line). We join
    continuations, then drop comment/blank lines, so each returned entry is one
    complete rule string. Deterministic; no regex backtracking risk."""
    joined: List[str] = []
    buf = ""
    for raw in content.splitlines():
        line = raw.rstrip("\n")
        stripped = line.strip()
        if buf:
            buf += " " + stripped
        elif not stripped or stripped.startswith("#"):
            continue  # comment / blank between rules
        else:
            buf = stripped
        if buf.endswith("\\"):
            buf = buf[:-1].rstrip()  # line continuation → keep accumulating
            continue
        joined.append(buf)
        buf = ""
    if buf:
        joined.append(buf)
    return joined


def _split_suricata_options(options: str) -> List[Tuple[str, str]]:
    """Split a Suricata option block into (key, value) pairs, QUOTE-AWARE.

    A ``;`` only separates options when it is OUTSIDE a double-quoted value (a
    ``msg:"foo; bar"`` holds a literal ``;`` that must NOT split the option), and a
    ``:`` only separates key from value at the FIRST unquoted colon. Backslash
    escapes inside a quote are honored. This replaces the naive ``options.split(';')``
    that let ``msg:"...; sid:1;"`` fake a sid/rev and mis-parsed keys."""
    pairs: List[Tuple[str, str]] = []
    buf: List[str] = []
    in_str = False
    esc = False
    for ch in options:
        if in_str:
            buf.append(ch)
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
            buf.append(ch)
        elif ch == ";":
            opt = "".join(buf).strip()
            if opt:
                key, sep, val = opt.partition(":")
                pairs.append((key.strip().lower(), val.strip() if sep else ""))
            buf = []
        else:
            buf.append(ch)
    tail = "".join(buf).strip()
    if tail:
        key, sep, val = tail.partition(":")
        pairs.append((key.strip().lower(), val.strip() if sep else ""))
    return pairs


def _strip_suricata_quoted(rule: str) -> str:
    """Blank double-quoted spans in a Suricata rule (spaces, length preserved) so a
    balance count of ``(``/``)`` ignores parens inside a quoted ``msg``/``pcre``.
    Honors backslash escapes."""
    out: List[str] = []
    in_str = False
    esc = False
    for ch in rule:
        if in_str:
            out.append(" ")
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
            out.append(" ")
        else:
            out.append(ch)
    return "".join(out)


def _lint_suricata(content: str) -> Tuple[List[str], List[str]]:
    """Structurally lint one or more Suricata rules. PURE, deterministic.

    Checks per rule:
      - the header is ``action proto src sport -> | <> dst dport`` (7 leading
        tokens with a direction operator), action in the known set;
      - an option block ``( ... )`` is present and balanced;
      - required options ``msg``, ``sid``, ``rev`` are present;
      - ``sid`` is numeric;
    Warns on a missing ``classtype`` (best practice). Errors make the rule invalid.
    """
    errors: List[str] = []
    warnings: List[str] = []

    rules = _split_suricata_rules(content)
    if not rules:
        errors.append("no Suricata rule found (expected 'action proto ... (options)')")
        return errors, warnings

    for idx, rule in enumerate(rules, 1):
        tag = f"rule {idx}" if len(rules) > 1 else "rule"
        # Balanced option-block parentheses — count only parens OUTSIDE quoted
        # values (a ':-(' in a quoted msg or a '(' in a pcre must not count).
        unquoted = _strip_suricata_quoted(rule)
        if unquoted.count("(") != unquoted.count(")"):
            errors.append(f"{tag}: unbalanced parentheses in option block")
            continue
        open_paren = unquoted.find("(")
        if open_paren == -1 or not unquoted.rstrip().endswith(")"):
            errors.append(f"{tag}: missing '( ... )' option block")
            continue

        header = rule[:open_paren].strip()
        # Option block interior taken from the ORIGINAL rule (quotes intact) using
        # the quote-aware open/close positions computed on the blanked text.
        options = rule[open_paren + 1: unquoted.rstrip().rfind(")")]

        # Header: action proto src sport <dir> dst dport  → >= 7 tokens.
        htoks = header.split()
        if not htoks:
            errors.append(f"{tag}: empty rule header")
            continue
        if htoks[0].lower() not in _SURICATA_ACTIONS:
            errors.append(
                f"{tag}: unknown action {htoks[0]!r} (expected one of "
                f"{sorted(_SURICATA_ACTIONS)})"
            )
        if not any(d in htoks for d in ("->", "<>")):
            errors.append(f"{tag}: header missing a direction operator ('->' or '<>')")
        elif len(htoks) < 7:
            errors.append(
                f"{tag}: header must be 'action proto src sport <dir> dst dport', "
                f"got {len(htoks)} tokens"
            )

        # Required options — parsed QUOTE-AWARE so a ';' inside a quoted value does
        # not fabricate an option and a ':' inside a value is not read as a key.
        opts = _split_suricata_options(options)
        opt_names = {k for k, _ in opts}
        for req in _SURICATA_REQUIRED_OPTS:
            if req not in opt_names:
                errors.append(f"{tag}: missing required option '{req}'")

        # sid must be numeric when present — read the value from the parsed options
        # (the REAL sid key), not a regex over raw text that could match 'sid:' in msg.
        sid_vals = [v for k, v in opts if k == "sid"]
        if sid_vals and not sid_vals[0].isdigit():
            errors.append(f"{tag}: 'sid' must be numeric, got {sid_vals[0]!r}")

        if "classtype" not in opt_names:
            warnings.append(f"{tag}: no 'classtype' option (recommended for triage)")

    return errors, warnings


# --------------------------------------------------------------------------
# Handler
# --------------------------------------------------------------------------
def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Deterministically lint a Sigma or YARA detection rule.

    Pure Python: no LLM, no tokens, no network, no secrets. Same input
    always produces the same output, making it safe as a mandatory gate in
    an automated detection pipeline.
    """
    try:
        rule_type, content = _validate(event)
    except ValueError as exc:
        return {"ok": False, "error": "validation_error", "message": str(exc)}

    if rule_type == "sigma":
        errors, warnings = _lint_sigma(content)
        fp_warnings = _fp_heuristics_sigma(_parse_yaml(content) if not errors else {})
    elif rule_type == "suricata":
        errors, warnings = _lint_suricata(content)
        fp_warnings = []
    else:  # yara
        errors, warnings = _lint_yara(content)
        fp_warnings = []

    result: Dict[str, Any] = {
        "ok": True,
        "rule_type": rule_type,
        "valid": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
    }
    if fp_warnings:
        result["fp_warnings"] = fp_warnings
    return result


if __name__ == "__main__":
    import json

    sample = """
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
    print(json.dumps(handler({"rule_type": "sigma", "content": sample}, None), indent=2))
