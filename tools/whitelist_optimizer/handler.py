"""whitelist_optimizer — deterministic, offline FP-to-whitelist synthesizer.

SecOps purpose (M6 feedback loop)
---------------------------------
When alert triage dispositions an alert as a FALSE POSITIVE, the detection
strategy should *learn* from it: a noisy rule that keeps firing on known-good
traffic should be given a tuned suppression/whitelist clause so it stops
crying wolf — WITHOUT going blind to the real threats it was built to catch.

This tool is the deterministic engine that closes that loop. Given a rule
name and a cohort of confirmed false-positive events, it:

  1. Analyzes the FP events and extracts the COMMON discriminating field that
     all of them share (e.g. every FP hit a CDN ``dst_domain``, or every FP
     was the ``backup.exe`` process, or every FP source IP falls inside one
     tight CIDR).
  2. Synthesizes a Sigma-style ``filter`` clause on that discriminator plus a
     ``condition: selection and not filter`` snippet.
  3. Guards against over-suppression: it will REFUSE to emit a whitelist that
     (a) has no safe common discriminator, or (b) would also suppress a
     provided true-positive example. In those cases it returns a clear
     "no safe whitelist" verdict instead of overfitting or suppressing
     everything.

Honesty label
-------------
This synthesis is REAL deterministic offline logic — same input always yields
the same whitelist. It is labelled ``source: "stub"`` because it performs no
LLM reasoning and makes no network calls; the downstream rule-regeneration
RUN that consumes this clause reuses the M1/M2 self-improving loop, driven
in-process/offline for the POC. Nothing here is "live".

Input contract
--------------
event = {
    "rule_name":     str,            # REQUIRED, the noisy rule being tuned
    "fp_events":     [ {..alert..} ],# REQUIRED, non-empty list of FP dicts
    "existing_rule": <sigma dict|str>,   # OPTIONAL, to merge the condition
    "tp_examples":   [ {..alert..} ],    # OPTIONAL, true-positives to protect
}
Any fp_event may also be flagged as a true-positive in-line (a "mixed set")
via ``disposition``/``verdict``/``label`` == "true_positive"/"tp", or
``is_true_positive: true``; such events are treated as TP guards, never as
FPs to suppress.

Output contract (safe whitelist found)
--------------------------------------
{
    "ok": True,
    "source": "stub",
    "rule_name": "...",
    "whitelist": {"fields": {"<field>": "<value>"}, "match_type": "..."},
    "suppressed_count": 2,
    "sigma_filter_yaml": "detection:\\n    filter_known_good:\\n ...",
    "rationale": "...",
}

Output contract (no safe whitelist)
------------------------------------
{
    "ok": True,
    "source": "stub",
    "rule_name": "...",
    "whitelist": None,
    "verdict": "no_safe_whitelist",
    "suppressed_count": 0,
    "rationale": "...",
}

Bad input:
{"ok": False, "error": "validation_error", "message": "..."}

Egress & secrets posture
------------------------
ZERO egress, ZERO secrets, ZERO tokens, no LLM. ``SENTINEL_EXECUTION_ROLE_ARN``,
``SENTINEL_REGION`` and ``AWS_PROFILE`` are honored for harness consistency but
are NOT required to run this tool.
"""

from __future__ import annotations

import importlib.util
import ipaddress
import os
import re
from typing import Any, Dict, List, Optional, Tuple

# --------------------------------------------------------------------------
# match_type constants
# --------------------------------------------------------------------------
MATCH_EXACT = "exact"
MATCH_DOMAIN_EXACT = "domain_exact"
MATCH_DOMAIN_SUFFIX = "domain_suffix"
MATCH_CIDR = "cidr"

# Field types used to interpret candidate discriminators.
_TYPE_DOMAIN = "domain"
_TYPE_IP = "ip"
_TYPE_EXACT = "exact"

# Candidate discriminating fields, in DETERMINISTIC priority order. Strong,
# benign-identifying discriminators come first (a CDN domain, a known process,
# a file hash), then network locality (IP/CIDR), then weaker context fields.
# The first field that yields a discriminator common to every FP event AND
# that does not also match a true-positive wins — this ordering is what lets
# the tool pick the *safe* field when several are shared.
_CANDIDATE_FIELDS: List[Tuple[str, str]] = [
    ("dst_domain", _TYPE_DOMAIN),
    ("domain", _TYPE_DOMAIN),
    ("dns_query", _TYPE_DOMAIN),
    ("url_domain", _TYPE_DOMAIN),
    ("http_host", _TYPE_DOMAIN),
    ("process_name", _TYPE_EXACT),
    ("process", _TYPE_EXACT),
    ("image", _TYPE_EXACT),
    ("process_path", _TYPE_EXACT),
    ("sha256", _TYPE_EXACT),
    ("hash", _TYPE_EXACT),
    ("src_ip", _TYPE_IP),
    ("dst_ip", _TYPE_IP),
    ("ip", _TYPE_IP),
    ("user", _TYPE_EXACT),
    ("username", _TYPE_EXACT),
    ("src_user", _TYPE_EXACT),
    ("host", _TYPE_EXACT),
    ("hostname", _TYPE_EXACT),
    ("dst_port", _TYPE_EXACT),
    ("port", _TYPE_EXACT),
]

# Minimum CIDR prefix lengths accepted, to avoid over-suppression. A CIDR
# broader than these (i.e. covering more than a small block) is rejected as an
# unsafe whitelist — we do not want to whitelist a whole /8.
_MIN_PREFIX_V4 = 24
_MIN_PREFIX_V6 = 48

# In-line true-positive markers that a caller may set on an fp_event to say
# "this one is actually a real detection, protect it".
_TP_STRINGS = {"true_positive", "tp", "true-positive", "truepositive"}


# --------------------------------------------------------------------------
# YAML parsing reuse (for an optional existing_rule) — same pattern as
# tools/sigma_match: import the sibling parser by path, degrade gracefully.
# --------------------------------------------------------------------------
def _load_sibling_parse_yaml():
    """Import ``_parse_yaml`` from tools/sigma_yara_lint by absolute path.

    tools/ is a flat scripts tree (not an installed package), so we load the
    sibling module by path. Any failure is non-fatal — the caller falls back
    to a tiny regex-based condition extractor so this tool stays offline and
    self-contained.
    """
    sibling = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "sigma_yara_lint",
        "handler.py",
    )
    if not os.path.exists(sibling):
        return None
    spec = importlib.util.spec_from_file_location(
        "_wlopt_sigma_yara_lint_handler", sibling
    )
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception:  # pragma: no cover - defensive, sibling always present
        return None
    return getattr(mod, "_parse_yaml", None)


def _extract_condition(existing_rule: Any) -> str:
    """Return the ``detection.condition`` of an existing rule, or 'selection'.

    ``existing_rule`` may be a parsed Sigma dict or a YAML string. On any
    problem we default to the conventional ``selection`` name rather than
    raising — the caller only needs the condition to compose the merged
    ``... and not filter`` expression.
    """
    if existing_rule is None:
        return "selection"

    parsed: Any = None
    if isinstance(existing_rule, dict):
        parsed = existing_rule
    elif isinstance(existing_rule, str) and existing_rule.strip():
        fn = _load_sibling_parse_yaml()
        if fn is not None:
            try:
                parsed = fn(existing_rule)
            except Exception:
                parsed = None
        if not isinstance(parsed, dict):
            # Minimal fallback: grab the RHS of a top-level "condition:" line.
            m = re.search(r"^\s*condition:\s*(.+?)\s*$", existing_rule, re.MULTILINE)
            if m:
                return m.group(1).strip().strip("'\"") or "selection"
            return "selection"

    if isinstance(parsed, dict):
        detection = parsed.get("detection")
        if isinstance(detection, dict):
            cond = detection.get("condition")
            if isinstance(cond, list):
                parts = [str(c).strip() for c in cond if str(c).strip()]
                if parts:
                    return " or ".join(f"({p})" for p in parts)
            elif isinstance(cond, str) and cond.strip():
                return cond.strip()
    return "selection"


# --------------------------------------------------------------------------
# Input validation
# --------------------------------------------------------------------------
def _validate(event: Dict[str, Any]) -> Tuple[str, List[Dict[str, Any]], Any, List[Dict[str, Any]]]:
    """Validate input; return (rule_name, fp_events, existing_rule, tp_examples).

    Raises ValueError on any malformed input so the handler can surface a
    validation_error with a clear reason (never swallow the cause).
    """
    if not isinstance(event, dict):
        raise ValueError("event must be a dict")

    rule_name = event.get("rule_name")
    if not isinstance(rule_name, str) or not rule_name.strip():
        raise ValueError("'rule_name' is required and must be a non-empty string")

    fp_events = event.get("fp_events")
    if not isinstance(fp_events, list) or not fp_events:
        raise ValueError("'fp_events' is required and must be a non-empty list")
    for i, ev in enumerate(fp_events):
        if not isinstance(ev, dict):
            raise ValueError(f"fp_events[{i}] must be a dict, got {type(ev).__name__}")

    tp_examples = event.get("tp_examples", event.get("true_positive_examples", []))
    if tp_examples is None:
        tp_examples = []
    if not isinstance(tp_examples, list):
        raise ValueError("'tp_examples' must be a list when provided")
    for i, ev in enumerate(tp_examples):
        if not isinstance(ev, dict):
            raise ValueError(f"tp_examples[{i}] must be a dict, got {type(ev).__name__}")

    existing_rule = event.get("existing_rule")
    if existing_rule is not None and not isinstance(existing_rule, (dict, str)):
        raise ValueError("'existing_rule' must be a Sigma dict or YAML string when provided")

    return rule_name.strip(), fp_events, existing_rule, tp_examples


def _is_tp_marked(ev: Dict[str, Any]) -> bool:
    """True if an fp_event is actually flagged as a true-positive (a guard).

    Recognizes the alert-triage disposition vocabulary so a "mixed set" that
    accidentally (or intentionally) includes a real detection never gets
    suppressed by the synthesized whitelist.
    """
    if ev.get("is_true_positive") is True:
        return True
    for key in ("disposition", "verdict", "label"):
        val = ev.get(key)
        if isinstance(val, str) and val.strip().lower() in _TP_STRINGS:
            return True
    return False


# --------------------------------------------------------------------------
# Value extraction / normalization helpers
# --------------------------------------------------------------------------
def _get_field(ev: Dict[str, Any], field: str) -> Optional[str]:
    """Return a non-empty stringified field value, or None if absent/empty."""
    val = ev.get(field)
    if val is None:
        return None
    s = str(val).strip()
    return s or None


def _all_values(events: List[Dict[str, Any]], field: str) -> Optional[List[str]]:
    """Return the field value for EVERY event, or None if any event lacks it.

    A discriminator is only usable if it is present in all FP events; a single
    missing value disqualifies the field.
    """
    values: List[str] = []
    for ev in events:
        v = _get_field(ev, field)
        if v is None:
            return None
        values.append(v)
    return values


# --------------------------------------------------------------------------
# Discriminator computation per field type
# --------------------------------------------------------------------------
def _common_domain(domains: List[str]) -> Optional[Tuple[str, str]]:
    """Compute a safe common domain discriminator.

    Returns ``(match_type, value)`` where match_type is ``domain_exact`` (all
    identical) or ``domain_suffix`` (a shared parent of >= 2 labels, so we
    don't whitelist an entire TLD). Returns None if no safe common domain.
    """
    low = [d.lower().rstrip(".") for d in domains]
    if len(set(low)) == 1:
        return (MATCH_DOMAIN_EXACT, low[0])

    # Longest common label-suffix (compare labels from the right).
    reversed_labels = [list(reversed(d.split("."))) for d in low]
    common: List[str] = []
    for tup in zip(*reversed_labels):
        if len(set(tup)) == 1:
            common.append(tup[0])
        else:
            break
    if len(common) >= 2:  # require at least e.g. "example.com", never just "com"
        return (MATCH_DOMAIN_SUFFIX, ".".join(reversed(common)))
    return None


def _common_cidr(ip_strings: List[str]) -> Optional[Tuple[str, str]]:
    """Compute the minimal covering CIDR (or exact IP) for a set of addresses.

    Returns ``(match_type, value)``: ``exact`` if all IPs are identical, else
    ``cidr`` with the smallest network containing them — but only if that
    network is no broader than the configured minimum prefix, otherwise None
    (too broad to be a safe whitelist).
    """
    try:
        addrs = [ipaddress.ip_address(s) for s in ip_strings]
    except ValueError:
        return None  # not IPs; caller may still try exact match elsewhere
    versions = {a.version for a in addrs}
    if len(versions) != 1:
        return None
    version = versions.pop()

    ints = [int(a) for a in addrs]
    if len(set(ints)) == 1:
        return (MATCH_EXACT, str(addrs[0]))

    bits = 32 if version == 4 else 128
    first = ints[0]
    diff = 0
    for v in ints[1:]:
        diff |= first ^ v
    prefix = bits - diff.bit_length()  # leading identical bits

    min_prefix = _MIN_PREFIX_V4 if version == 4 else _MIN_PREFIX_V6
    if prefix < min_prefix:
        return None  # network too broad — refuse to whitelist a huge block

    network_int = first & (((1 << prefix) - 1) << (bits - prefix)) if prefix else 0
    net = ipaddress.ip_network((int(network_int), prefix), strict=False)
    return (MATCH_CIDR, str(net))


def _discriminator_for_field(
    field: str, ftype: str, fp_events: List[Dict[str, Any]]
) -> Optional[Tuple[str, str]]:
    """Return ``(match_type, value)`` for a field, or None if not usable.

    A field is usable only if every FP event carries it and the values share a
    safe common representation for the field's type.
    """
    values = _all_values(fp_events, field)
    if values is None:
        return None

    if ftype == _TYPE_DOMAIN:
        return _common_domain(values)
    if ftype == _TYPE_IP:
        return _common_cidr(values)
    # Exact-match fields: usable only if every value is identical (case-insens).
    low = [v.lower() for v in values]
    if len(set(low)) == 1:
        return (MATCH_EXACT, values[0])
    return None


# --------------------------------------------------------------------------
# Clause matching (authoritative for suppressed_count + TP guard)
# --------------------------------------------------------------------------
def _clause_matches(ev: Dict[str, Any], field: str, match_type: str, value: str) -> bool:
    """Does one event match the synthesized whitelist clause?

    This is the single source of truth used both to count suppressed FPs and
    to prove the clause does not catch a true-positive.
    """
    raw = _get_field(ev, field)
    if raw is None:
        return False

    if match_type == MATCH_EXACT:
        return raw.lower() == value.lower()
    if match_type == MATCH_DOMAIN_EXACT:
        return raw.lower().rstrip(".") == value.lower().rstrip(".")
    if match_type == MATCH_DOMAIN_SUFFIX:
        dv = raw.lower().rstrip(".")
        sv = value.lower().rstrip(".")
        return dv == sv or dv.endswith("." + sv)
    if match_type == MATCH_CIDR:
        try:
            return ipaddress.ip_address(raw) in ipaddress.ip_network(value, strict=False)
        except ValueError:
            return False
    return False


# --------------------------------------------------------------------------
# Sigma YAML snippet synthesis
# --------------------------------------------------------------------------
def _sigma_filter_yaml(field: str, match_type: str, value: str, base_condition: str) -> str:
    """Render the ``filter`` selection + merged condition as a Sigma snippet.

    The condition becomes ``<base> and not filter_known_good``, wrapping the
    base in parentheses when it is a compound expression so precedence is
    preserved.
    """
    if match_type == MATCH_EXACT:
        key, val = field, value
    elif match_type == MATCH_DOMAIN_EXACT:
        key, val = field, value
    elif match_type == MATCH_DOMAIN_SUFFIX:
        # If every value is a strict subdomain, anchor on a leading dot for a
        # label boundary; else emit the bare suffix so the apex still matches.
        key = f"{field}|endswith"
        val = value
    elif match_type == MATCH_CIDR:
        key, val = f"{field}|cidr", value
    else:  # pragma: no cover - defensive
        key, val = field, value

    needs_parens = any(op in f" {base_condition.lower()} " for op in (" and ", " or ", " not "))
    base = f"({base_condition})" if needs_parens else base_condition
    condition = f"{base} and not filter_known_good"

    return (
        "detection:\n"
        "    filter_known_good:\n"
        f"        {key}: '{val}'\n"
        f"    condition: {condition}\n"
    )


# --------------------------------------------------------------------------
# Handler
# --------------------------------------------------------------------------
def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Turn a cohort of false-positive events into a safe Sigma whitelist clause.

    Deterministic and offline: same input always yields the same result. Never
    emits a whitelist that suppresses a provided true-positive, and never
    fabricates one when the FPs share no safe common discriminator.
    """
    try:
        rule_name, fp_events, existing_rule, tp_examples = _validate(event)
    except ValueError as exc:
        return {"ok": False, "error": "validation_error", "message": str(exc)}

    # Split any in-line true-positive-flagged events out of the FP cohort and
    # fold them into the TP guard set.
    tp_guards: List[Dict[str, Any]] = list(tp_examples)
    fp_cohort: List[Dict[str, Any]] = []
    for ev in fp_events:
        if _is_tp_marked(ev):
            tp_guards.append(ev)
        else:
            fp_cohort.append(ev)

    base_condition = _extract_condition(existing_rule)

    if not fp_cohort:
        return {
            "ok": True,
            "source": "stub",
            "rule_name": rule_name,
            "whitelist": None,
            "verdict": "no_safe_whitelist",
            "suppressed_count": 0,
            "rationale": (
                "No false-positive events remain to analyze after separating "
                "true-positive-flagged events; refusing to synthesize a whitelist."
            ),
        }

    # Evaluate candidate fields in priority order; the first that yields a
    # discriminator common to every FP AND that does not match any TP wins.
    rejected_for_tp: List[str] = []
    for field, ftype in _CANDIDATE_FIELDS:
        disc = _discriminator_for_field(field, ftype, fp_cohort)
        if disc is None:
            continue
        match_type, value = disc

        # Guard: the clause must NOT suppress any known true-positive.
        if any(_clause_matches(tp, field, match_type, value) for tp in tp_guards):
            rejected_for_tp.append(field)
            continue

        suppressed_count = sum(
            1 for ev in fp_cohort if _clause_matches(ev, field, match_type, value)
        )
        sigma_yaml = _sigma_filter_yaml(field, match_type, value, base_condition)
        rationale = (
            f"All {len(fp_cohort)} false-positive event(s) for rule "
            f"'{rule_name}' share {field}={value!r} ({match_type}); a "
            f"whitelist on this discriminator suppresses {suppressed_count} of "
            f"them"
            + (
                f" while preserving {len(tp_guards)} true-positive example(s)."
                if tp_guards
                else "."
            )
        )
        return {
            "ok": True,
            "source": "stub",
            "rule_name": rule_name,
            "whitelist": {"fields": {field: value}, "match_type": match_type},
            "suppressed_count": suppressed_count,
            "sigma_filter_yaml": sigma_yaml,
            "rationale": rationale,
        }

    # No safe discriminator: either the FPs share nothing, or every shared
    # field would also suppress a true-positive.
    if rejected_for_tp:
        rationale = (
            f"The false-positive events for rule '{rule_name}' share "
            f"discriminator(s) on {sorted(set(rejected_for_tp))}, but every one "
            "would also suppress a provided true-positive example. Refusing to "
            "emit a whitelist that would blind the rule to a real detection."
        )
    else:
        rationale = (
            f"The {len(fp_cohort)} false-positive events for rule '{rule_name}' "
            "share no common discriminating field. Refusing to synthesize a "
            "whitelist that would overfit these exact events or suppress "
            "legitimate traffic."
        )
    return {
        "ok": True,
        "source": "stub",
        "rule_name": rule_name,
        "whitelist": None,
        "verdict": "no_safe_whitelist",
        "suppressed_count": 0,
        "rationale": rationale,
    }


if __name__ == "__main__":
    import json

    demo = {
        "rule_name": "Malware Beacon to C2 Domain",
        "fp_events": [
            {"alert_id": "a1", "dst_domain": "img.assets.example.com", "host": "web-01"},
            {"alert_id": "a2", "dst_domain": "js.assets.example.com", "host": "web-02"},
        ],
        "tp_examples": [
            {"alert_id": "t1", "dst_domain": "cdn-update.example.test", "host": "web-01"},
        ],
    }
    print(json.dumps(handler(demo, None), indent=2))
