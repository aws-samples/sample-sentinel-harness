"""
Regression tests for the round-6 adversarial-audit fixes.
================================================================================
Round-6 audited gateway / exporter / observability / benchmark_models / scenarios /
a2a-contract. 9 findings survived independent skeptic verification; this file pins
each so it cannot silently regress:

  * allowlist_optimizer (HIGH) — for a domain_suffix allowlist whose FP cohort
    includes the apex, the matcher CERTIFIED suppression of the apex (dv == sv) but
    the emitted Sigma only had `|endswith: '.suffix'` (misses the apex) → a
    false-green: scenario reported closed=True while a real FP leaked. Now the
    emitter produces an OR of an exact-apex clause + a strict-subdomain clause, so
    the artifact matches what the matcher certifies.
  * a2a-contract (HIGH x2) — the production `strands_model_callable` seams fed a
    Strands `AgentResult.message` (a dict) to `json.loads`, always raising
    TypeError → every live A2A call returned an internal error. Now the text is
    extracted from the message's content parts.
  * gateway (MED) — target-name validation used the stricter GATEWAY regex (48
    chars, no trailing hyphen), falsely rejecting service-valid target names. Now a
    separate 100-char/trailing-hyphen-allowed target validator.
  * exporter (MED) — an allowedTools entry with a newline broke out of its `#`
    comment line, injecting code into the exported module. Now sanitized to one
    inert comment line.
  * observability (MED) — emit_* helpers raised TypeError when a caller passed a
    dim colliding with the fixed dimension name (kind/gate/dimension/input_tokens).
    Now positional-only params + merge so the caller value wins, no crash.
  * gateway (LOW) — wait_gateway_ready treated DELETING as transient → polled to
    timeout. Now DELETING/DELETE_UNSUCCESSFUL are terminal (fail fast).
  * observability (LOW) — a non-finite float DIMENSION value emitted NaN/Infinity
    (invalid JSON, silently dropped by a strict MetricFilter). Now coerced to a str.
  * benchmark_models (LOW) — ModeModel/ModelPrice numeric fields were unvalidated
    (unlike Workload); a negative/NaN produced garbage rankings. Now validated.

HARD RULE: ZERO network, ZERO tokens, ZERO AWS — pure Python / monkeypatched.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_tool(name: str):
    path = os.path.join(_ROOT, "tools", name, "handler.py")
    spec = importlib.util.spec_from_file_location(f"{name}_r6", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _load_specialist_mod(rel_path: str, unique: str):
    path = os.path.join(_ROOT, "specialists", rel_path)
    spec = importlib.util.spec_from_file_location(unique, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[unique] = mod
    spec.loader.exec_module(mod)
    return mod


# --------------------------------------------------------------------------- #
# #1 (HIGH) — allowlist_optimizer domain_suffix apex is actually suppressed   #
# --------------------------------------------------------------------------- #
wl = _load_tool("allowlist_optimizer")
sm = _load_tool("sigma_match")


def _apex_cohort_result():
    fp = [{"dst_domain": "assets.example.com"},          # the apex
          {"dst_domain": "img.assets.example.com"},
          {"dst_domain": "js.assets.example.com"}]
    return wl.handler({
        "rule_name": "r", "fp_events": fp, "field": "dst_domain",
        "existing_rule": "detection:\n  selection:\n    x: y\n  condition: selection\n",
    }, None)


def test_domain_suffix_emits_apex_and_subdomain_clauses():
    res = _apex_cohort_result()
    syaml = res["sigma_filter_yaml"]
    assert res["suppressed_count"] == 3
    assert "filter_known_good_apex" in syaml and "filter_known_good_sub" in syaml
    assert "dst_domain: 'assets.example.com'" in syaml          # exact apex
    assert "dst_domain|endswith: '.assets.example.com'" in syaml  # strict subdomain


def test_emitted_artifact_actually_suppresses_all_three_including_apex():
    """The certified suppressed_count (3) must equal what the emitted Sigma really
    suppresses — the false-green this fix closes."""
    # Build a full rule that embeds the emitter's two filter selections + condition,
    # with a base `selection` that fires on every example.com domain.
    rule = (
        "title: t\n"
        "logsource:\n"
        "    category: proxy\n"
        "detection:\n"
        "    selection:\n"
        "        dst_domain|contains: 'example.com'\n"
        "    filter_known_good_apex:\n"
        "        dst_domain: 'assets.example.com'\n"
        "    filter_known_good_sub:\n"
        "        dst_domain|endswith: '.assets.example.com'\n"
        "    condition: selection and not (filter_known_good_apex or filter_known_good_sub)\n"
    )
    for dom, should_suppress in [("assets.example.com", True),
                                 ("img.assets.example.com", True),
                                 ("js.assets.example.com", True),
                                 ("evilexample.com", False)]:  # cross-label must still fire
        res = sm.handler({"rule": rule, "log_event": {"dst_domain": dom}}, None)
        assert res.get("ok"), res
        assert (not res["matched"]) == should_suppress, (dom, res["matched"])


# --------------------------------------------------------------------------- #
# #2/#6 (HIGH) — a2a strands_model_callable parses a Message dict, not crashes #
# --------------------------------------------------------------------------- #
class _FakeAgentResult:
    """Mimics a Strands AgentResult: .message is a Message DICT; __str__ joins text."""

    def __init__(self, envelope_json: str):
        self.message = {"role": "assistant", "content": [{"text": envelope_json}]}

    def __str__(self):
        return "".join(p.get("text", "") for p in self.message["content"])


_A2A = _load_specialist_mod("_a2a_contract.py", "a2a_contract_r6")


def test_shared_seam_parses_message_dict_envelope():
    envelope = '{"verdict": "ok", "grounded": true}'
    callable_ = _A2A.strands_model_callable(lambda text: _FakeAgentResult(envelope))
    out = callable_("hi")
    assert out == {"verdict": "ok", "grounded": True}


def test_shared_seam_text_extractor_handles_shapes():
    # message dict with text parts
    assert _A2A._agent_result_text(_FakeAgentResult('{"a":1}')) == '{"a":1}'
    # a bare string result
    assert _A2A._agent_result_text("plain") == "plain"


def test_cve_intel_seam_parses_message_dict_envelope():
    cve = _load_specialist_mod(os.path.join("cve-intel", "local_a2a.py"), "cve_intel_local_a2a_r6")
    envelope = '{"cve_id": "CVE-2024-0001", "grounded": false}'
    callable_ = cve.strands_model_callable(lambda text: _FakeAgentResult(envelope))
    assert callable_("hi") == {"cve_id": "CVE-2024-0001", "grounded": False}


# --------------------------------------------------------------------------- #
# #3 (MED) — gateway target-name validator is wider than the gateway one      #
# --------------------------------------------------------------------------- #
from sentinel_harness import gateway as gw  # noqa: E402


def test_target_name_allows_long_and_trailing_hyphen():
    long_name = "nvd-vuln-lookup-and-cve-enrichment-federated-tool-target-x60"
    assert len(long_name) > 48
    assert gw._validate_target_name(long_name) == long_name
    assert gw._validate_target_name("nvd-tools-") == "nvd-tools-"


def test_gateway_name_still_strict():
    with pytest.raises(ValueError):
        gw._validate_name("nvd-tools-")           # trailing hyphen rejected for gateways
    with pytest.raises(ValueError):
        gw._validate_name("a" * 49)               # >48 chars rejected for gateways


# --------------------------------------------------------------------------- #
# #4 (MED) — exporter comment injection                                       #
# --------------------------------------------------------------------------- #
from sentinel_harness import exporter as ex  # noqa: E402


def test_allowed_tool_newline_cannot_inject_code():
    cfg = {"name": "t", "system_prompt": "You are a test.",
           "allowed_tools": ["code_interpreter", "evil\nimport os\nMALICIOUS = 1"]}
    art = ex.export_harness_to_strands(cfg)
    # no injected TOP-LEVEL code line
    injected = [ln for ln in art.splitlines()
                if ln.strip() and not ln.startswith(("#", " "))
                and ("MALICIOUS" in ln or ln.strip() == "import os")]
    assert injected == []
    # the whole module is still valid python
    import ast
    ast.parse(art)


def test_comment_safe_collapses_control_chars():
    assert "\n" not in ex._comment_safe("a\nb\tc\rd")


# --------------------------------------------------------------------------- #
# #5 (MED) — observability emit_* dimension collisions do not crash           #
# --------------------------------------------------------------------------- #
from sentinel_harness import observability as obs  # noqa: E402


def test_emit_error_kind_collision_no_crash():
    line = obs.emit_error("s", "throttle", log=lambda x: None, kind="manual")
    assert line["kind"] == "manual"   # caller override wins (last-writer)


def test_emit_hitl_gate_gate_collision_no_crash():
    line = obs.emit_hitl_gate("s", "tool", log=lambda x: None, gate="override")
    assert line["gate"] == "override"


def test_emit_eval_score_dimension_collision_no_crash():
    line = obs.emit_eval_score("s", "safety", 0.9, True, log=lambda x: None, dimension="d2")
    assert line["dimension"] == "d2"


def test_emit_token_metric_extra_collision_no_crash():
    line = obs.emit_token_metric("s", 5, 5, log=lambda x: None, input_tokens=999)
    assert line["tokens"] == 10        # real value preserved, extra ignored/merged safely


def test_emit_error_normal_path_unchanged():
    line = obs.emit_error("s", "throttle", log=lambda x: None)
    assert line["kind"] == "throttle" and line["errors"] == 1.0


# --------------------------------------------------------------------------- #
# #7 (LOW) — gateway wait fails fast on DELETING                              #
# --------------------------------------------------------------------------- #
def test_wait_gateway_ready_fails_fast_on_deleting(monkeypatch):
    class _Ctrl:
        def get_gateway(self, **k):
            return {"status": "DELETING", "statusReasons": ["deleted"]}

    monkeypatch.setattr(gw, "_control", _Ctrl())
    with pytest.raises(RuntimeError, match="DELETING"):
        gw.wait_gateway_ready("gw-1", timeout=5)


# --------------------------------------------------------------------------- #
# #8 (LOW) — non-finite dimension value stays strict-JSON safe                #
# --------------------------------------------------------------------------- #
def test_non_finite_dim_is_strict_json_safe():
    line = obs.emit_invoke_latency("s", 42, log=lambda x: None, ratio=float("nan"))
    json.loads(json.dumps(line))       # must not raise (no bare NaN token)
    assert line["ratio"] == "nan"
    assert line["latency_ms"] == 42.0


# --------------------------------------------------------------------------- #
# #9 (LOW) — benchmark_models validates numeric fields like Workload          #
# --------------------------------------------------------------------------- #
from sentinel_harness import benchmark_models as bm  # noqa: E402


def test_shipped_modes_and_prices_pass_validation():
    # importing already constructed them; re-assert the shipped constants are valid.
    assert len(bm.MODES) >= 1 and len(bm.MODEL_PRICES) >= 1


@pytest.mark.parametrize("bad", [-1.0, float("nan"), float("inf")])
def test_mode_model_rejects_bad_numeric(bad):
    with pytest.raises(ValueError):
        bm.ModeModel(key="x", label="x", billing="standing", hourly_usd=bad,
                     per_invoke_usd=0.0, latency_overhead_ms=0.0,
                     ops_hours_per_month=0.0, owns_agent_loop=True)


def test_mode_model_rejects_bad_billing():
    with pytest.raises(ValueError):
        bm.ModeModel(key="x", label="x", billing="bogus", hourly_usd=1.0,
                     per_invoke_usd=0.0, latency_overhead_ms=0.0,
                     ops_hours_per_month=0.0, owns_agent_loop=True)


@pytest.mark.parametrize("bad", [-0.001, float("nan")])
def test_model_price_rejects_bad_numeric(bad):
    with pytest.raises(ValueError):
        bm.ModelPrice(input_per_1k=bad, output_per_1k=0.01)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
