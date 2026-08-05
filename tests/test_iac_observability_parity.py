"""INV-IAC-4 — the Terraform mirror produces the metrics its alarms consume.

README calls `iac-terraform/` a **mirror** of `iac-cdk/` for identity/vpc/guardrail/obs/harness.
For observability that claim was false in a way neither `terraform validate` nor `cdk synth`
could see:

    iac-cdk/lib/observability-stack.ts   3 MetricFilters + 2 Alarms
    iac-terraform/observability.tf       0 metric filters + 1 Alarm

The Terraform alarm watches `SentinelHarness/TokensPerScenario`, and nothing in that tree
produced it — no `aws_cloudwatch_log_metric_filter`, no `put_metric`, no EMF. The metric had
**zero producers**, so the alarm would sit in `INSUFFICIENT_DATA` forever; and because it is
declared `treat_missing_data = "notBreaching"`, it would never fire and never look broken
either. An operator who deployed this Terraform believing the mirror claim had a token-overrun
alarm that could not fire.

Same shape as INV-METRIC-1, where `core.metered_invoke` wrote its metric through a text logger
so `FilterPattern.exists("$.tokens")` never matched and no alarm ever fired. There the producer
emitted the wrong format; here the producer did not exist. Both are silent.

`terraform validate` passes both before and after the fix — it checks syntax and provider
schema, not whether a referenced metric has a source. That is exactly why this parity check has
to exist as a test.

What this does NOT assert
-------------------------
Not resource-for-resource equality. Terraform mirrors five domains and README says so; CDK also
ships gateway/registry/memory/runtime stacks with no Terraform counterpart, which is a stated
scope decision, not drift. The assertion is narrower and sharper: **every custom metric an alarm
or dashboard consumes must have a producer in the same tree**, and the metric names must match
the CDK constants so the two deployments observe the same thing.

ZERO network, ZERO AWS: reads two source trees.
"""
from __future__ import annotations

import os
import re

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CDK_OBS = os.path.join(REPO_ROOT, "iac-cdk", "lib", "observability-stack.ts")
TF_DIR = os.path.join(REPO_ROOT, "iac-terraform")


def _strip_ts_comments(source: str) -> str:
    source = re.sub(r"/\*.*?\*/", "", source, flags=re.S)
    return "\n".join(
        line for line in source.splitlines() if not line.strip().startswith("//")
    )


def _strip_hcl_comments(source: str) -> str:
    return "\n".join(
        line for line in source.splitlines() if not line.strip().startswith("#")
    )


def _cdk_source() -> str:
    with open(CDK_OBS, encoding="utf-8") as fh:
        return _strip_ts_comments(fh.read())


def _tf_source() -> str:
    """All Terraform observability sources, comments stripped.

    Comment stripping is load-bearing: both trees carry long comments naming the metrics, so a
    naive scan would find `TokensPerScenario` in prose and conclude a producer exists. That is
    substring matching standing in for structure — the defect class this repo records most.
    """
    parts = []
    for name in sorted(os.listdir(TF_DIR)):
        if not name.endswith(".tf"):
            continue
        with open(os.path.join(TF_DIR, name), encoding="utf-8") as fh:
            parts.append(_strip_hcl_comments(fh.read()))
    return "\n".join(parts)


def _cdk_metric_constants() -> dict:
    """`METRIC_NAMESPACE` / `*_METRIC_NAME` exported by the CDK stack."""
    source = _cdk_source()
    found = dict(re.findall(r'export const ([A-Z_]+)\s*=\s*"([^"]+)"', source))
    return {k: v for k, v in found.items()
            if k == "METRIC_NAMESPACE" or k.endswith("_METRIC_NAME")}


def _tf_metric_locals() -> dict:
    """`locals` entries naming a metric or the namespace, on the Terraform side."""
    source = _tf_source()
    # ALL locals blocks, not the first. There are three (guardrail / observability / vpc), and my
    # first version used `re.search` — it matched guardrail.tf's block, found no metric names, and
    # returned {} while the positive control below failed. A single-instance assumption about a
    # construct that appears several times: the scan reported "nothing here" for a tree that has
    # exactly what it was looking for, two files further down.
    found: dict = {}
    for block in re.findall(r"locals\s*\{(.*?)\n\}", source, re.S):
        for key, value in re.findall(r'([a-z_]+)\s*=\s*"([^"]+)"', block):
            if "metric" in key or "namespace" in key:
                found[key] = value
    return found


def _tf_filter_bodies() -> list:
    """Bodies of each `aws_cloudwatch_log_metric_filter` block, comments stripped."""
    return re.findall(
        r'resource\s+"aws_cloudwatch_log_metric_filter"\s+"[a-z_]+"\s*\{(.*?)\n\}',
        _tf_source(), re.S,
    )


def test_the_scan_sees_both_trees():
    """Positive control. Every assertion below compares two derived sets; if either came back
    empty they would hold vacuously and this module would be decoration."""
    assert os.path.isfile(CDK_OBS), f"{CDK_OBS} is missing"
    constants = _cdk_metric_constants()
    assert len(constants) >= 4, (
        f"parsed only {len(constants)} metric constants from the CDK stack: {constants}. The "
        "export shape changed and this comparison is now blind."
    )
    locals_ = _tf_metric_locals()
    assert len(locals_) >= 4, (
        f"parsed only {len(locals_)} metric locals from Terraform: {locals_}."
    )


def test_terraform_defines_a_producer_for_every_metric_it_alarms_on():
    """The defect. An alarm on a metric with no producer can never fire.

    Worse than a missing alarm, because the console shows INSUFFICIENT_DATA — and with
    `treat_missing_data = "notBreaching"` it shows OK. "We are monitoring this" and "this can
    never fire" look identical.
    """
    source = _tf_source()

    alarmed = set(re.findall(r"metric_name\s*=\s*local\.([a-z_]+)", source))
    assert alarmed, (
        "no `metric_name = local.<x>` alarm reference found in iac-terraform/. Either the alarms "
        "were removed or this parser is blind — both must fail loudly."
    )

    # Producers: log metric filters, keyed by the local they populate.
    produced = set(re.findall(
        r"metric_transformation\s*\{[^}]*?name\s*=\s*local\.([a-z_]+)", source, re.S
    ))

    missing = sorted(alarmed - produced)
    assert not missing, (
        f"iac-terraform alarms on metric(s) {missing} that NOTHING in that tree produces. "
        f"Producers found: {sorted(produced)}.\n\n"
        "The alarm would sit in INSUFFICIENT_DATA forever, and with "
        '`treat_missing_data = "notBreaching"` it would never fire and never look broken. '
        "Add an `aws_cloudwatch_log_metric_filter` with a matching "
        "`metric_transformation { name = local.<x> }`, mirroring "
        "iac-cdk/lib/observability-stack.ts. `terraform validate` cannot catch this."
    )


def test_the_dashboard_only_charts_metrics_that_exist():
    """Same rule for the dashboard: a widget on an unproduced metric renders an empty graph,
    which reads as "quiet system" rather than "no data source"."""
    source = _tf_source()
    charted = set(re.findall(r"\[\s*local\.metrics_namespace\s*,\s*local\.([a-z_]+)", source))
    if not charted:
        pytest.skip("the dashboard charts no local-referenced metric")
    produced = set(re.findall(
        r"metric_transformation\s*\{[^}]*?name\s*=\s*local\.([a-z_]+)", source, re.S
    ))
    missing = sorted(charted - produced)
    assert not missing, (
        f"the Terraform dashboard charts metric(s) {missing} with no producer in that tree — an "
        f"empty graph looks like a quiet system. Producers: {sorted(produced)}."
    )


def test_both_trees_agree_on_the_metric_namespace_and_names():
    """Names must MATCH, not merely exist on both sides.

    Two deployments emitting `SentinelHarness/TokensPerScenario` and
    `Sentinel/TokensPerScenario` would each look internally consistent while observing different
    things — and a runbook written against one would silently not apply to the other.
    """
    cdk = _cdk_metric_constants()
    tf = _tf_metric_locals()

    assert tf.get("metrics_namespace") == cdk.get("METRIC_NAMESPACE"), (
        f"namespace mismatch: CDK {cdk.get('METRIC_NAMESPACE')!r} vs Terraform "
        f"{tf.get('metrics_namespace')!r}"
    )

    cdk_values = {v for k, v in cdk.items() if k.endswith("_METRIC_NAME")}
    tf_values = {v for k, v in tf.items() if k.endswith("_metric")}
    only_cdk = sorted(cdk_values - tf_values)
    assert not only_cdk, (
        f"metric(s) {only_cdk} are defined in the CDK stack but named nowhere in "
        f"iac-terraform/. The Terraform deployment would not observe them, so the README "
        f"'mirror' claim would be false for those signals. Terraform names: {sorted(tf_values)}"
    )
    only_tf = sorted(tf_values - cdk_values)
    assert not only_tf, (
        f"metric(s) {only_tf} exist only in Terraform. A signal on one side and not the other "
        "means a runbook written against the CDK deployment does not apply to this one."
    )


def test_every_cdk_metric_filter_has_a_terraform_counterpart():
    """Filter-for-filter parity, by the JSON field each selects.

    Checked by SELECTOR (`$.tokens`) rather than by count, because counting says nothing about
    which signal is missing — and a count that happens to match while the fields differ is the
    worst outcome: parity asserted, parity absent.
    """
    cdk = _cdk_source()
    cdk_fields = set(re.findall(r'FilterPattern\.exists\("\$\.([a-z_]+)"\)', cdk))
    assert cdk_fields, (
        "no `FilterPattern.exists(\"$.<field>\")` found in the CDK stack — either the metric "
        "filters were removed or this parser is blind."
    )

    # Per-FILTER, and the pattern field must equal the value field. Taking the UNION of
    # `pattern =` fields and `value =` fields let a mutation survive: renaming only the pattern
    # to `$.bogus` still left `value = "$.tokens"` in the union, so the set comparison passed.
    #
    # That union was not merely a weak test — it hid a REAL failure mode. In CloudWatch the
    # pattern selects which log lines match and the value says which field to extract, so a
    # filter matching `$.bogus` while extracting `$.tokens` emits no data points at all: exactly
    # as silent as having no filter. The right question is per-filter agreement, which is what a
    # union can never ask.
    tf_fields = set()
    for body in _tf_filter_bodies():
        pattern_fields = re.findall(r'pattern\s*=\s*"\{\s*\$\.([a-z_]+)\s*=', body)
        value_fields = re.findall(r'value\s*=\s*"\$\.([a-z_]+)"', body)
        assert pattern_fields and value_fields, (
            f"a metric filter has no parseable pattern/value field:\n{body[:300]}"
        )
        assert set(pattern_fields) == set(value_fields), (
            f"a metric filter selects log lines on {pattern_fields} but extracts "
            f"{value_fields}. CloudWatch would match those lines and find no such field, "
            f"emitting NO data points — as silent as having no filter at all:\n{body[:300]}"
        )
        tf_fields.update(pattern_fields)

    missing = sorted(cdk_fields - tf_fields)
    assert not missing, (
        f"the CDK stack extracts log field(s) {missing} into metrics; Terraform extracts "
        f"{sorted(tf_fields)}. The Terraform deployment is blind to those signals.\n"
        "Mirror them with `aws_cloudwatch_log_metric_filter` blocks."
    )


def test_the_terraform_filters_read_the_log_group_that_stack_creates():
    """A filter attached to the wrong log group produces nothing, and looks configured.

    The CDK filters bind to `this.scenarioLogGroup`. Terraform's must bind to the log group
    resource in the same tree — a hardcoded or variable name could point at a group nothing
    writes to, which fails exactly as silently as having no filter at all.
    """
    source = _tf_source()
    filters = re.findall(
        r'resource\s+"aws_cloudwatch_log_metric_filter"\s+"[a-z_]+"\s*\{(.*?)\n\}',
        source, re.S,
    )
    assert filters, "iac-terraform defines no aws_cloudwatch_log_metric_filter"
    for body in filters:
        assert re.search(r"log_group_name\s*=\s*aws_cloudwatch_log_group\.", body), (
            "a metric filter's `log_group_name` does not reference an "
            "`aws_cloudwatch_log_group` resource in this tree. A filter on a group nothing "
            f"writes to produces no data and looks configured:\n{body[:300]}"
        )
