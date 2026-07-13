# whitelist_optimizer — deterministic offline FP-to-whitelist synthesizer

`whitelist_optimizer` is the engine that closes the **M6 feedback loop**:
when alert triage dispositions an alert as a **false positive**, this tool
turns that cohort of FP events into a concrete Sigma-style
suppression/whitelist clause, so a noisy detection rule stops firing on
known-good traffic — **without going blind** to the real threats it was
built to catch.

> Given a noisy `rule_name` and a set of confirmed false-positive events,
> what is the *safe* whitelist clause that suppresses them?

## What it does

1. **Extracts the common discriminator.** It scans candidate fields in a
   fixed priority order (benign-identifying first: `dst_domain` and other
   domains, `process_name`/`image`/`sha256`, then network locality
   `src_ip`/`dst_ip`, then weaker context) and finds the first field that is
   present in **every** FP event and shares a **safe common value**:
   - **domains** → exact domain, or a shared parent suffix of ≥ 2 labels
     (never a bare TLD like `.com`);
   - **IPs** → the identical IP (exact) or the *minimal* covering CIDR, but
     only if it is no broader than `/24` (v4) / `/48` (v6);
   - **other fields** → exact match only when every value is identical
     (case-insensitive).
2. **Synthesizes a Sigma `filter`** selection plus a merged
   `condition: <base> and not filter_known_good` snippet.
3. **Refuses to overfit.** If the FPs share no safe common field, it returns
   a `no_safe_whitelist` verdict instead of fabricating a clause.
4. **Protects true positives.** It never emits a whitelist that would also
   suppress a provided true-positive example (`tp_examples`) or an
   in-line `disposition: true_positive` event in a mixed set.

## Provable core (real vs stub)

The synthesis is **real deterministic offline logic** — same input always
yields the same whitelist, no LLM, no tokens, no network. It is labelled
`source: "stub"` because it performs no model reasoning: the downstream
**rule-regeneration RUN** that consumes this clause reuses the M1/M2
self-improving loop, driven in-process/offline for the POC. Nothing here is
"live".

## Contract

```python
handler(event, context)
# event = {
#     "rule_name":     "<noisy rule name>",        # REQUIRED
#     "fp_events":     [ {..alert/event dict..} ],  # REQUIRED, non-empty
#     "existing_rule": "<sigma yaml>" | {parsed},   # OPTIONAL, merges condition
#     "tp_examples":   [ {..alert dict..} ],        # OPTIONAL, protect these
# }
```

Safe whitelist found:

```json
{
  "ok": true,
  "source": "stub",
  "rule_name": "Malware Beacon to C2 Domain",
  "whitelist": {"fields": {"dst_domain": "assets.example.com"}, "match_type": "domain_suffix"},
  "suppressed_count": 2,
  "sigma_filter_yaml": "detection:\n    filter_known_good:\n        dst_domain|endswith: 'assets.example.com'\n    condition: selection and not filter_known_good\n",
  "rationale": "All 2 false-positive event(s) ... share dst_domain='assets.example.com' ..."
}
```

No safe whitelist (shares nothing, or every shared field hits a TP):

```json
{
  "ok": true,
  "source": "stub",
  "rule_name": "Grab Bag Rule",
  "whitelist": null,
  "verdict": "no_safe_whitelist",
  "suppressed_count": 0,
  "rationale": "... share no common discriminating field. Refusing to synthesize ..."
}
```

Bad input:

```json
{"ok": false, "error": "validation_error", "message": "..."}
```

Validation: a missing/empty `rule_name` or a missing/empty `fp_events` list
is a `validation_error`, as is a non-dict event / fp_event / tp_example or a
bad `existing_rule` type.

## `match_type` values

| `match_type`     | Meaning                                                       |
|------------------|---------------------------------------------------------------|
| `exact`          | field value identical across FPs (case-insensitive)           |
| `domain_exact`   | all FPs share the identical domain                            |
| `domain_suffix`  | FPs share a parent domain of ≥ 2 labels; emits `field|endswith`|
| `cidr`           | FPs fall inside one minimal, tight CIDR; emits `field|cidr`    |

## Over-suppression guards

- No FP-common field → **no whitelist** (never overfit the exact events).
- Domain suffix must be ≥ 2 labels → **never** whitelist a whole TLD.
- CIDR must be ≤ `/24` (v4) / `/48` (v6) → **never** whitelist a huge block.
- The emitted clause must not match any `tp_examples` or in-line
  `true_positive` event → **never** blind the rule to a real detection.

## Egress & secrets

Zero egress, zero secrets, zero tokens. `SENTINEL_EXECUTION_ROLE_ARN`,
`SENTINEL_REGION` and `AWS_PROFILE` are honored for harness consistency but
are **not required** to run this tool.

## YAML parsing reuse

An optional `existing_rule` YAML string is parsed by reusing
`tools/sigma_yara_lint/handler.py::_parse_yaml` (PyYAML with a dependency-free
minimal fallback), imported by path; if the sibling is unavailable it degrades
to a small regex extractor for the `condition:` line, so the tool stays
self-contained and fully offline.

## Registry (shared change — not edited by this tool)

To make this tool live, SecOps adds it to `registry/tools.yaml`:

```yaml
  - name: whitelist_optimizer
    owner: detection-engineering
    status: approved
    description: >-
      Deterministic, LLM-free FP-to-whitelist synthesizer for the M6 feedback
      loop: turns a cohort of false-positive events into a safe Sigma-style
      suppression clause (domain / process / CIDR discriminator) with a
      condition: selection and not filter snippet. Refuses to overfit or to
      suppress a provided true-positive. Makes no network calls.
```

and lists it in the governance assertions of `tests/test_registry.py`
(`load_registry` factory map + `list_live` / `approved_missing_impl` sets).

## Run the demo / tests

```bash
python tools/whitelist_optimizer/handler.py
SENTINEL_EXECUTION_ROLE_ARN=arn:aws:iam::000000000000:role/test \
AWS_DEFAULT_REGION=us-east-1 \
  uv run --no-project --python 3.13 --with pytest --with boto3 --with pyyaml --with . \
  python -m pytest tests/test_whitelist_optimizer.py -q
```
