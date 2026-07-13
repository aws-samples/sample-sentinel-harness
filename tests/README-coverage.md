# Measuring test coverage

The `tests/` suite is offline and hermetic (see `README.md`). This document
explains how to get an **honest, measurable** coverage number for it —
especially for the M3 surface (`tools/`, `longrunning/`, `specialists/`) — and
why the obvious `coverage --source=<dir>` invocation does **not** work here.

## TL;DR — run it

From the repo root, with the pinned test interpreter:

```bash
# 1. explicit invocation (no config file needed)
SENTINEL_EXECUTION_ROLE_ARN=arn:aws:iam::000000000000:role/test \
AWS_DEFAULT_REGION=us-east-1 \
AWS_ACCESS_KEY_ID=testing AWS_SECRET_ACCESS_KEY=testing \
/tmp/sentinel_test_venv/bin/python -m coverage run --branch \
    --include="*/tools/*,*/longrunning/*,*/specialists/*,*/sentinel_harness/*" \
    -m pytest tests/ -q

/tmp/sentinel_test_venv/bin/python -m coverage report -m
```

Because the repo now ships a `.coveragerc` (branch mode + the same `include`
globs + `show_missing`), the short form also Just Works — no long flags:

```bash
SENTINEL_EXECUTION_ROLE_ARN=arn:aws:iam::000000000000:role/test \
AWS_DEFAULT_REGION=us-east-1 \
AWS_ACCESS_KEY_ID=testing AWS_SECRET_ACCESS_KEY=testing \
/tmp/sentinel_test_venv/bin/python -m coverage run -m pytest tests/ -q
/tmp/sentinel_test_venv/bin/python -m coverage report
```

The dummy `SENTINEL_EXECUTION_ROLE_ARN` / region / AWS keys keep the run
hermetic (no real region, profile, or credential resolution). The role ARN
uses the all-zeros `000000000000` placeholder — no real account id.

## Why `--include` and NOT `--source`

The tool / specialist / long-running modules are **not** imported by package
name. They live in flat script trees — `tools/<name>/handler.py`,
`longrunning/bas-runner/bas_cases.py`, `longrunning/detonation/...`,
`specialists/<name>/agent_a2a.py` — and some directories cannot be packages at
all (`bas-runner` has a dash). The tests therefore load them with

```python
spec = importlib.util.spec_from_file_location("sigma_match_handler", path)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
```

under **unique fabricated module names** so path-loaded modules never collide
(two different `bedrock_entrypoint.py` files exist).

`coverage`'s `--source=<dir>` option enables **import-time interception** to
discover every module *by name* under that source tree. That interception
fights the path-loading pattern:

- It re-hooks the loader's `get_code`, which **breaks re-`exec_module`** of a
  file that is deliberately loaded a second time under a new name. Concretely,
  `tests/test_bas_cases.py::test_main_demo_block_runs_and_prints_report`
  re-executes `bas_cases.py` as `__main__` to cover its demo block; under
  `--source=longrunning` that test (and one sibling) **fails**, so the coverage
  run is no longer measuring a green suite.
- Modules that are only ever path-loaded can be mis-attributed or dropped,
  yielding a misleadingly low (sometimes `0%`) number that reflects coverage's
  own bookkeeping, not the tests.

`--include=<globs>` is a pure **post-hoc file-path filter**. It never touches
the import machinery; it simply keeps, in the report, only the recorded lines
whose file path matches a glob. The path-loaded modules are still recorded
against their real on-disk paths, so they are attributed correctly — and the
entire suite stays green (all tests pass under the `--include` run).

## Current M3 numbers

Ground truth from the `--include` run above over the full `tests/` suite
(591 passed, 3 skipped; branch coverage on). These are the M3-relevant modules:

| Module | Cover | Notable missing (branch) |
|---|--:|---|
| `tools/sigma_match/handler.py` | 65% | 137-212 (minimal-YAML fallback parser, only when PyYAML is absent); 234-242, 270, 354, 401, 445, 459, 463, 472, 495-497, 550-570 (matcher/condition edge branches) |
| `tools/asset_lookup/handler.py` | 90% | 192, 243, 275, 298, 311-313 (and it has no dedicated test file — only exercised via `test_attack_mapper.py`) |
| `longrunning/bas-runner/bas_cases.py` | 84% | 280-283, 298-300, 420-439 (tails) |
| `longrunning/detonation/bedrock_entrypoint.py` | 35% | 103-109, 150-167, 205-206, 238-287 (`@app.entrypoint` async generator `run_detonation` orchestration + event yields + error/restart branches) |
| `longrunning/detonation/src/vm.py` | 92% | 192, 234, 247, 255 |
| `specialists/attack-mapper/agent_a2a.py` | 80% | 469-474, 519-533 (`build_app` / `serve` wrappers behind guarded deps) |
| `specialists/threat-hunt/agent_a2a.py` | 81% | 479-484, 529-543 (same `serve` / `build_app` wrappers) |

Whole-repo `TOTAL` under these include globs: **77%**.

The larger gaps (`sigma_match` fallback parser, `bedrock_entrypoint` async
main flow) are the biggest measurable M3 targets; the `build_app`/`serve`
wrapper gaps sit behind optional heavy deps (`strands` / `bedrock_agentcore` /
`a2a`) that CI guards with `importorskip`.

## Guard: the coverage smoke test

`tests/test_coverage_smoke.py` is a fast, fully-offline meta-test. It asserts
that the key M3 modules **import** (loaded by unique path names, zero AWS) and
that their primary public entrypoints are callable:
`sigma_match.handler`, `asset_lookup.handler`,
`bas_cases.generate_cases` / `bas_cases.replay`, and the detonation
`OneShotMicroVM`. It is a tripwire that the M3 surface stays importable — if a
refactor breaks one of these entrypoints, this test fails immediately rather
than the coverage number silently dropping.
