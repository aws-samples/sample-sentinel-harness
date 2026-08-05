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
(3858 passed, 9 skipped; branch coverage on).

Three of those nine skips are `test_coverage_doc.py` itself, and the reason is structural
rather than incidental: `coverage run -m pytest tests` writes `.coverage` only when it
**exits**, so during the run there is no data file for those assertions to read. For a long
time that meant the guard keeping this very table honest **never ran in CI** — it executed
only on maintainer laptops, where `make ci` had already produced the file. CI now runs the
module as a dedicated step *after* `coverage report`, with
`SENTINEL_REQUIRE_COVERAGE_DATA=1`, under which absent data raises instead of skipping. Under
a plain `pytest tests` (no coverage wrapper) the count is 3858 passed / 6 skipped, because
`.coverage` from a previous `make ci` is present. See INV-DOC-5.

> These numbers are **checked, not asserted**.
> `tests/test_coverage_doc.py` re-measures every row against a fresh coverage run and
> fails the build when one drifts more than 5 points. The table below was a hand-written
> M3-era snapshot for a long time — taken when the suite had 591 tests — and by the time a
> sweep re-measured it, **five of its seven rows were wrong by 16 to 61 points, every one
> of them UNDERSTATING the real coverage.** A document that makes the project look worse
> than it is misdirects effort exactly as much as one that flatters it, and nothing was
> checking this one.

| Module | Cover | Notable missing (branch) |
|---|--:|---|
| `tools/sigma_match/handler.py` | 98% | 140, 143, 890-910 (fallback-parser tails; the minimal-YAML path is now covered) |
| `tools/asset_lookup/handler.py` | 90% | 350, 386, 389, 407, 438, 450-452, 506, 516-520 (live-path error branches) |
| `longrunning/bas-runner/bas_cases.py` | 100% | — |
| `longrunning/bas-runner/bedrock_entrypoint.py` | 100% | — (was **19%**, the lowest file in the repo) |
| `longrunning/detonation/bedrock_entrypoint.py` | 96% | 61 |
| `longrunning/detonation/src/vm.py` | 93% | 281, 327, 340, 348 |
| `specialists/attack-mapper/agent_a2a.py` | 100% | — |
| `specialists/threat-hunt/agent_a2a.py` | 100% | — |
| `specialists/cve-intel/agent_a2a.py` | 100% | — (was **60%**; see the note below) |

Whole-repo `TOTAL` under these include globs: **92%**.

That total is measured with `site-packages` **omitted**. Until a sweep caught it, the
`*/tools/*` include glob also matched `site-packages/mcp/server/fastmcp/tools/` — 96
statements of a third-party library, 46 uncovered — which dragged the reported figure from
91.19% down to 90.75% and made the 88 floor looser than it looked, because the denominator
carried code this repo neither owns nor should test.

The `bas-runner/bedrock_entrypoint.py` gap is closed — round 7 of the sweeps found it was
never hard to test, only untested: `tests/test_bas_runner.py` imported the module and
asserted `callable(build_loop)` without ever calling it. 27 tests later it is at 100%,
and 5/5 mutations of its security logic are caught (INV-PLAY-3 checkpoint substitution,
the session-cap restart path, and the two deliberately-swallowed exceptions).

All four specialists now sit at 100%, and how they got there is worth recording. Round 8
compared them and found `cve-intel` at 60% while its three structurally identical siblings
were at 100%. The gap was **not** difficulty: `tests/test_attack_mapper.py` reaches the
lazily-imported `strands` / `mcp` / `fastapi` paths by injecting stub module trees with
`monkeypatch.setitem(sys.modules, ...)`, and that technique had simply never been carried to
`cve-intel`'s tests. "A fix applied to one call site is not an invariant" — this time the
thing applied to one call site was a TESTING TECHNIQUE.

The same comparison caught `adversarial-reviewer` at 96.5%: three unreached branches in
`_artifact_to_text` / `_condition_line` (a list nested in a list, a bare scalar artifact, and
the no-condition fallback), all trivially reachable.

Both sets are mutation-tested. One of the six mutations initially SURVIVED — dropping nested
lists from the artifact text — because the new assertion checked `"a" in text`, which still
holds when the list renders as Python's repr `- ['a', 'b']`. Substring standing in for
structure, the error this repo has recorded more than any other. The assertion now checks the
line structure and indentation and rejects a leaked repr; the mutation is caught.

## Guard: the coverage smoke test

`tests/test_coverage_smoke.py` is a fast, fully-offline meta-test. It asserts
that the key M3 modules **import** (loaded by unique path names, zero AWS) and
that their primary public entrypoints are callable:
`sigma_match.handler`, `asset_lookup.handler`,
`bas_cases.generate_cases` / `bas_cases.replay`, and the detonation
`OneShotMicroVM`. It is a tripwire that the M3 surface stays importable — if a
refactor breaks one of these entrypoints, this test fails immediately rather
than the coverage number silently dropping.
