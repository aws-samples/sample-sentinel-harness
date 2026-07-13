# Contributing

Thanks for your interest in `sentinel-harness`. This is a reference implementation
and educational sample for **authorized, defensive** security operations.

## Ground rules

1. **No proprietary or organization-specific data — ever.** This is a public repo.
   Use only generic SecOps content and public threat examples (ATT&CK, public CVEs).
   Company names, internal hostnames, real asset inventories, and the like do not
   belong here. CI enforces a name/secret scan and will fail the build.
2. **No hardcoded secrets or AWS account IDs.** Everything is env-parameterized
   (`SENTINEL_EXECUTION_ROLE_ARN`, `SENTINEL_REGION`, `AWS_PROFILE`). Use the
   `000000000000` placeholder in docs/examples.
3. **Defensive scope only.** Offensive/simulation scenarios must keep a
   human-in-the-loop gate on every action (Play Mode). No autonomous exploitation.
4. **English** for all code, comments, and docs.

## Development

This repo uses [`uv`](https://docs.astral.sh/uv/) and a `Makefile` — the same
toolchain as `docs/QUICKSTART.md`. The offline suite is hermetic (no venv to
manage, no AWS, no network); `uv` builds the environment on the fly.

```bash
export SENTINEL_EXECUTION_ROLE_ARN="arn:aws:iam::000000000000:role/test"  # for offline tests
make test                 # full offline suite (hermetic via uv; no AWS calls)
make lint                 # ruff over the Python sources
```

Run `make lint` and `make test` before opening a PR — that pair is the CI gate.

Under the hood `make test` runs the canonical hermetic invocation
(`uv run --no-project --python 3.13 --with pytest --with hypothesis --with boto3 --with pyyaml --with . python -m pytest tests/ -q`);
run it directly if you need to pass extra pytest flags. `hypothesis` is required —
`tests/test_prop_*.py` are property-based and fail collection without it. To hack
on the package in an editable environment, `uv sync` then `uv run pytest tests/ -q`.

Live scenarios require real AWS credentials for a **non-production** account and a
real execution role — see `docs/SETUP.md`.

## Style

- Match the existing `sentinel_harness/core.py` API and the `scenarios/` style.
- New scenarios go in `scenarios/`, write their evidence JSON to `evidence/`, and
  should be runnable end-to-end (create → invoke → verdict → leave cleanup to `sentinel cleanup`).
- Keep tool templates deterministic where the design calls for it (e.g. linters must
  not call an LLM).

## Reporting

Security issues: please open a private report rather than a public issue.
