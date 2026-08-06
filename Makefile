# sentinel-harness — one ergonomic entry point for the whole platform.
# =============================================================================
# Every target is a one-liner story. The heavy lifting lives in tested, reusable
# scripts (deploy/*.sh) and the package itself — this Makefile only wires them
# together so a newcomer can go from clone to deploy/seed/create/smoke without
# memorizing flags. Nothing here hardcodes an account or region: those come from
# the caller's active AWS profile / CDK environment.
#
# Safe-by-default: `test`, `lint`, `synth`, `seed-registry`, `create-harnesses`,
# `smoke`, `demo`, `clean` are all OFFLINE (no AWS). Only `deploy`,
# `deploy-endpoints`, `reset`, `destroy` touch AWS, each behind the existing
# human-confirmation prompt in deploy/deploy.sh / deploy/destroy.sh.
# =============================================================================

# Run every recipe in one bash shell with strict mode (fail fast, catch pipes).
SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

# The canonical offline test invocation (no /tmp venv; hermetic via uv).
PYTEST := uv run --no-project --python 3.13 --with pytest --with hypothesis --with boto3 --with pyyaml --with . python -m pytest

.DEFAULT_GOAL := help
.PHONY: help ci typecheck test lint synth deploy deploy-endpoints seed-registry create-harnesses \
        smoke reset destroy demo clean dist
# `dist` was added as a target a few rounds ago and NOT declared here. It went unnoticed
# because tests/test_makefile.py's KEY_TARGETS list had drifted to 13 of the 16 targets, so
# the PHONY check never covered it. Both are fixed together.

help: ## List available targets (default).
	@echo "sentinel-harness — make targets"
	@echo "==============================="
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| sort \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "OFFLINE (no AWS): ci test lint synth seed-registry create-harnesses smoke demo clean"
	@echo "TOUCHES AWS (confirm prompt): deploy deploy-endpoints reset destroy"

typecheck: ## Run both mypy gates exactly as CI does (lenient core + --strict security modules)
	# The security-module gate is STRICT on purpose: these files decide whether an
	# agent reaches production (loop_safety/autonomy/agent_loop) and what a
	# sandboxed agent may run (sandbox_hooks). Run this before touching them.
	uv run --no-project --python 3.12 --with mypy --with boto3 --with pyyaml --with . \
		mypy sentinel_harness/core.py sentinel_harness/factory.py \
		     sentinel_harness/loader.py sentinel_harness/registry.py \
		     sentinel_harness/registry_live.py
	uv run --no-project --python 3.12 --with mypy --with boto3 --with pyyaml --with . \
		mypy --strict --ignore-missing-imports --follow-imports=silent \
		     sentinel_harness/loop_safety.py sentinel_harness/autonomy.py \
		     sentinel_harness/agent_loop.py sentinel_harness/sandbox_hooks.py \
		     sentinel_harness/provenance.py sentinel_harness/feedback.py

ci: ## Run the core CI gates locally (lint · coverage>=88 · iac synth · secret-scan). NOTE: the mypy type-gate and the iac-cdk/test/*.test.ts stack tests run in CI only.
	# Mirrors the lint/test/synth/scan gates of .github/workflows/ci.yml. It does NOT
	# run two CI-only gates: the `mypy` job (`make typecheck` runs both halves of it
	# locally) and the `iac` job's `ts-node` stack-assertion tests
	# (iac-cdk/test/*.test.ts). A green `make ci` therefore does not guarantee green
	# CI on those two — run them if you touched typed core modules or the CDK stacks.
	# 1) Lint — REQUIRED, pinned to the same ruff CI + pre-commit run.
	uv run --no-project --python 3.13 --with ruff==0.15.20 ruff check .
	# 2) Coverage-gated tests (offline; branch coverage; fails under the 88 floor
	#    that .coveragerc and ci.yml share). pytest-randomly prints the seed.
	SENTINEL_REGION=us-east-1 AWS_DEFAULT_REGION=us-east-1 \
	SENTINEL_EXECUTION_ROLE_ARN=arn:aws:iam::000000000000:role/ci-test-role \
	AWS_ACCESS_KEY_ID=testing AWS_SECRET_ACCESS_KEY=testing \
	uv run --no-project --python 3.13 --with pytest --with pytest-randomly \
		--with coverage --with hypothesis --with boto3 --with pyyaml --with . \
		python -m coverage run -m pytest -q tests
	uv run --no-project --python 3.13 --with coverage python -m coverage report --fail-under=88
	# 3) IaC — tsc type-check + cdk synth. (The `iac` CI job ALSO runs the
	#    iac-cdk/test/*.test.ts stack tests via ts-node; those are CI-only here.)
	cd iac-cdk && npx tsc --noEmit && npx cdk synth >/dev/null
	# 4) Public-repo hygiene — the single shared secret/name scan (invoked via
	#    bash so it runs regardless of the script's executable bit).
	bash deploy/scan_secrets.sh
	@echo "make ci: all gates passed (lint · coverage>=88 · iac synth · secret-scan)."

test: ## Run the offline test suite (hermetic, no AWS).
	$(PYTEST) tests/ -q

lint: ## Static-check the Python with ruff.
	uv run --no-project --python 3.13 --with ruff ruff check .

synth: ## CDK synth the 9 Layer-3 stacks locally (offline, no deploy).
	cd iac-cdk && npx cdk synth

deploy: ## Deploy the FREE-TIER Layer-3 foundation (CDK; confirms account+region).
	deploy/deploy.sh

deploy-endpoints: ## Deploy the foundation PLUS the ~$$30/mo VPC interface endpoints.
	deploy/deploy.sh --with-endpoints

seed-registry: ## Print approved tools + run the offline dual-gate governance check.
	deploy/seed_registry.sh

create-harnesses: ## Validate/create the harness fleet (DRY_RUN=1 offline default; DRY_RUN=0 + creds to really create).
	deploy/create_harnesses.sh

smoke: ## Run the tests/smoke acceptance suite (offline; SENTINEL_SMOKE_LIVE=1 for live).
	deploy/smoke.sh

reset: destroy ## Alias for destroy — tear the foundation back down.

destroy: ## Tear down all 9 sentinel-* CDK stacks (confirms account+region).
	deploy/destroy.sh

demo: ## Run the narrated end-to-end platform tour (offline).
	uv run --no-project --python 3.13 --with boto3 --with pyyaml --with . python demo/platform_demo.py

clean: ## Remove local build/test caches (build/, cdk.out, .pytest_cache, __pycache__, ...).
	# `build/` MUST be here. setuptools stages the whole package tree into build/lib/ and
	# copies FROM it, never pruning entries whose source has been deleted — so a renamed or
	# removed module keeps shipping. Measured: after the whitelist_optimizer -> allowlist_optimizer
	# rename, a locally built wheel carried 21 handlers, including the DELETED
	# tools/whitelist_optimizer/. Installing it put dead code back on disk. `make clean` used to
	# leave build/ alone, so the stale copy survived every clean and every rebuild.
	rm -rf build/ dist/ iac-cdk/cdk.out .pytest_cache .ruff_cache htmlcov .coverage
	find . -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
	@echo "cleaned local caches (no source, no evidence removed)."

dist: clean ## Build a wheel + sdist from a CLEAN tree (never reuse a stale build/).
	# Depends on `clean` deliberately: building on top of an existing build/lib/ is exactly how
	# a deleted module ends up in the artifact. CI is safe by accident (fresh checkout); this
	# makes a local build match it on purpose.
	uv build
	@echo "built dist/ from a clean tree — verify with: uv run pytest tests/test_wheel_contents.py"
