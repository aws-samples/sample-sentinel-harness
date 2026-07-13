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
.PHONY: help ci test lint synth deploy deploy-endpoints seed-registry create-harnesses \
        smoke reset destroy demo clean

help: ## List available targets (default).
	@echo "sentinel-harness — make targets"
	@echo "==============================="
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| sort \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "OFFLINE (no AWS): ci test lint synth seed-registry create-harnesses smoke demo clean"
	@echo "TOUCHES AWS (confirm prompt): deploy deploy-endpoints reset destroy"

ci: ## Run the FULL CI gate locally, mirroring .github/workflows/ci.yml exactly.
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
	# 3) IaC — tsc type-check + cdk synth (same as the `iac` CI job).
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

clean: ## Remove local build/test caches (cdk.out, .pytest_cache, __pycache__, ...).
	rm -rf iac-cdk/cdk.out .pytest_cache .ruff_cache htmlcov .coverage
	find . -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
	@echo "cleaned local caches (no source, no evidence removed)."
