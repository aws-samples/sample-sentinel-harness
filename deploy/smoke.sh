#!/usr/bin/env bash
#
# smoke.sh — run the tests/smoke acceptance suite (offline by default).
# ==============================================================================
# WHY this script exists:
#   tests/smoke/ freezes the one-time live milestone proofs into re-runnable
#   checks. By DEFAULT the suite is 100% OFFLINE (it reads account-scrubbed
#   evidence JSONs, synthesizes the CDK app locally, and runs pure-Python
#   replays) — so `make smoke` is a fast, hermetic "is the platform still
#   internally consistent?" gate needing no AWS. The LIVE re-verification
#   (actually calling AWS again) is opt-in only.
#
# WHAT it does:
#   Runs `pytest tests/smoke -q` via uv. With SENTINEL_SMOKE_LIVE=1 it also opts
#   into the live checks (which themselves SKIP unless AWS creds resolve — they
#   never fail-by-default and never fabricate liveness).
#
# ENVIRONMENT:
#   SENTINEL_SMOKE_LIVE    unset/0 = offline only (default) · 1 = also live checks
#
# USAGE:
#   deploy/smoke.sh                      # offline smoke suite (default)
#   SENTINEL_SMOKE_LIVE=1 deploy/smoke.sh  # also run opt-in live checks
#   deploy/smoke.sh --help
#
# Exit codes: propagates pytest's exit code (0 = all passed / skipped).
#
set -euo pipefail

# --- Resolve paths independent of the caller's CWD. --------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  sed -n '2,29p' "${BASH_SOURCE[0]}"
  exit 0
fi

if command -v uv >/dev/null 2>&1; then
  PY=(uv run --no-project --python 3.13 --with pytest --with boto3 --with pyyaml --with . python -m pytest)
else
  PY=(python3 -m pytest)
fi

LIVE="${SENTINEL_SMOKE_LIVE:-0}"
echo "== sentinel-harness · smoke suite (SENTINEL_SMOKE_LIVE=${LIVE}) =="
if [[ "${LIVE}" == "1" ]]; then
  echo "MODE: LIVE-OPT-IN — live checks run if AWS creds resolve, else SKIP."
else
  echo "MODE: OFFLINE — ZERO AWS / network calls."
fi

cd "${REPO_ROOT}"
SENTINEL_SMOKE_LIVE="${LIVE}" "${PY[@]}" tests/smoke -q "$@"
