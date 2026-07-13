#!/usr/bin/env bash
#
# create_harnesses.sh — provision the shipped harness fleet from harnesses/*/harness.yaml.
# ==============================================================================
# WHY this script exists:
#   Each harnesses/<name>/harness.yaml is a declarative SecOps agent (model, system
#   prompt, tools, memory, HITL gates). Turning the whole directory into live
#   AgentCore harnesses by hand — one `sentinel create` per file, in the right
#   order, without touching the wrong account — is exactly the toil this wrapper
#   removes. It makes the SAFE path (offline validation) the default and the
#   real, credential-touching create an explicit opt-in.
#
# SAFE-BY-DEFAULT (DRY_RUN=1, the default):
#   Loops every harnesses/*/harness.yaml through factory.provision_fleet(dry_run=True)
#   — a pure OFFLINE resolve+validate (loader parses the YAML, expands ${ENV},
#   injects inline HITL gates, validates the harnessName) with ZERO AWS calls.
#   This is what `make create-harnesses` runs, so it is always safe to invoke.
#
# REAL CREATE (DRY_RUN=0):
#   Requires resolvable AWS credentials + a NON-PROD account. Calls the real
#   factory.provision_fleet() which is idempotent (create-or-skip) and env-tag
#   guarded. Deploy the Layer-3 foundation first (deploy/deploy.sh) so the gateway
#   ARN the configs reference exists.
#
# ENVIRONMENT:
#   DRY_RUN                     1 (default, offline validate) | 0 (real create)
#   SENTINEL_GATEWAY_ARN        gateway ARN the configs reference (${...} in yaml).
#                               A placeholder is stamped for dry-run so validation
#                               never needs a real value; MUST be real for DRY_RUN=0.
#   SENTINEL_ENV                fleet env tag (default: dev). Never 'prod' here.
#
# USAGE:
#   deploy/create_harnesses.sh              # offline validate the whole fleet (default)
#   DRY_RUN=0 deploy/create_harnesses.sh    # really create (needs creds + non-prod acct)
#   deploy/create_harnesses.sh --help
#
# Exit codes: 0 success · 1 validation / prereq error.
#
set -euo pipefail

# --- Resolve paths independent of the caller's CWD. --------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
HARNESS_GLOB="${REPO_ROOT}/harnesses"

DRY_RUN="${DRY_RUN:-1}"
SENTINEL_ENV="${SENTINEL_ENV:-dev}"

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  sed -n '2,41p' "${BASH_SOURCE[0]}"
  exit 0
fi

if command -v uv >/dev/null 2>&1; then
  PY=(uv run --no-project --python 3.13 --with pyyaml --with boto3 --with . python)
else
  PY=(python3)
fi

# For offline validation the configs still reference ${SENTINEL_GATEWAY_ARN}; the
# loader errors on an unset ${VAR}. Stamp a scrubbed placeholder (account 000...)
# for dry-run so validation is self-contained. A real DRY_RUN=0 run MUST provide
# the real ARN — we do NOT overwrite a value the caller already exported.
if [[ "${DRY_RUN}" != "0" ]]; then
  export SENTINEL_GATEWAY_ARN="${SENTINEL_GATEWAY_ARN:-arn:aws:bedrock-agentcore:us-east-1:000000000000:gateway/dry-run-placeholder}"
  export SENTINEL_REGION="${SENTINEL_REGION:-us-east-1}"
  export AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-us-east-1}"
  export SENTINEL_EXECUTION_ROLE_ARN="${SENTINEL_EXECUTION_ROLE_ARN:-arn:aws:iam::000000000000:role/dry-run-placeholder}"
fi

echo "== sentinel-harness · create harnesses (DRY_RUN=${DRY_RUN}, env=${SENTINEL_ENV}) =="
if [[ "${DRY_RUN}" == "0" ]]; then
  echo "MODE: REAL CREATE — this will call AWS AgentCore against your active profile."
  if [[ -z "${SENTINEL_GATEWAY_ARN:-}" ]]; then
    echo "ERROR: DRY_RUN=0 needs a real SENTINEL_GATEWAY_ARN (deploy the foundation first)." >&2
    exit 1
  fi
else
  echo "MODE: OFFLINE VALIDATE — resolve + validate every config, ZERO AWS calls."
fi

cd "${REPO_ROOT}"
SENTINEL_ENV="${SENTINEL_ENV}" DRY_RUN="${DRY_RUN}" HARNESS_GLOB="${HARNESS_GLOB}" "${PY[@]}" - <<'PY'
import glob
import os
import sys

from sentinel_harness import factory

dry_run = os.environ.get("DRY_RUN", "1") != "0"
root = os.environ["HARNESS_GLOB"]
configs = sorted(glob.glob(os.path.join(root, "*", "harness.yaml")))
if not configs:
    print(f"no harness.yaml under {root}", file=sys.stderr)
    sys.exit(1)

manifest = {
    "tags": {"team": "secops", "sentinel:env": os.environ.get("SENTINEL_ENV", "dev")},
    "harnesses": [{"config": p} for p in configs],
}

print(f"\n{len(configs)} harness config(s):")
for p in configs:
    print(f"  - {os.path.relpath(p, root)}")

results = factory.provision_fleet(manifest, dry_run=dry_run)
print("\nresult:")
for r in results:
    hid = f"  id={r['harnessId']}" if r.get("harnessId") else ""
    print(f"  {r['name']:<28} {r['action']}{hid}")
PY

echo ""
if [[ "${DRY_RUN}" == "0" ]]; then
  echo "fleet create complete (idempotent, env-tag guarded)."
else
  echo "fleet validated offline. Re-run with DRY_RUN=0 (+ creds) to really create."
fi
