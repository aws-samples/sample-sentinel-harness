#!/usr/bin/env bash
#
# destroy.sh — tear down the sentinel-harness Layer-3 foundation stacks (CDK).
# ==============================================================================
# WHY this script exists:
#   Demo/sandbox infrastructure should be trivially reversible so it never becomes
#   forgotten standing cost. This wrapper destroys every sentinel-* CDK stack in
#   one command, after a human confirmation that names the exact account + region.
#
# WHAT it removes:
#   All eight sentinel-* CDK stacks (guardrail, identity, observability, network,
#   gateway, registry, memory, harness). It uses `cdk destroy --force --all`,
#   which CDK scopes to the stacks defined by THIS app (all named sentinel-*) —
#   it does not enumerate or touch unrelated stacks in the account.
#
#   It does NOT delete the CDKToolkit bootstrap stack (the CDK staging bucket /
#   ECR repo / roles). That is shared bootstrap you may want for future deploys;
#   remove it yourself with `aws cloudformation delete-stack --stack-name CDKToolkit`
#   only if you are done with CDK in this account entirely.
#
# SAFETY:
#   * Requires an interactive human "yes" after printing account + region.
#   * `--force` skips CDK's own per-stack "are you sure" — which is why we gate on
#     our own confirmation first (consent is asked exactly once, up front).
#   * Idempotent: destroying an already-absent stack is a CDK no-op.
#
# USAGE:
#   deploy/destroy.sh          # confirm, then destroy all sentinel-* stacks
#   deploy/destroy.sh --yes    # skip the prompt (CI). Account + region still printed.
#   deploy/destroy.sh --help
#
# Exit codes: 0 success · 1 prereq/usage error · 130 user aborted at the prompt.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IAC_DIR="$(cd "${SCRIPT_DIR}/../iac-cdk" && pwd)"

# Every stack this app owns — all sentinel-* names, matching bin/sentinel.ts.
# The CDKToolkit bootstrap stack is deliberately absent from this list.
SENTINEL_STACKS=(
  "sentinel-gateway"
  "sentinel-registry"
  "sentinel-memory"
  "sentinel-network"
  "sentinel-identity"
  "sentinel-guardrail"
  "sentinel-observability"
  "sentinel-harness"
)

ASSUME_YES=false

usage() {
  cat <<'EOF'
Usage: deploy/destroy.sh [--yes] [--help]

  (no flags)   Confirm, then destroy ALL sentinel-* CDK stacks.
  --yes        Do not prompt for confirmation (for CI). Account + region printed.
  --help       Show this help and exit.

Destroys only sentinel-* stacks. Does NOT touch the CDKToolkit bootstrap stack.
Account and region come from your ACTIVE AWS profile — never hardcoded.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --yes|-y)  ASSUME_YES=true; shift ;;
    --help|-h) usage; exit 0 ;;
    *) echo "error: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

require_cmd() {
  local cmd="$1" hint="$2"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "error: required command '$cmd' not found on PATH. $hint" >&2
    exit 1
  fi
}

echo "== sentinel-harness · L3 foundation destroy =="
echo "-- checking prerequisites --"
require_cmd node "Install Node 18+ (https://nodejs.org)."
require_cmd npx  "npx ships with Node/npm — reinstall Node if it is missing."
require_cmd aws  "Install the AWS CLI v2 (https://aws.amazon.com/cli/)."

if [[ ! -d "${IAC_DIR}/node_modules" ]]; then
  echo "error: ${IAC_DIR}/node_modules is missing. Run 'npm install' in iac-cdk first:" >&2
  echo "         (cd '${IAC_DIR}' && npm install)" >&2
  exit 1
fi

echo "-- resolving AWS identity (sts get-caller-identity) --"
if ! CALLER_JSON="$(aws sts get-caller-identity --output json 2>/dev/null)"; then
  echo "error: could not resolve AWS credentials. Set AWS_PROFILE / run 'aws sso login'" >&2
  echo "       for the account whose sentinel-* stacks you want to remove, then retry." >&2
  exit 1
fi

if command -v python3 >/dev/null 2>&1; then
  ACCOUNT_ID="$(printf '%s' "$CALLER_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["Account"])')"
  CALLER_ARN="$(printf '%s' "$CALLER_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["Arn"])')"
else
  ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
  CALLER_ARN="$(aws sts get-caller-identity --query Arn --output text)"
fi

REGION="${SENTINEL_REGION:-${AWS_REGION:-${AWS_DEFAULT_REGION:-$(aws configure get region 2>/dev/null || true)}}}"
if [[ -z "${REGION}" ]]; then
  echo "error: no region resolved. Set SENTINEL_REGION or AWS_REGION (e.g. us-east-1)." >&2
  exit 1
fi

# Bind CDK to the resolved environment (from the active profile — never hardcoded).
export CDK_DEFAULT_ACCOUNT="${ACCOUNT_ID}"
export CDK_DEFAULT_REGION="${REGION}"

echo
echo "  About to DESTROY the sentinel-harness L3 foundation in:"
echo "    AWS account : ${ACCOUNT_ID}"
echo "    Region      : ${REGION}"
echo "    Caller      : ${CALLER_ARN}"
echo "    Stacks      : ${SENTINEL_STACKS[*]}"
echo "    Bootstrap   : CDKToolkit is NOT touched."
echo

if [[ "${ASSUME_YES}" != true ]]; then
  printf "  Type 'yes' to destroy the stacks above: "
  read -r REPLY < /dev/tty || REPLY=""
  if [[ "${REPLY}" != "yes" ]]; then
    echo "aborted — no changes made." >&2
    exit 130
  fi
fi

echo
echo "-- destroying (npx cdk destroy --force) — account ${ACCOUNT_ID} / ${REGION} --"
# --force skips CDK's per-stack prompt; we already took explicit consent above.
# Naming the stacks (rather than --all) keeps the blast radius to sentinel-* only.
(
  cd "${IAC_DIR}"
  npx cdk destroy "${SENTINEL_STACKS[@]}" --force
)

echo
echo "== destroy complete =="
echo "The CDKToolkit bootstrap stack was left in place. Remove it manually only if"
echo "you are finished with CDK in this account entirely."
