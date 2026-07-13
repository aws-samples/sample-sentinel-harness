#!/usr/bin/env bash
#
# deploy.sh — one-command deploy of the sentinel-harness Layer-3 foundation (CDK).
# ==============================================================================
# WHY this script exists:
#   The M4 CDK app in ../iac-cdk ships eight synth-green stacks, but a human still
#   has to (a) prove their AWS identity, (b) pick the *right* (non-prod!) account,
#   and (c) decide whether to pay for the ~$30/mo VPC interface endpoints. Doing
#   that by hand is error-prone and easy to get wrong against the wrong account.
#   This wrapper makes the safe path the default and the costly path an explicit,
#   opt-in flag — while NEVER hardcoding an account (that comes from the caller's
#   active profile) and NEVER deploying before a human has seen and confirmed the
#   exact account + region it is about to touch.
#
# WHAT it deploys:
#   By default: the FREE-TIER stacks — guardrail, identity (Cognito), observability
#   (CloudWatch dashboard + budget alarm), and network *without* the billable
#   PrivateLink interface endpoints. Standing cost of that set is ~a few dollars
#   a month (see deploy/README.md for the honest per-stack breakdown).
#   With --with-endpoints: additionally flips on the ~$30/mo VPC interface
#   endpoints via the CDK context flag `sentinel:deployVpcEndpoints=true`.
#
# SAFETY:
#   * Requires an interactive human "yes" after printing account + region.
#   * `--require-approval never` is passed to CDK ONLY after that human confirm,
#     so CDK's own IAM prompt is not silently bypassed before a person has agreed.
#   * NON-PROD target. This provisions a security workload; run it against a
#     sandbox/non-prod account first (docs/BLUEPRINT.md is explicit on this).
#   * Idempotent: CDK deploy is a no-op for already-current stacks, so re-running
#     is safe.
#
# USAGE:
#   deploy/deploy.sh                 # free-tier stacks only (default)
#   deploy/deploy.sh --with-endpoints  # also deploy the ~$30/mo VPC endpoints
#   deploy/deploy.sh --yes           # skip the interactive prompt (CI/non-interactive)
#   deploy/deploy.sh --help
#
# Exit codes: 0 success · 1 prereq/usage error · 130 user aborted at the prompt.
#
set -euo pipefail

# --- Resolve paths independent of the caller's CWD (WHY: this script is invoked
#     from anywhere; the CDK app lives in a sibling dir). ------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IAC_DIR="$(cd "${SCRIPT_DIR}/../iac-cdk" && pwd)"

# The free-tier stack set — everything EXCEPT the billable VPC interface endpoints.
# (The endpoints are a context flag on sentinel-network, not a separate stack, so
# the stack list is identical; the flag is what changes with --with-endpoints.)
# We name only sentinel-* stacks; the CDKToolkit bootstrap stack is never touched.
FREE_TIER_STACKS=(
  "sentinel-guardrail"
  "sentinel-identity"
  "sentinel-observability"
  "sentinel-network"
)

WITH_ENDPOINTS=false
ASSUME_YES=false

usage() {
  # Keep usage in sync with the header. Printed on --help or bad args.
  cat <<'EOF'
Usage: deploy/deploy.sh [--with-endpoints] [--yes] [--help]

  (no flags)         Deploy the FREE-TIER foundation stacks:
                     sentinel-guardrail, sentinel-identity, sentinel-observability,
                     sentinel-network (interface endpoints OFF — ~a few $/mo total).
  --with-endpoints   Also deploy the ~$30/mo VPC interface endpoints
                     (-c sentinel:deployVpcEndpoints=true on sentinel-network).
  --yes              Do not prompt for confirmation (for CI). The account + region
                     are still printed. Use with care.
  --help             Show this help and exit.

Account and region come from your ACTIVE AWS profile — never hardcoded. Point at a
NON-PROD account (this provisions a security workload). See deploy/README.md.
EOF
}

# --- Parse args. Unknown flags are a hard error (never silently ignore). --------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --with-endpoints) WITH_ENDPOINTS=true; shift ;;
    --yes|-y)         ASSUME_YES=true; shift ;;
    --help|-h)        usage; exit 0 ;;
    *) echo "error: unknown argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# --- Prereq checks. Fail LOUDLY and early with an actionable message; never let a
#     missing tool surface as a confusing error 40 lines into a CDK run. ---------
require_cmd() {
  local cmd="$1" hint="$2"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "error: required command '$cmd' not found on PATH. $hint" >&2
    exit 1
  fi
}

echo "== sentinel-harness · L3 foundation deploy =="
echo "-- checking prerequisites --"
require_cmd node "Install Node 18+ (https://nodejs.org)."
require_cmd npx  "npx ships with Node/npm — reinstall Node if it is missing."
require_cmd aws  "Install the AWS CLI v2 (https://aws.amazon.com/cli/)."

# `cdk` is used via `npx cdk` (the version pinned in iac-cdk/package.json), so a
# global cdk install is NOT required — but node_modules must be present.
if [[ ! -d "${IAC_DIR}/node_modules" ]]; then
  echo "error: ${IAC_DIR}/node_modules is missing. Run 'npm install' in iac-cdk first:" >&2
  echo "         (cd '${IAC_DIR}' && npm install)" >&2
  exit 1
fi

# --- Resolve the AWS identity. This BOTH proves creds work AND gives us the
#     account id to export as CDK_DEFAULT_ACCOUNT (never hardcoded). -------------
echo "-- resolving AWS identity (sts get-caller-identity) --"
if ! CALLER_JSON="$(aws sts get-caller-identity --output json 2>/dev/null)"; then
  echo "error: could not resolve AWS credentials. Set AWS_PROFILE / run 'aws sso login'" >&2
  echo "       (or export AWS_ACCESS_KEY_ID etc.) for a NON-PROD account, then retry." >&2
  exit 1
fi

# Extract account id + caller ARN without needing jq (portable): python3 is a hard
# dep of this repo anyway. Falls back to the AWS CLI query if python3 is absent.
if command -v python3 >/dev/null 2>&1; then
  ACCOUNT_ID="$(printf '%s' "$CALLER_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["Account"])')"
  CALLER_ARN="$(printf '%s' "$CALLER_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["Arn"])')"
else
  ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
  CALLER_ARN="$(aws sts get-caller-identity --query Arn --output text)"
fi

# Region resolution order: SENTINEL_REGION > AWS_REGION > AWS_DEFAULT_REGION >
# the profile's configured region. WHY: the repo's runtime uses SENTINEL_REGION,
# so honoring it here keeps deploy + runtime on the SAME region (a real M4 bug
# was a stray region env deploying to the wrong region — see the m4 evidence).
REGION="${SENTINEL_REGION:-${AWS_REGION:-${AWS_DEFAULT_REGION:-$(aws configure get region 2>/dev/null || true)}}}"
if [[ -z "${REGION}" ]]; then
  echo "error: no region resolved. Set SENTINEL_REGION or AWS_REGION (e.g. us-east-1)," >&2
  echo "       or configure a default region on your profile." >&2
  exit 1
fi

# --- Export the CDK environment from the ACTIVE profile. NEVER hardcode. --------
# CDK reads CDK_DEFAULT_ACCOUNT/REGION to bind stacks to a concrete environment;
# setting them from the resolved identity keeps the app account-agnostic in code.
export CDK_DEFAULT_ACCOUNT="${ACCOUNT_ID}"
export CDK_DEFAULT_REGION="${REGION}"

# --- Show the human exactly what will be touched, then REQUIRE confirmation. ----
echo
echo "  About to deploy the sentinel-harness L3 foundation to:"
echo "    AWS account : ${ACCOUNT_ID}"
echo "    Region      : ${REGION}"
echo "    Caller      : ${CALLER_ARN}"
echo "    Profile     : ${AWS_PROFILE:-<default / env credentials>}"
echo "    Stacks      : ${FREE_TIER_STACKS[*]}"
if [[ "${WITH_ENDPOINTS}" == true ]]; then
  echo "    Endpoints   : ON  (--with-endpoints → ~\$30/mo VPC interface endpoints)"
else
  echo "    Endpoints   : off (free-tier; pass --with-endpoints to add ~\$30/mo)"
fi
echo
echo "  This is a NON-PROD target. Confirm the account above is a sandbox/non-prod"
echo "  account and NOT production."
echo

if [[ "${ASSUME_YES}" != true ]]; then
  # Read from the terminal even if stdin is a pipe, so a piped installer can't
  # auto-answer this. Default is NO on empty/EOF.
  printf "  Type 'yes' to proceed: "
  read -r REPLY < /dev/tty || REPLY=""
  if [[ "${REPLY}" != "yes" ]]; then
    echo "aborted — no changes made." >&2
    exit 130
  fi
fi

# --- Build the CDK context flags. Endpoints are the ONLY thing the flag changes;
#     the stack list is the same either way. --------------------------------------
CTX_ARGS=()
if [[ "${WITH_ENDPOINTS}" == true ]]; then
  CTX_ARGS+=("-c" "sentinel:deployVpcEndpoints=true")
fi

echo
echo "-- deploying (npx cdk deploy) — account ${ACCOUNT_ID} / ${REGION} --"
# `--require-approval never` is used ONLY here, AFTER the human confirm above, so
# we are not bypassing consent — the person already agreed to this exact env.
# `--app` is left to cdk.json. Running from IAC_DIR so cdk.json/context resolve.
(
  cd "${IAC_DIR}"
  npx cdk deploy "${FREE_TIER_STACKS[@]}" \
    --require-approval never \
    "${CTX_ARGS[@]}"
)

echo
echo "== deploy complete =="
echo "Verify with the evidence scenarios / dashboards described in deploy/README.md."
echo "Tear it all down with:  deploy/destroy.sh"
