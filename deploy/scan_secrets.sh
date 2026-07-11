#!/usr/bin/env bash
#
# scan_secrets.sh — the repo's public-hygiene gate, as a reusable script.
# ============================================================================
# This repo is PUBLIC open source. It must contain ZERO trace of any
# customer/company name, and NO hardcoded AWS account IDs or access keys. This
# script fails (exit 1) if any of those leak in. It is the SINGLE SOURCE of the
# scan logic shared by `make ci`, the pre-commit hook, and CI.
#
# Patterns are assembled from character classes so this script never matches
# itself (no literal forbidden token is a scannable string here).
#
# Allowed placeholders (well-known, non-real):
#   * 000000000000 — the all-zeros placeholder used in docs/tests.
#   * 123456789012 — the canonical AWS documentation example account.
#   * 555555555555 — repeated-digit placeholder used in offline test fixtures.
#
# Exit codes: 0 = clean · 1 = a customer name / account ID / access key leaked.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="${1:-$(cd "${SCRIPT_DIR}/.." && pwd)}"

GREP() { grep -rInE "$1" "$ROOT" \
  --binary-files=without-match \
  --exclude-dir=.git \
  --exclude-dir=.github \
  --exclude-dir=node_modules \
  --exclude-dir=.venv \
  --exclude-dir=cdk.out \
  --exclude-dir=__pycache__ ; }

FAILED=0

# 1) Customer / company names (case-insensitive), built from a char class so the
#    literal name never appears in this file.
NAME_RE='[Aa][Vv][Ee][Nn][Ii][Rr]'
if GREP "$NAME_RE"; then
  echo "::error::Customer/company name found in repository. This is a public repo — remove it."
  FAILED=1
fi

# 2) Hardcoded 12-digit AWS account IDs inside an IAM/ARN/ECR context.
ACCT_RE='(iam|sts|logs|s3|lambda|bedrock-agentcore)::[0-9]{12}:|arn:aws[a-z-]*:[a-z0-9-]*:[a-z0-9-]*:[0-9]{12}:|[0-9]{12}\.dkr\.ecr\.'
if GREP "$ACCT_RE" | grep -vE ':0{12}:|0{12}\.dkr|123456789012|555555555555'; then
  echo "::error::Hardcoded 12-digit AWS account ID found. Use env vars / the 000000000000 placeholder instead."
  FAILED=1
fi

# 3) AWS access key IDs (AKIA / ASIA prefixes + 16 uppercase/digits), assembled
#    from a char class so no real-looking key sits in this file.
KEY_RE='(A[KS]IA)[0-9A-Z]{16}'
if GREP "$KEY_RE"; then
  echo "::error::Hardcoded AWS access key ID found. Never commit credentials."
  FAILED=1
fi

if [ "$FAILED" -ne 0 ]; then
  echo "secret-and-name scan FAILED"
  exit 1
fi
echo "secret-and-name scan passed — no customer names or hardcoded credentials found."
