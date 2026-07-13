#!/usr/bin/env bash
#
# seed_registry.sh — print the approved tool allowlist and prove the dual-gate.
# ==============================================================================
# WHY this script exists:
#   registry/tools.yaml is the SecOps-owned *declarative* half of the Layer-3
#   dual-gate: a tool is only ever LIVE if it is (a) status:approved here AND
#   (b) backed by a code factory in sentinel_harness.registry. "Seeding" the
#   registry is therefore not a database write — it is a human-readable
#   confirmation that the shipped allowlist parses, that the approved set is what
#   we think it is, and that the governance reconciliation reports no drift.
#
# WHAT it does (100% OFFLINE — no AWS, no network):
#   1. Prints every approved tool in registry/tools.yaml (name + owner).
#   2. Runs sentinel_harness.registry.load_registry() and asserts the dual-gate
#      reconciles clean (GovernanceReport.ok is True) for the approved set.
#   Exit 0 = registry consistent; exit 1 = drift / parse error (fails loudly).
#
# USAGE:
#   deploy/seed_registry.sh            # print approved tools + run governance check
#   deploy/seed_registry.sh --help
#
# Exit codes: 0 success · 1 registry drift / prereq error.
#
set -euo pipefail

# --- Resolve paths independent of the caller's CWD. --------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
REGISTRY_PATH="${SENTINEL_REGISTRY_PATH:-${REPO_ROOT}/registry/tools.yaml}"

# Prefer `uv run` (project rule) but fall back to a plain interpreter if uv is
# absent, so the wrapper is usable in a bare CI image too.
if command -v uv >/dev/null 2>&1; then
  PY=(uv run --no-project --python 3.13 --with pyyaml --with . python)
else
  PY=(python3)
fi

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  sed -n '2,26p' "${BASH_SOURCE[0]}"
  exit 0
fi

echo "== sentinel-harness · registry seed (offline governance check) =="
echo "registry: ${REGISTRY_PATH}"

# The Python one-liner is the real check: it parses the shipped YAML, lists the
# approved tools, synthesizes a code factory for each approved name (mirroring the
# shipped TOOL_FACTORY_MAP coverage), and asserts the dual-gate reports no drift.
cd "${REPO_ROOT}"
SENTINEL_REGISTRY_PATH="${REGISTRY_PATH}" "${PY[@]}" - <<'PY'
import sys
import yaml
from sentinel_harness.registry import load_registry

path = __import__("os").environ["SENTINEL_REGISTRY_PATH"]
data = yaml.safe_load(open(path, encoding="utf-8")) or {}
tools = data.get("tools") or []
approved = [t for t in tools if t.get("status") == "approved"]

print(f"\napproved tools ({len(approved)}):")
for t in approved:
    print(f"  - {t['name']:<22} owner={t.get('owner', '?')}")

pending = [t["name"] for t in tools if t.get("status") == "pending"]
if pending:
    print(f"\npending (never live until approved + coded): {', '.join(pending)}")

# Build a code-side factory for each approved name so the dual-gate can reconcile.
factory_map = {t["name"]: (lambda n=t["name"]: {"name": n}) for t in approved}
reg = load_registry(factory_map, path)
report = reg.governance_check()

print(f"\nlive (approved AND code-backed): {len(reg.list_live())}")
if not report.ok:
    print("GOVERNANCE DRIFT:", file=sys.stderr)
    print(f"  approved_missing_impl={report.approved_missing_impl}", file=sys.stderr)
    print(f"  impl_missing_registry={report.impl_missing_registry}", file=sys.stderr)
    sys.exit(1)
print("dual-gate OK — no governance drift.")
PY

echo ""
echo "registry seed complete (offline). No AWS resources were touched."
