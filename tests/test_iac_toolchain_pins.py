"""
The IaC toolchain pins must stay consistent with the runner CI actually uses.
===========================================================================
`iac-cdk` has 8 stack tests, and `.github/workflows/ci.yml` runs each as a standalone
`npx ts-node test/<name>.test.ts` — there is no jest. That makes `ts-node` load-bearing
CI infrastructure, and it constrains which TypeScript major this project can adopt.

Round 23 tested the Dependabot TypeScript 7.0 proposal empirically rather than declining
it on caution:

    tsc --noEmit under 7.0.2   CLEAN, once `types: ["node"]` is declared. The 7 x
                               TS2591 "Cannot find name 'process'" errors were an
                               implicit-@types regression, not incompatible code.
    npx ts-node test/*.test.ts ALL 8 die at startup:
                               TypeError: Cannot read properties of undefined
                                          (reading 'fileExists')

TS 7 is the native rewrite and no longer exposes the `ts.sys` JS surface `ts-node` reads
its tsconfig through. So the blocker is the RUNNER, not the code — and adopting TS 7 needs
a runner migration (tsx, `node --experimental-strip-types`, or jest+swc) as its own
change.

This file keeps that decision from rotting in either direction:

* the pin exists and the reason is recorded where Dependabot reads it, so the same PR
  does not arrive weekly with no memory of why it was closed;
* if someone lifts the pin, they must ALSO have replaced the ts-node runner — otherwise
  the build fails here rather than in a green-looking CI whose IaC test layer silently
  cannot start.

Zero network, zero AWS: this reads config files as data.
"""
from __future__ import annotations

import json
import pathlib
import re

import pytest

yaml = pytest.importorskip("yaml", reason="PyYAML parses the dependabot config")

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
DEPENDABOT = REPO_ROOT / ".github" / "dependabot.yml"
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"
IAC_DIR = REPO_ROOT / "iac-cdk"
PACKAGE_JSON = IAC_DIR / "package.json"
TSCONFIG = IAC_DIR / "tsconfig.json"


def _strip_jsonc(text: str) -> str:
    """tsconfig.json is JSONC — drop // comments so json can read it.

    Line-based rather than regex-over-the-whole-file: a `//` inside a string value (a URL,
    a path) must not be treated as a comment. Only a line whose first non-space characters
    are `//` is dropped.
    """
    kept = [ln for ln in text.splitlines() if not ln.lstrip().startswith("//")]
    return "\n".join(kept)


def _npm_update_block() -> dict:
    doc = yaml.safe_load(DEPENDABOT.read_text(encoding="utf-8"))
    blocks = [u for u in doc.get("updates", [])
              if u.get("package-ecosystem") == "npm"]
    assert len(blocks) == 1, (
        f"expected exactly one npm update block, found {len(blocks)} — this module's "
        "assertions target the iac-cdk one and would be ambiguous"
    )
    return blocks[0]


# --------------------------------------------------------------------------- #
# The runner CI depends on                                                     #
# --------------------------------------------------------------------------- #
def test_ci_still_runs_the_stack_tests_through_ts_node():
    """The premise of the whole pin. If CI stops using ts-node, the constraint is gone
    and this module's reasoning must be revisited rather than silently kept."""
    ci = CI_WORKFLOW.read_text(encoding="utf-8")
    assert "ts-node" in ci, (
        "ci.yml no longer mentions ts-node. If the stack-test runner was migrated, the "
        "TypeScript >=7 pin in dependabot.yml may no longer be needed — re-test with "
        "`npm install typescript@~7 && npx tsc --noEmit && npx ts-node test/*.test.ts` "
        "and update both files together."
    )
    assert re.search(r"test/\*\.test\.ts|test/\*", ci), (
        "ci.yml no longer globs iac-cdk/test/*.test.ts — the stack tests may not be "
        "running at all"
    )


def test_the_stack_tests_exist():
    tests = sorted(IAC_DIR.glob("test/*.test.ts"))
    assert len(tests) >= 8, (
        f"only {len(tests)} stack test(s) found; CI's per-file loop would silently "
        "cover less than expected"
    )


# --------------------------------------------------------------------------- #
# The pin, and the reason for it                                               #
# --------------------------------------------------------------------------- #
def test_typescript_major_is_pinned_below_7():
    """package.json must not float onto a TypeScript major the runner cannot load."""
    pkg = json.loads(PACKAGE_JSON.read_text(encoding="utf-8"))
    spec = (pkg.get("devDependencies") or {}).get("typescript")
    assert spec, "typescript is not a devDependency of iac-cdk"
    assert not re.match(r"^[\^>]", spec), (
        f"typescript is specified as {spec!r}, which allows a major-version drift onto "
        "TS 7 — where all 8 stack tests fail to start under ts-node. Use a `~x.y` or "
        "exact pin."
    )
    major = int(re.search(r"(\d+)", spec).group(1))
    assert major < 7, (
        f"typescript is pinned at major {major}. TS 7 removes the `ts.sys` JS surface "
        "that ts-node reads its tsconfig through, so every stack test dies with "
        "'Cannot read properties of undefined (reading \\'fileExists\\')'. Adopting it "
        "requires migrating the runner (tsx / node --experimental-strip-types / "
        "jest+swc) in the same change."
    )


def test_dependabot_ignores_the_typescript_major_and_says_why():
    """A pin with no recorded reason gets lifted by the next person who sees a stale
    dependency — and Dependabot re-proposes it weekly forever."""
    block = _npm_update_block()
    ignores = block.get("ignore") or []
    ts_ignore = [i for i in ignores if i.get("dependency-name") == "typescript"]
    assert ts_ignore, (
        "dependabot.yml does not ignore the typescript major, so the TS 7 PR arrives "
        "again every week with no memory of why it was closed"
    )
    versions = " ".join(ts_ignore[0].get("versions") or [])
    assert "7" in versions, f"the typescript ignore does not cover 7.x: {versions!r}"

    # The reason must be written where the reader is: in the config file itself.
    text = DEPENDABOT.read_text(encoding="utf-8")
    assert "ts.sys" in text and "ts-node" in text, (
        "the typescript pin carries no explanation of the ts-node/ts.sys incompatibility "
        "that caused it — a pin without its evidence is indistinguishable from caution"
    )


# --------------------------------------------------------------------------- #
# The half of the TS 7 failure that WAS a real gap                             #
# --------------------------------------------------------------------------- #
def test_tsconfig_declares_the_node_types_explicitly():
    """`types` was unset, which up to TS 5 meant "include every @types/* under
    typeRoots". TS 7 dropped that implicit behaviour and `process` / `crypto` / `path` /
    `__dirname` all stopped resolving.

    Declaring it is right independent of any upgrade: `@types/node` was already a
    devDependency, and relying on an implicit include is exactly the kind of unstated
    dependency that turns a version bump into a mystery.
    """
    cfg = json.loads(_strip_jsonc(TSCONFIG.read_text(encoding="utf-8")))
    types = (cfg.get("compilerOptions") or {}).get("types")
    assert types is not None, (
        "tsconfig.json leaves `types` unset, relying on TypeScript's implicit "
        "@types/* inclusion — removed in TS 7, and the cause of 7 x TS2591 "
        "'Cannot find name process' during the upgrade test"
    )
    assert "node" in types, f"`types` does not include 'node': {types!r}"
    pkg = json.loads(PACKAGE_JSON.read_text(encoding="utf-8"))
    assert "@types/node" in (pkg.get("devDependencies") or {}), (
        "tsconfig declares types: ['node'] but @types/node is not a devDependency — tsc "
        "would fail to resolve it"
    )
