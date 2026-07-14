# Releasing

A version-agnostic runbook for cutting a `sentinel-harness` release. The whole flow is
tag-driven: pushing a `vX.Y.Z` tag fires `.github/workflows/release.yml`, which builds,
signs, and publishes.

## What the release automation does

`.github/workflows/release.yml` (on push of a `v*` tag):

**`build` job**
1. Build the sdist + wheel (`python -m build`).
2. Smoke-test the built wheel (`sentinel --help`, import + `__version__`).
3. Generate a **CycloneDX SBOM** (`sbom.cyclonedx.json`) of the dependency tree.
4. Record a **SLSA build-provenance attestation** over `dist/*` (`actions/attest-build-provenance`, keyless / Sigstore).
5. Extract release notes from `CHANGELOG.md` — an `awk` matcher pulls the section under the heading **`## [X.Y.Z]`** (this heading spelling is load-bearing).
6. Create the **GitHub Release** with the artifacts + the SBOM attached.

**`pypi-publish` job** (only when the tag is **not** a prerelease — no hyphen)
7. Publish to PyPI via `pypa/gh-action-pypi-publish` over **OIDC Trusted Publishing** — no stored token.

## Release checklist

1. **Bump the version** — `pyproject.toml` (`version = "X.Y.Z"`, the single source;
   `sentinel_harness.__version__` reads it via `importlib.metadata`).
2. **Update the CHANGELOG** — move everything under `## [Unreleased]` into a new
   `## [X.Y.Z] - YYYY-MM-DD` section using the six Keep-a-Changelog groups
   (Added / Changed / Deprecated / Removed / Fixed / Security). **The heading must be
   exactly `## [X.Y.Z]`** — the release notes extractor keys on it. Update the compare
   links at the bottom.
3. **Green the gate locally** — run the full CI parity:
   ```bash
   make ci          # ruff + coverage>=88 + cdk synth + secret-scan
   ```
4. **Commit** the version bump + CHANGELOG on a branch, PR, merge to `main`.

## Cutting the release

```bash
git checkout main && git pull
git tag vX.Y.Z
git push origin vX.Y.Z        # → release.yml fires
```

- **Prereleases** — tag with a hyphen (e.g. `v0.3.0-rc1`). The GitHub Release is marked
  prerelease and the **PyPI publish is skipped** (`if: !contains(github.ref_name, '-')`).
- **Real releases** — a clean `vX.Y.Z` runs the full flow including PyPI.

## One-time prerequisites

| Prerequisite | Status | How |
|---|---|---|
| GitHub Pages source = "GitHub Actions" | ✅ done | set via `gh api -X POST repos/<owner>/<repo>/pages -f build_type=workflow` |
| PyPI **trusted publisher** for this repo+workflow | ⚠️ **required before first PyPI publish** | configure once on PyPI (project → Publishing → add a GitHub Actions trusted publisher for `release.yml`). Until then the `pypi-publish` job fails by design (a release is not "done" until the OIDC identity is accepted). |

## Verifying a release

```bash
gh release view vX.Y.Z                                   # notes + assets (wheel, sdist, SBOM)
gh attestation verify dist/<artifact> --repo <owner>/<repo>   # SLSA provenance
# confirm the SBOM asset (sbom.cyclonedx.json) is attached
# confirm the API docs site republished: https://aws-samples.github.io/sample-sentinel-harness/
```

## Versioning policy

Semantic Versioning:

- **MAJOR** — a breaking change to the public Python API (`sentinel_harness` exports)
  or the harness/scenario contract.
- **MINOR** — new capabilities, tools, specialists, scenarios, or milestones,
  backward-compatible.
- **PATCH** — fixes, docs, CI, and hardening with no API change.

Every release ships live evidence (`evidence/*.json`) and a green CI gate; the CHANGELOG
is the source of truth for what changed.
