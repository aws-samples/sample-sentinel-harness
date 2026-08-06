"""Repository maintenance tooling — not part of the shipped package.

`__init__.py` is REQUIRED here, not decorative. Without it `scripts/` resolves as a namespace
package, and INV-PKG-1 records what that costs: the repo once shipped a top-level `litellm/`
namespace package while `litellm` is also a PyPI dependency every specialist installs, so a regular
installed package silently outranked it and `litellm.gateway` stopped importing in the only
environment it targeted. `scripts` is a plausible name for an installed package too, so the same
trap applies.

Nothing here is imported by `sentinel_harness`; these are maintainer entry points run via
`make <target>`. They are deliberately excluded from the sdist for the same reason `.github/` is —
CI and maintenance tooling is not source, and a downstream packager (conda-forge, Debian, Fedora)
should not have their build depend on it. See `tests/test_sdist_contents.py`.
"""
