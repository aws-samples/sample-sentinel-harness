"""
Docs-drift guard for the pdoc-rendered API reference.
=====================================================
The API site (``.github/workflows/docs.yml`` → pdoc → GitHub Pages) is only as good
as the docstrings it renders. This test fails the build when a PUBLIC symbol exported
from ``sentinel_harness`` has no docstring, so the reference site can never silently
degrade into a wall of undocumented names.

Scope + rationale:
- Only ``sentinel_harness.__all__``-style exports are checked (the names a user
  imports and the ones pdoc surfaces first) — internal helpers are out of scope.
- Constants / simple data values (str, int, float, bool, frozenset, dict, tuple,
  module objects) are skipped: a docstring on a plain value is neither idiomatic nor
  renderable. Only callables (functions) and classes must be documented.
- ZERO AWS / network: this reads the already-imported module object, nothing else.
"""
from __future__ import annotations

import inspect
import os

# Hermetic import — never resolve a real region/role/creds.
os.environ.setdefault("SENTINEL_REGION", "us-east-1")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("SENTINEL_EXECUTION_ROLE_ARN", "arn:aws:iam::000000000000:role/test-harness-role")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")

import sentinel_harness as sh  # noqa: E402


def _public_names() -> list[str]:
    """Public exports: names bound on the package that don't start with '_'."""
    return [n for n in dir(sh) if not n.startswith("_")]


def test_public_callables_and_classes_have_docstrings():
    """Every exported function/class must carry a non-empty docstring (feeds pdoc)."""
    undocumented = []
    for name in _public_names():
        obj = getattr(sh, name)
        if inspect.isfunction(obj) or inspect.isclass(obj):
            doc = inspect.getdoc(obj)
            if not (doc and doc.strip()):
                undocumented.append(name)
    assert not undocumented, (
        "public API exports missing a docstring (the pdoc site would render them "
        f"blank): {sorted(undocumented)}"
    )


def test_package_has_module_docstring():
    """The package itself must have a top-level docstring (pdoc's landing page)."""
    assert (sh.__doc__ or "").strip(), "sentinel_harness package is missing its module docstring"


def test_public_surface_is_nonempty():
    """Guard against an __init__ regression that stops re-exporting the public API."""
    names = _public_names()
    # A floor, not an exact count (the surface only grows): core entry points present.
    for expected in ("create_harness", "invoke", "create_gateway", "regression_guard"):
        assert expected in names, f"expected public export {expected!r} missing from sentinel_harness"
    assert len(names) >= 40, f"public surface unexpectedly small ({len(names)} names) — export regression?"
