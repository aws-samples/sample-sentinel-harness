"""
Offline tests for the registry's built-in PyYAML fallback parser (_mini_yaml)
=============================================================================
``sentinel_harness.registry`` uses PyYAML when installed, else a tiny built-in
``_mini_yaml`` sufficient for the flat ``{tools: [ {key: value}, ... ]}`` shape
the shipped registry files use. These tests pin that fallback's behavior with
ZERO AWS calls and ZERO network:

- ``_mini_yaml`` parses a crafted doc (quoted values, booleans, null, comments,
  blank lines) EQUIVALENTLY to PyYAML on the same text,
- ``load_yaml`` works with PyYAML forced OFF (``_yaml = None``), proving the
  fallback path is wired,
- ``_scalar`` edge cases (empty, quotes, bool casing, null aliases, plain).

PyYAML availability is toggled per-test by monkeypatching ``registry._yaml``, so
the fallback is exercised deterministically regardless of the environment.
"""
from __future__ import annotations

import os

import pytest

os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

import yaml  # noqa: E402  (PyYAML is a declared test dependency)

from sentinel_harness import registry as reg  # noqa: E402


# A crafted doc exercising every feature the fallback claims to support:
# a leading comment, blank lines, an inline trailing comment, quoted values
# (double + single), booleans (true/false, mixed case), and a null alias.
CRAFTED = """# sentinel registry — crafted for parser-equivalence tests
tools:
  # first tool
  - name: sigma_yara_lint
    owner: "det-eng"
    status: approved      # inline comment stripped
    enabled: true

  - name: web_search
    owner: 'ti'
    status: pending
    beta: FALSE
    retired: null
    replacement: ~
"""


@pytest.fixture()
def yaml_off(monkeypatch):
    """Force the PyYAML-absent code path by nulling ``registry._yaml``."""
    monkeypatch.setattr(reg, "_yaml", None)


# --------------------------------------------------------------- equivalence
def test_mini_yaml_matches_pyyaml_on_crafted_doc():
    """The fallback parses the crafted doc identically to PyYAML."""
    assert reg._mini_yaml(CRAFTED) == yaml.safe_load(CRAFTED)


def test_mini_yaml_shape_and_values():
    """Spot-check the parsed structure so the equivalence test can't pass on a
    shared-but-wrong shape."""
    data = reg._mini_yaml(CRAFTED)
    assert list(data) == ["tools"]
    tools = data["tools"]
    assert len(tools) == 2
    assert tools[0] == {
        "name": "sigma_yara_lint",
        "owner": "det-eng",       # double-quotes stripped
        "status": "approved",     # trailing comment removed
        "enabled": True,          # boolean coerced
    }
    assert tools[1] == {
        "name": "web_search",
        "owner": "ti",            # single-quotes stripped
        "status": "pending",
        "beta": False,            # mixed-case FALSE coerced
        "retired": None,          # null alias
        "replacement": None,      # ~ alias
    }


# --------------------------------------------------------------- load_yaml fallback wiring
def test_load_yaml_uses_fallback_when_pyyaml_absent(tmp_path, yaml_off):
    """With ``_yaml=None``, load_yaml drives ``_mini_yaml`` and still builds a
    correct registry — equivalent to loading the same text via PyYAML."""
    path = tmp_path / "reg.yaml"
    path.write_text(CRAFTED, encoding="utf-8")

    r = reg.ToolRegistry().load_yaml(str(path))
    assert set(r.entries()) == {"sigma_yara_lint", "web_search"}
    assert r.get_entry("sigma_yara_lint").status == "approved"
    assert r.get_entry("sigma_yara_lint").owner == "det-eng"
    assert r.get_entry("web_search").status == "pending"
    # Non-recognized keys (enabled/beta/retired/...) land under metadata.
    assert r.get_entry("sigma_yara_lint").metadata == {"enabled": True}
    assert r.get_entry("web_search").metadata == {
        "beta": False, "retired": None, "replacement": None
    }


def test_load_yaml_fallback_equivalent_to_pyyaml(tmp_path, monkeypatch):
    """Loading the crafted doc yields identical entries whether PyYAML is on or
    off — the fallback is a drop-in for the shapes we ship."""
    path = tmp_path / "reg.yaml"
    path.write_text(CRAFTED, encoding="utf-8")

    monkeypatch.setattr(reg, "_yaml", yaml)
    with_pyyaml = reg.ToolRegistry().load_yaml(str(path)).entries()

    monkeypatch.setattr(reg, "_yaml", None)
    without_pyyaml = reg.ToolRegistry().load_yaml(str(path)).entries()

    assert set(with_pyyaml) == set(without_pyyaml)
    for name in with_pyyaml:
        a, b = with_pyyaml[name], without_pyyaml[name]
        assert (a.name, a.owner, a.status, a.metadata) == (
            b.name, b.owner, b.status, b.metadata
        )


# --------------------------------------------------------------- _scalar edge cases
def test_scalar_empty_is_empty_string():
    assert reg._scalar("") == ""


@pytest.mark.parametrize("raw,expected", [
    ('"quoted"', "quoted"),
    ("'quoted'", "quoted"),
    ('""', ""),
    ("''", ""),
])
def test_scalar_strips_matching_quotes(raw, expected):
    assert reg._scalar(raw) == expected


@pytest.mark.parametrize("raw,expected", [
    ("true", True),
    ("True", True),
    ("TRUE", True),
    ("false", False),
    ("False", False),
    ("FALSE", False),
])
def test_scalar_booleans(raw, expected):
    assert reg._scalar(raw) is expected


@pytest.mark.parametrize("raw", ["null", "Null", "NULL", "~", "none", "None", "NONE"])
def test_scalar_null_aliases(raw):
    assert reg._scalar(raw) is None


@pytest.mark.parametrize("raw", ["approved", "det-eng", "T1059.001", "192.0.2.10"])
def test_scalar_plain_strings_pass_through(raw):
    assert reg._scalar(raw) == raw


def test_scalar_quoted_boolean_stays_string():
    """A quoted 'true' is a string, not a boolean — quotes win over coercion."""
    assert reg._scalar('"true"') == "true"
    assert reg._scalar("'null'") == "null"


# --------------------------------------------------------------- _mini_yaml robustness
def test_mini_yaml_ignores_content_outside_tools_block():
    """Top-level keys other than ``tools:`` are ignored by the narrow parser."""
    text = "version: 1\nmeta:\n  owner: secops\ntools:\n  - name: a\n    owner: t\n"
    assert reg._mini_yaml(text) == {"tools": [{"name": "a", "owner": "t"}]}


def test_mini_yaml_empty_doc_yields_empty_tools():
    assert reg._mini_yaml("") == {"tools": []}
    assert reg._mini_yaml("# only a comment\n\n") == {"tools": []}


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))


# --------------------------------------------------------------------------- #
# regression (round-2 audit): block-scalar (>-, |) + non-dict spec + deprecated
# --------------------------------------------------------------------------- #
def test_mini_yaml_folds_block_scalar():
    doc = ("tools:\n"
           "  - name: t\n"
           "    description: >-\n"
           "      line one\n"
           "      line two\n"
           "    status: approved\n")
    out = reg._mini_yaml(doc)["tools"][0]
    assert out["description"] == "line one line two"  # not the literal '>-'
    assert out["status"] == "approved"


def test_non_dict_spec_raises_registry_error():
    r = reg.ToolRegistry()
    with pytest.raises(reg.RegistryError, match="must be a mapping"):
        r.load_dict({"tools": {"bad": "not-a-dict"}})


def test_deprecated_with_code_is_drift():
    r = reg.ToolRegistry({"old": lambda: {}})
    r.add_entry(reg.ToolEntry(name="old", owner="x", status="deprecated", description="d"))
    rep = r.governance_check()
    assert rep.deprecated_with_code == ["old"]
    assert rep.ok is False
    assert "old" not in rep.pending  # not miscategorized as pending
