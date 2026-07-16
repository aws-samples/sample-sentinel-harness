"""
sentinel-harness · tool/skill registry (Layer-3 governance)
===========================================================
A **ToolRegistry** enforces the governance rule that a SecOps team uses to
centrally decide which tools/skills an agent may use:

    A tool is *live* only if it appears in BOTH
      (1) the registry  — a declarative allowlist (registry.yaml or a dict),
          owned/curated by SecOps (owner, status, description), AND
      (2) the code       — a ``TOOL_FACTORY_MAP`` that maps a tool name to the
          callable that actually builds its harness tool-config.

This is a deliberate *dual-gate*. The declarative side lets a security team
approve/deprecate tools without shipping code; the code side guarantees an
approved name is actually implemented. A name present in only one side is a
governance drift the ``governance_check`` surfaces (never silently ignored).

Configuration (12-factor)
-------------------------
    export SENTINEL_REGISTRY_PATH="registry/tools.yaml"   # optional override

Nothing here calls AWS, reads secrets, or uses an LLM. It is pure, deterministic
governance metadata + a factory lookup.
"""
from __future__ import annotations
import os
from dataclasses import dataclass, field
from typing import Callable, Iterable

# Optional dependency: PyYAML. Mirror core/tool style — use it if present, else
# fall back to a tiny built-in parser for the flat shape our registry files use.
try:  # pragma: no cover - import guard
    import yaml as _yaml  # type: ignore
except Exception:  # pragma: no cover
    _yaml = None

DEFAULT_REGISTRY_PATH = os.environ.get("SENTINEL_REGISTRY_PATH", "registry/tools.yaml")

# Valid declarative lifecycle states a SecOps owner may set on an entry.
STATUSES = ("approved", "pending", "deprecated")


class RegistryError(Exception):
    """Raised when a tool cannot be resolved or an entry is malformed."""


@dataclass(frozen=True)
class ToolEntry:
    """One declarative registry record. ``status`` gates liveness: only
    ``approved`` entries are eligible to be live (must also have a code impl)."""
    name: str
    owner: str
    status: str = "pending"
    description: str = ""
    metadata: dict = field(default_factory=dict)

    def __post_init__(self):
        if not self.name:
            raise RegistryError("registry entry requires a non-empty 'name'")
        if not self.owner:
            raise RegistryError(f"registry entry {self.name!r} requires an 'owner'")
        if self.status not in STATUSES:
            raise RegistryError(
                f"registry entry {self.name!r} has invalid status {self.status!r}; "
                f"expected one of {STATUSES}"
            )


@dataclass
class GovernanceReport:
    """Result of a dual-gate reconciliation between registry and code map."""
    live: list[str] = field(default_factory=list)              # in both + approved
    approved_missing_impl: list[str] = field(default_factory=list)  # registry-only
    impl_missing_registry: list[str] = field(default_factory=list)  # code-only
    pending: list[str] = field(default_factory=list)           # in both, status==pending
    deprecated_with_code: list[str] = field(default_factory=list)  # deprecated but code still live

    @property
    def ok(self) -> bool:
        """True when there is no governance drift (no orphan on either side, and no
        DEPRECATED tool still shipping a live code factory — that tool could still
        be resolved, so it is drift, not a benign pending)."""
        return (not self.approved_missing_impl and not self.impl_missing_registry
                and not self.deprecated_with_code)


class ToolRegistry:
    """Declarative allowlist + code-factory dual-gate.

    ``factory_map`` maps a tool name -> zero-arg (or kw-only) callable returning a
    harness tool-config dict (e.g. the ``sentinel_harness.core.tool_*`` builders).
    The registry itself never *runs* a factory unless ``resolve`` is asked to.
    """

    def __init__(self, factory_map: dict[str, Callable[..., dict]] | None = None):
        self._entries: dict[str, ToolEntry] = {}
        self._factories: dict[str, Callable[..., dict]] = dict(factory_map or {})

    # ------------------------------------------------------------------ code side
    def register(self, name: str, factory: Callable[..., dict]) -> None:
        """Register (or override) the code implementation for ``name``."""
        if not name:
            raise RegistryError("register requires a non-empty tool name")
        if not callable(factory):
            raise RegistryError(f"factory for {name!r} must be callable")
        self._factories[name] = factory

    @property
    def factory_map(self) -> dict[str, Callable[..., dict]]:
        return dict(self._factories)

    # -------------------------------------------------------------- declarative side
    def add_entry(self, entry: ToolEntry) -> None:
        self._entries[entry.name] = entry

    def load_dict(self, data: dict) -> ToolRegistry:
        """Load declarative entries from an already-parsed mapping.

        Accepts either ``{"tools": [ {name,owner,...}, ... ]}`` or a bare
        ``{name: {owner, status, ...}, ...}`` mapping. Returns ``self`` for
        chaining. Recognized keys (name/owner/status/description) are hoisted;
        everything else is preserved under ``metadata``.
        """
        if not isinstance(data, dict):
            raise RegistryError("registry data must be a mapping")
        items = data.get("tools", data)
        if isinstance(items, list):
            pairs: Iterable[tuple[str, dict]] = (
                (it.get("name"), it) for it in items if isinstance(it, dict)
            )
        elif isinstance(items, dict):
            pairs = items.items()
        else:
            raise RegistryError("registry 'tools' must be a list or mapping")
        for name, spec in pairs:
            # A non-dict spec (e.g. a bare string) must surface as RegistryError —
            # the documented error type — not a cryptic bare ValueError from dict().
            if spec is not None and not isinstance(spec, dict):
                raise RegistryError(
                    f"entry {name!r} spec must be a mapping, got {type(spec).__name__}"
                )
            spec = dict(spec or {})
            spec.pop("name", None)
            known = {k: spec.pop(k) for k in ("owner", "status", "description") if k in spec}
            self.add_entry(ToolEntry(name=name, metadata=spec, **known))
        return self

    def load_yaml(self, path: str | None = None) -> ToolRegistry:
        """Load declarative entries from a YAML file. Uses PyYAML when available,
        else a minimal flat parser sufficient for the shipped ``tools.yaml`` shape.
        """
        path = path or DEFAULT_REGISTRY_PATH
        if not os.path.exists(path):
            raise RegistryError(f"registry file not found: {path}")
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
        data = _yaml.safe_load(text) if _yaml is not None else _mini_yaml(text)
        return self.load_dict(data or {})

    # ------------------------------------------------------------------ resolution
    def resolve(self, name: str) -> dict:
        """Return the built tool-config for a *live* tool, or raise.

        Enforces the full dual-gate at call time: the name must be in the
        registry, be ``approved``, AND have a code factory. Any miss raises
        ``RegistryError`` (never silently returns a partial/None config).
        """
        entry = self._entries.get(name)
        if entry is None:
            raise RegistryError(f"tool {name!r} is not in the registry (not approved for use)")
        if entry.status != "approved":
            raise RegistryError(f"tool {name!r} is registered but status={entry.status!r} (not approved)")
        factory = self._factories.get(name)
        if factory is None:
            raise RegistryError(f"tool {name!r} is approved but has no code implementation in TOOL_FACTORY_MAP")
        return factory()

    def list_live(self) -> list[str]:
        """Names live under the dual-gate: approved AND implemented in code."""
        return sorted(
            n for n, e in self._entries.items()
            if e.status == "approved" and n in self._factories
        )

    def get_entry(self, name: str) -> ToolEntry:
        entry = self._entries.get(name)
        if entry is None:
            raise RegistryError(f"tool {name!r} is not in the registry")
        return entry

    def entries(self) -> dict[str, ToolEntry]:
        return dict(self._entries)

    # ------------------------------------------------------------------ governance
    def governance_check(self) -> GovernanceReport:
        """Reconcile the two gates and report drift.

        - ``approved_missing_impl``: approved in the registry but no code factory
          (a SecOps team approved a tool engineering hasn't shipped).
        - ``impl_missing_registry``: a code factory exists but the name is absent
          from the registry (shadow capability that was never governed/approved).
        - ``pending``: present on both sides but not yet approved.
        - ``live``: approved AND implemented — the only tools ``resolve`` serves.
        """
        report = GovernanceReport()
        reg_names = set(self._entries)
        code_names = set(self._factories)
        for name, entry in self._entries.items():
            if entry.status == "approved":
                if name in code_names:
                    report.live.append(name)
                else:
                    report.approved_missing_impl.append(name)
            elif entry.status == "pending":
                if name in code_names:
                    report.pending.append(name)
            elif name in code_names:
                # A non-approved, non-pending status (e.g. deprecated) that STILL
                # ships a live code factory is drift — resolve() could serve it.
                report.deprecated_with_code.append(name)
        report.impl_missing_registry = sorted(code_names - reg_names)
        report.live.sort()
        report.approved_missing_impl.sort()
        report.pending.sort()
        report.deprecated_with_code.sort()
        return report


def load_registry(
    factory_map: dict[str, Callable[..., dict]] | None = None,
    path: str | None = None,
) -> ToolRegistry:
    """Convenience: build a registry from ``factory_map`` + a YAML file."""
    return ToolRegistry(factory_map).load_yaml(path)


# ---------------------------------------------------------------- minimal YAML
def _mini_yaml(text: str) -> dict:
    """Parse the narrow ``{tools: [ {key: value}, ... ]}`` shape our registry
    files use, so the module works without PyYAML installed. NOT a general YAML
    parser — it handles a top-level ``tools:`` list of flat string/scalar maps.
    """
    tools: list[dict] = []
    current: dict | None = None
    in_tools = False
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        raw = lines[i]
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            i += 1
            continue
        stripped = line.strip()
        indent = len(line) - len(line.lstrip())
        if indent == 0:
            in_tools = stripped.rstrip(":") == "tools"
            i += 1
            continue
        if not in_tools:
            i += 1
            continue
        if stripped.startswith("- "):
            current = {}
            tools.append(current)
            stripped = stripped[2:].strip()
            if not stripped:
                i += 1
                continue
        if current is None or ":" not in stripped:
            i += 1
            continue
        key, _, value = stripped.partition(":")
        value = value.strip()
        # Block-scalar indicators (>-, >, |, |-): the value is the following
        # more-indented lines folded/joined. Without this the description came
        # back as the literal '>-'. We fold to a single space-joined string
        # (good enough for our one-line descriptions); the indicator's chomping
        # nuances are not modeled.
        if value in (">", ">-", ">+", "|", "|-", "|+"):
            block: list[str] = []
            j = i + 1
            while j < len(lines):
                bl = lines[j]
                if not bl.strip():
                    j += 1
                    continue
                bindent = len(bl) - len(bl.lstrip())
                if bindent <= indent:
                    break
                block.append(bl.strip())
                j += 1
            current[key.strip()] = " ".join(block)
            i = j
            continue
        current[key.strip()] = _scalar(value)
        i += 1
    return {"tools": tools}


def _scalar(value: str):
    if not value:
        return ""
    if (value[0] == value[-1]) and value[0] in "\"'":
        return value[1:-1]
    low = value.lower()
    if low in ("true", "false"):
        return low == "true"
    if low in ("null", "~", "none"):
        return None
    return value
