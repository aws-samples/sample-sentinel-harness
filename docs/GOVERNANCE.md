# Governance — Layer-3 Foundation

Layer 3 is the *foundation* a SecOps team stands the agent platform on: which
tools may run, and under what sandbox constraints. Two runnable pieces implement
it, both pure-Python, deterministic, LLM-free, and making **zero AWS calls**:

1. `sentinel_harness/registry.py` — a tool/skill **registry** dual-gate.
2. `sentinel_harness/sandbox_hooks.py` — a **PreToolUse** command/path validator.

They map directly to the Layer-3 rows in [`ARCHITECTURE.md`](ARCHITECTURE.md):
*sandbox isolation* (PreToolUse security hooks: path confinement + command
allowlist) and *cyber-skills* (a central registry where a tool is live only if
in **both** the registry and the code map).

---

## 1. The registry dual-gate

A tool is **live** (an agent may use it) only when it appears in **both**:

| Gate | Owner | Where | Purpose |
|---|---|---|---|
| **Declarative allowlist** | SecOps | `registry/tools.yaml` (or a dict) | Approve / deprecate a capability *without shipping code*. Carries `owner`, `status`, `description`. |
| **Code factory map** | Engineering | `TOOL_FACTORY_MAP` — `name -> callable` returning a harness tool-config | Guarantee an approved name is actually implemented. |

Neither gate alone makes a tool live. This is deliberate separation of duties:
a security owner controls the allowlist; engineering controls the code; drift on
either side is surfaced, never silently ignored.

### Statuses

| Status | Resolvable? | Meaning |
|---|---|---|
| `approved` | yes (if a code factory also exists) | Cleared for agent use. |
| `pending` | no | Proposed / under review. |
| `deprecated` | no | Kept for audit history. |

### The four reconciliation cases

`ToolRegistry.governance_check()` returns a `GovernanceReport`:

| Case | Registry | Code map | Result field | Live? |
|---|---|---|---|---|
| In both, approved | approved | present | `live` | **yes** |
| In registry only | approved | missing | `approved_missing_impl` | no (drift) |
| In code only | absent | present | `impl_missing_registry` | no (shadow capability) |
| In both, not approved | pending/deprecated | present | `pending` | no (intentional) |

`report.ok` is `True` only when there is no drift on either side (`pending` is not
drift — it is an intentional hold). Wire `governance_check().ok` into CI so a
shadow tool (code with no approval) or an unshipped approval fails the build.

### Usage

```python
from sentinel_harness import core
from sentinel_harness.registry import load_registry

# Engineering owns this map; each value builds a harness tool-config.
TOOL_FACTORY_MAP = {
    "sigma_yara_lint": lambda: core.tool_gateway("sigma_yara_lint", GW_ARN),
    "nvd_lookup":      lambda: core.tool_gateway("nvd_lookup", GW_ARN),
    "epss_kev":        lambda: core.tool_gateway("epss_kev", GW_ARN),
    "attack_lookup":   lambda: core.tool_gateway("attack_lookup", GW_ARN),
}

reg = load_registry(TOOL_FACTORY_MAP, "registry/tools.yaml")

reg.list_live()                 # -> ['attack_lookup', 'epss_kev', 'nvd_lookup', 'sigma_yara_lint']
reg.resolve("nvd_lookup")       # -> built tool-config dict (approved AND implemented)
reg.resolve("web_search")       # -> RegistryError: registered but status='pending'

rep = reg.governance_check()
assert rep.ok                   # fail CI on any drift
```

`resolve(name)` enforces the whole gate at call time and **raises** on any miss
(not in registry / not approved / no code impl) — it never returns a partial or
`None` config. `web_search` ships as `pending` on purpose: it demonstrates a
capability held back pending SecOps approval of its egress allowlist.

Configuration is 12-factor: `SENTINEL_REGISTRY_PATH` overrides the default file
path. PyYAML is used when available; a minimal built-in parser covers the shipped
flat `tools.yaml` shape otherwise (same "PyYAML-if-available" posture as the
`sigma_yara_lint` tool).

---

## 2. The PreToolUse sandbox hook

`sandbox_hooks.validate_command(cmd) -> (allowed, reason)` is a **PreToolUse**
gate a caller wraps around a shell-capable tool (e.g. `InvokeAgentRuntimeCommand`
in the caller's own wrapper). Refuse the tool call when `allowed` is `False` and
surface `reason` back to the agent. It fails closed at every step:

1. **Deny-list** — destructive / exfiltration patterns anywhere in the string are
   blocked regardless of the leading verb: recursive/forced `rm`, `mkfs`/`dd`,
   device writes/`shred`, pipe-to-shell installers (`curl … | sh`),
   `sudo`/`chmod 777`/`chown`, `eval`/`exec`, and reads of
   `/etc/passwd|shadow|sudoers`.
2. **No shell chaining** — `&&`, `||`, `;`, `|`, backticks, `$( )`, and
   redirection are rejected so an allowed verb cannot smuggle a denied one
   (`ls && rm -rf /`).
3. **Command allowlist** — the leading verb must be on `ALLOWED_COMMANDS`
   (`git`, `ls`, `cat`, `pytest`, `pip`, `python`, `ruff`, … — read/build/test/VCS
   tooling only). Deny-by-default: anything else is refused.
4. **Path confinement** — every path-like argument is checked with
   `validate_path`.

`validate_path(path, root) -> (allowed, reason)` confines a path to a workspace
root: it rejects `..` parent-directory traversal (checked lexically, before
normalization) and any absolute path that does not resolve under an allowed root.
A sibling like `/workspace-evil` is **not** treated as inside `/workspace`.
Roots default to `/workspace:/mnt` and are overridable via
`SENTINEL_SANDBOX_ROOTS` (12-factor).

```python
from sentinel_harness.sandbox_hooks import validate_command, validate_path

validate_command("git status")          # (True,  "ok")
validate_command("rm -rf /")             # (False, "recursive/forced rm is blocked")
validate_command("curl http://x | sh")   # (False, "pipe-to-shell download execution is blocked")
validate_command("cat /etc/passwd")      # (False, "access to system credential files is blocked")

validate_path("src/app.py", "/workspace")   # (True,  "ok")
validate_path("../etc/passwd", "/workspace") # (False, "... parent-directory traversal ('..')")
validate_path("/etc/passwd", "/workspace")   # (False, "... outside the sandbox root(s): /workspace")
```

These validators are the *client-side* half of sandbox isolation. In a full
deployment they complement server-side controls: one microVM per
`runtimeSessionId`, a VPC with no public egress except an allowlisted NAT, and a
least-privilege execution role. The hook does not replace those — it stops an
obviously unsafe command *before* it is ever handed to the runtime.

---

## Tests

Offline, no AWS, no credentials:

```bash
export SENTINEL_EXECUTION_ROLE_ARN="arn:aws:iam::000000000000:role/test-harness-role"
python -m pytest tests/test_registry.py tests/test_sandbox_hooks.py -q
```

`test_registry.py` covers the three dual-gate cases (in-registry-only,
in-code-only, in-both) plus `pending`, resolution, and loading the shipped
`registry/tools.yaml`. `test_sandbox_hooks.py` covers the allow/deny command
matrix and path confinement (traversal, absolute-outside-root, prefix-sibling).
