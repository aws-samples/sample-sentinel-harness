"""
sentinel-harness · command-line interface
==========================================
Exposes the core library as the ``sentinel`` command (see pyproject
``[project.scripts]``). Pure stdlib + the core library — no third-party deps.

Subcommands
-----------
    sentinel create   <config.yaml|config.json>          create a harness from a config file
    sentinel invoke   <harness-arn> <prompt> [--session] [--actor]
    sentinel list                                         list harnesses
    sentinel delete   <harness-id> [--keep-memory]
    sentinel cleanup  <prefix>                            delete every harness whose name starts with prefix
    sentinel run-scenario <name>                          dispatch to scenarios/ (cve_triage | multi_harness | detection_gen)

Everything is env-parameterized (see core.py): SENTINEL_EXECUTION_ROLE_ARN,
SENTINEL_REGION, AWS_PROFILE. Nothing here is customer- or company-specific.

Two config schemas are accepted by ``sentinel create``:

  1. The SHIPPED declarative harness schema (see ``harnesses/<name>/harness.yaml``
     and ``docs/HARNESSES.md``) — detected by the ``harnessName`` key and resolved
     by ``sentinel_harness.loader.load_harness_config`` (reads the ``systemPrompt``
     file relative to the yaml dir, expands ``${ENV_VAR}`` refs, injects inline
     HITL gates named in ``allowedTools``, and passes model/tools/memory through):

         sentinel create harnesses/alert-triage/harness.yaml

  2. The legacy flat schema below (kept working for JSON/simple configs).

Legacy flat config shape (YAML or JSON — YAML is parsed only if PyYAML is
installed; JSON always works with pure stdlib):

    name: my_harness            # required; [a-zA-Z][a-zA-Z0-9_]{0,39} (no hyphens)
    system_prompt: "..."        # required
    model: sonnet               # sonnet | haiku | opus | a full Bedrock model id
    max_iterations: 15
    max_tokens: 4096
    timeout_seconds: 300
    allowed_tools: [tool_a, tool_b]
    memory:                     # optional
      strategies: [SEMANTIC, SUMMARIZATION]
      expiry_days: 90
      # or, to bring-your-own:  arn: "arn:aws:...:memory/..."
    tools:                      # optional list of tool specs
      - {type: code_interpreter}
      - {type: remote_mcp, name: intel, url: "https://...", headers: {Authorization: "${arn:...}"}}
      - {type: gateway, name: gw, gateway_arn: "arn:aws:...:gateway/..."}
      - {type: inline, name: request_review, description: "...", input_schema: {...}}
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from . import core as sh
from .loader import load_harness_config

SCENARIOS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scenarios")


# --------------------------------------------------------------------------- io
def _eprint(*args) -> None:
    print(*args, file=sys.stderr)


def _load_config(path: str) -> dict:
    """Load a harness config from YAML or JSON. JSON works with pure stdlib;
    YAML requires PyYAML (optional). A JSON file is always accepted."""
    if not os.path.isfile(path):
        raise FileNotFoundError(f"config file not found: {path}")
    with open(path, "r", encoding="utf-8") as fh:
        raw = fh.read()
    ext = os.path.splitext(path)[1].lower()
    if ext in (".yaml", ".yml"):
        try:
            import yaml  # type: ignore
        except ImportError as exc:  # pragma: no cover - depends on env
            raise RuntimeError(
                "PyYAML is required to read YAML configs (pip install pyyaml), "
                "or convert the config to JSON."
            ) from exc
        data = yaml.safe_load(raw)
    else:
        data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError(f"config must be a mapping, got {type(data).__name__}")
    return data


# ------------------------------------------------------------------ config -> args
def _resolve_model(model) -> dict | None:
    """Map a friendly alias or full model id to a bedrockModelConfig; None if unset."""
    if not model:
        return None
    if isinstance(model, dict):  # already a bedrockModelConfig-shaped dict
        return model
    alias = {"sonnet": sh.MODEL_SONNET, "haiku": sh.MODEL_HAIKU, "opus": sh.MODEL_OPUS}
    return sh.bedrock_model(alias.get(str(model).lower(), str(model)))


def _build_tool(spec: dict) -> dict:
    """Turn one tool spec dict into a core tool builder result."""
    if not isinstance(spec, dict) or "type" not in spec:
        raise ValueError(f"each tool needs a 'type': {spec!r}")
    t = spec["type"]
    if t == "code_interpreter":
        return sh.tool_code_interpreter(spec.get("name", "code_interpreter"))
    if t == "remote_mcp":
        return sh.tool_remote_mcp(spec["name"], spec["url"], spec.get("headers"))
    if t == "gateway":
        return sh.tool_gateway(spec["name"], spec["gateway_arn"], spec.get("outbound_auth"))
    if t == "inline":
        return sh.tool_inline(spec["name"], spec["description"], spec["input_schema"])
    raise ValueError(f"unknown tool type: {t!r}")


def _build_memory(spec) -> dict | None:
    if not spec:
        return None
    if not isinstance(spec, dict):
        raise ValueError("memory must be a mapping")
    if spec.get("arn"):  # bring-your-own memory
        return sh.byo_memory(spec["arn"], spec.get("retrieval_config"))
    return sh.managed_memory(spec.get("strategies"), spec.get("expiry_days"))


def _config_to_kwargs(cfg: dict) -> tuple[str, str, dict]:
    """Translate a config mapping into (name, system_prompt, create_harness kwargs)."""
    try:
        name = cfg["name"]
        system_prompt = cfg["system_prompt"]
    except KeyError as exc:
        raise ValueError(f"config missing required key: {exc}") from exc

    tools = [_build_tool(s) for s in cfg.get("tools", [])] or None
    kwargs = dict(
        model=_resolve_model(cfg.get("model")),
        tools=tools,
        skills=cfg.get("skills"),
        memory=_build_memory(cfg.get("memory")),
        allowed_tools=cfg.get("allowed_tools"),
        max_iterations=cfg.get("max_iterations"),
        max_tokens=cfg.get("max_tokens"),
        timeout_seconds=cfg.get("timeout_seconds"),
    )
    return name, system_prompt, kwargs


# --------------------------------------------------------------------- commands
def cmd_create(args: argparse.Namespace) -> int:
    # Two accepted schemas:
    #   * the SHIPPED harnesses/<name>/harness.yaml schema (has `harnessName`) —
    #     resolved by the YAML loader (systemPrompt file read, ${ENV} expanded,
    #     inline HITL gates injected).
    #   * the legacy flat schema (has `name` + `system_prompt`) — kept working.
    cfg = _load_config(args.config)
    if "harnessName" in cfg:
        kwargs = load_harness_config(args.config)
        name = kwargs.pop("name")
        system_prompt = kwargs.pop("system_prompt")
    else:
        name, system_prompt, kwargs = _config_to_kwargs(cfg)
    h = sh.create_harness(name, system_prompt, **kwargs)
    hid = h["harnessId"]
    print(f"created harness {name}  id={hid}")
    if not args.no_wait:
        _eprint("waiting for READY ...")
        sh.wait_ready(hid)
        print("status=READY")
    print(json.dumps({"harnessId": hid, "arn": h.get("arn"),
                      "memory": h.get("memory")}, indent=2, default=str))
    return 0


def cmd_invoke(args: argparse.Namespace) -> int:
    session = args.session or sh.new_session("cli")
    _eprint(f"session={session}" + (f"  actor={args.actor}" if args.actor else ""))
    r = sh.invoke(args.harness_arn, session, args.prompt, actor_id=args.actor)
    # Stream the reply text to stdout; diagnostics go to stderr.
    sys.stdout.write(r["text"])
    if r["text"] and not r["text"].endswith("\n"):
        sys.stdout.write("\n")
    sys.stdout.flush()
    _eprint(f"[stop_reason={r['stop_reason']} tools_used={r['tools_used']}]")
    # A stream error is surfaced by core inside the text — treat as failure.
    if any(e in r["events"] for e in
           ("runtimeClientError", "validationException", "internalServerException")):
        _eprint("stream reported an error event")
        return 1
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    harnesses = sh.list_harnesses()
    if args.json:
        print(json.dumps(harnesses, indent=2, default=str))
        return 0
    if not harnesses:
        print("(no harnesses)")
        return 0
    for h in harnesses:
        print(f"{h.get('status', '?'):16} {h.get('harnessName', '?'):32} {h.get('harnessId', '?')}")
    return 0


def cmd_delete(args: argparse.Namespace) -> int:
    sh.delete_harness(args.harness_id, keep_memory=args.keep_memory)
    print(f"deleted {args.harness_id}" + ("  (kept memory)" if args.keep_memory else ""))
    return 0


def cmd_cleanup(args: argparse.Namespace) -> int:
    deleted = sh.cleanup(args.prefix)
    print(f"deleted {len(deleted)} harness(es) with prefix {args.prefix!r}")
    for name in deleted:
        print(f"  - {name}")
    return 0


# scenario name -> module file under scenarios/
_SCENARIOS = {
    "cve_triage": "scenario_cve_triage.py",
    "multi_harness": "scenario_multi_harness.py",
    "detection_gen": "scenario_detection_gen.py",
}


def cmd_run_scenario(args: argparse.Namespace) -> int:
    name = args.name
    if name not in _SCENARIOS:
        _eprint(f"unknown scenario {name!r}. available: {', '.join(sorted(_SCENARIOS))}")
        return 2
    path = os.path.join(SCENARIOS_DIR, _SCENARIOS[name])
    if not os.path.isfile(path):
        _eprint(f"scenario file not found: {path}")
        return 2
    # Each scenario is a self-contained script with a build()/run() flow guarded by
    # its own __main__ block; execute it as __main__ so that block fires.
    import runpy
    runpy.run_path(path, run_name="__main__")
    return 0


# ------------------------------------------------------------------------- parser
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sentinel",
        description="SecOps agents as configuration on Amazon Bedrock AgentCore Harness.",
    )
    p.add_argument("--region", help="override SENTINEL_REGION for this run")
    sub = p.add_subparsers(dest="command", required=True)

    c = sub.add_parser("create", help="create a harness from a yaml/json config file")
    c.add_argument("config", help="path to harness config (.yaml/.yml/.json)")
    c.add_argument("--no-wait", action="store_true", help="do not block until READY")
    c.set_defaults(func=cmd_create)

    i = sub.add_parser("invoke", help="invoke a harness and stream the reply")
    i.add_argument("harness_arn")
    i.add_argument("prompt")
    i.add_argument("--session", help="runtimeSessionId (>=33 chars); auto-generated if omitted")
    i.add_argument("--actor", help="actorId — scopes memory per analyst/tenant")
    i.set_defaults(func=cmd_invoke)

    ls = sub.add_parser("list", help="list harnesses")
    ls.add_argument("--json", action="store_true", help="emit raw JSON")
    ls.set_defaults(func=cmd_list)

    d = sub.add_parser("delete", help="delete a harness by id")
    d.add_argument("harness_id")
    d.add_argument("--keep-memory", action="store_true", help="do not cascade-delete managed memory")
    d.set_defaults(func=cmd_delete)

    cl = sub.add_parser("cleanup", help="delete every harness whose name starts with prefix")
    cl.add_argument("prefix")
    cl.set_defaults(func=cmd_cleanup)

    rs = sub.add_parser("run-scenario", help="run a bundled scenario")
    rs.add_argument("name", choices=sorted(_SCENARIOS), help="scenario to run")
    rs.set_defaults(func=cmd_run_scenario)

    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if getattr(args, "region", None):
        os.environ["SENTINEL_REGION"] = args.region
    try:
        return args.func(args)
    except KeyboardInterrupt:  # pragma: no cover
        _eprint("interrupted")
        return 130
    except Exception as exc:  # noqa: BLE001 — CLI boundary: report and exit non-zero
        _eprint(f"error: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
