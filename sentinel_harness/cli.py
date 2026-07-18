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
    sentinel export   <harness.yaml|name> [-o out.py]     emit editable Strands Agent code (no-lock-in escape hatch)
    sentinel detection audit <dir> [--techniques ..]      offline Sigma rule-library health check (lint+dedup+ATT&CK coverage)
                      [--json] [--navigator [OUT]] [--min-score N]

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
from .exporter import export_harness_to_strands
from .loader import load_harness_config

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCENARIOS_DIR = os.path.join(_REPO_ROOT, "scenarios")
HARNESSES_DIR = os.path.join(_REPO_ROOT, "harnesses")


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
    # An empty/whitespace prefix would match EVERY harness (''.startswith('')==True)
    # and cascade-delete managed memory. Refuse with a clean usage error (exit 2)
    # rather than let it reach the destructive path — the usual trigger is an
    # unset/empty $PREFIX in a script. core.cleanup guards this too (defense in depth).
    if not args.prefix.strip():
        _eprint("cleanup: refusing an empty prefix — it would delete EVERY harness. "
                "Pass a specific non-empty prefix.")
        return 2
    if args.dry_run:
        # Show what WOULD be deleted without touching anything.
        matched = [h.get("harnessName", "?") for h in sh.list_harnesses()
                   if str(h.get("harnessName", "")).startswith(args.prefix)]
        print(f"[dry-run] {len(matched)} harness(es) would be deleted with prefix {args.prefix!r}")
        for name in sorted(matched):
            print(f"  - {name}")
        return 0
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


def _resolve_harness_path(harness: str) -> str:
    """Resolve the export target to a harness.yaml path.

    Accepts a direct path to a ``.yaml``/``.yml`` file, OR a harness name that
    maps to ``harnesses/<name>/harness.yaml`` (the shipped layout). A bare name
    is tried as-is and with common ``sentinel_``/``-``↔``_`` normalizations."""
    # 1) A real file path wins outright.
    if os.path.isfile(harness):
        return harness
    # 2) Otherwise treat it as a harness name under harnesses/<name>/harness.yaml.
    candidates = [harness]
    stripped = harness[len("sentinel_"):] if harness.startswith("sentinel_") else harness
    for base in (stripped, stripped.replace("_", "-"), harness.replace("_", "-")):
        if base not in candidates:
            candidates.append(base)
    for base in candidates:
        candidate = os.path.join(HARNESSES_DIR, base, "harness.yaml")
        if os.path.isfile(candidate):
            return candidate
    raise FileNotFoundError(
        f"could not resolve harness {harness!r} — pass a path to a harness.yaml "
        f"or a name under {HARNESSES_DIR}/<name>/harness.yaml"
    )


def cmd_export(args: argparse.Namespace) -> int:
    """No-lock-in escape hatch: turn a harness config into editable Strands code."""
    path = _resolve_harness_path(args.harness)
    cfg = load_harness_config(path)
    code = export_harness_to_strands(cfg)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(code)
        _eprint(f"wrote Strands Agent code for {cfg.get('name')!r} to {args.out}")
    else:
        sys.stdout.write(code)
        if not code.endswith("\n"):
            sys.stdout.write("\n")
        sys.stdout.flush()
    return 0


TOOLS_DIR = os.path.join(_REPO_ROOT, "tools")


def _load_tool_handler(name: str):
    """Load a ``tools/<name>/handler.py`` module by path (tools/ is a flat scripts
    tree, not an importable package). Returns the module."""
    import importlib.util
    path = os.path.join(TOOLS_DIR, name, "handler.py")
    if not os.path.isfile(path):
        raise FileNotFoundError(f"tool handler not found: {path}")
    spec = importlib.util.spec_from_file_location(f"_cli_tool_{name}", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _collect_sigma_rules(directory: str) -> list:
    """Read every ``.yml``/``.yaml`` file under ``directory`` (recursively) as a
    Sigma rule STRING. Deterministic order (sorted by relative path) so a repeat
    run over the same tree produces the same audit. Skips nothing silently — an
    unreadable file raises so the operator sees it."""
    if not os.path.isdir(directory):
        raise NotADirectoryError(f"not a directory: {directory}")
    paths = []
    for root, _dirs, files in os.walk(directory):
        for fn in files:
            if fn.lower().endswith((".yml", ".yaml")):
                paths.append(os.path.join(root, fn))
    paths.sort()
    rules = []
    for p in paths:
        with open(p, "r", encoding="utf-8") as fh:
            rules.append(fh.read())
    return rules


def cmd_detection_audit(args: argparse.Namespace) -> int:
    """Run the deterministic rule-library health check over a directory of Sigma
    rules. Prints a report (or JSON / a Navigator layer) and — with ``--min-score``
    — exits non-zero when the health score is below the threshold, so it can gate CI."""
    try:
        rules = _collect_sigma_rules(args.directory)
    except (NotADirectoryError, OSError) as exc:
        _eprint(f"detection audit: {exc}")
        return 2
    if not rules:
        _eprint(f"detection audit: no .yml/.yaml Sigma rules found under {args.directory!r}")
        return 2

    techniques = None
    if args.techniques:
        techniques = [t.strip().upper() for t in args.techniques.split(",") if t.strip()]

    audit = _load_tool_handler("detection_audit")
    event = {"rules": rules}
    if techniques is not None:
        event["techniques"] = techniques
    result = audit.handler(event, None)
    if not result.get("ok"):
        _eprint(f"detection audit: {result.get('message', 'audit failed')}")
        return 2

    # --navigator: emit the ATT&CK Navigator layer instead of the text report.
    if args.navigator:
        navtool = _load_tool_handler("detection_navigator")
        nav = navtool.handler(event, None)
        if not nav.get("ok"):
            _eprint(f"detection audit: navigator export failed: {nav.get('message')}")
            return 2
        # --navigator with no value (const '-') means stdout; a value is a file path.
        out_path = None if args.navigator == "-" else args.navigator
        _emit_json(nav["layer"], out_path)
        return 0

    if args.json:
        _emit_json(result, None)
    else:
        _print_audit_report(result)

    # CI gate: fail when the health score is below --min-score.
    if args.min_score is not None and result["health_score"] < args.min_score:
        _eprint(f"detection audit: health_score {result['health_score']} "
                f"< --min-score {args.min_score}")
        return 1
    return 0


def _emit_json(obj, out_path) -> None:
    """Write ``obj`` as pretty JSON to ``out_path`` (a file) or stdout."""
    text = json.dumps(obj, indent=2, ensure_ascii=False)
    if out_path:
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        _eprint(f"wrote {out_path}")
    else:
        sys.stdout.write(text + "\n")
        sys.stdout.flush()


def _print_audit_report(result: dict) -> None:
    """Human-readable rule-library health report."""
    t = result["totals"]
    print(f"Rule-library health: {result['health_score']}/100  "
          f"({result['rule_count']} rule(s))")
    print(f"  invalid={t['invalid_rules']}  duplicates={t['duplicate_pairs']}  "
          f"subsumptions={t['subsumptions']}  overlaps={t['overlaps']}  "
          f"uncovered={t['uncovered_techniques']}  untagged={t['untagged_rules']}  "
          f"invalid_tags={t['invalid_tags']}")
    findings = result.get("findings") or []
    if findings:
        print("Findings (worst first):")
        for f in findings:
            print(f"  {f}")
    else:
        print("No findings — clean.")


def _audit_directory(directory: str, techniques):
    """Collect Sigma rules under ``directory`` and run detection_audit.

    Returns ``(rc, result)``: on a rule-collection/empty/audit error rc is 2 and
    result is None; otherwise rc is 0 and result is the audit dict."""
    try:
        rules = _collect_sigma_rules(directory)
    except (NotADirectoryError, OSError) as exc:
        _eprint(f"detection: {exc}")
        return 2, None
    if not rules:
        _eprint(f"detection: no .yml/.yaml Sigma rules found under {directory!r}")
        return 2, None
    event = {"rules": rules}
    if techniques is not None:
        event["techniques"] = techniques
    result = _load_tool_handler("detection_audit").handler(event, None)
    if not result.get("ok"):
        _eprint(f"detection: {result.get('message', 'audit failed')}")
        return 2, None
    return 0, result


def cmd_detection_baseline(args: argparse.Namespace) -> int:
    """Snapshot or compare a rule-library health baseline (regression gate).

    ``--snapshot OUT`` writes a baseline JSON for DIRECTORY's current audit.
    Otherwise DIRECTORY is compared against ``--against BASELINE`` and the command
    exits non-zero if the library REGRESSED (score drop beyond --allow-score-drop,
    or a new invalid rule / uncovered technique / duplicate pair)."""
    techniques = None
    if args.techniques:
        techniques = [t.strip().upper() for t in args.techniques.split(",") if t.strip()]
    rc, audit = _audit_directory(args.directory, techniques)
    if rc != 0:
        return rc

    baseline_tool = _load_tool_handler("detection_baseline")

    if args.snapshot is not None:
        snap = baseline_tool.handler({"mode": "snapshot", "audit": audit}, None)
        if not snap.get("ok"):
            _eprint(f"detection baseline: {snap.get('message')}")
            return 2
        out = None if args.snapshot == "-" else args.snapshot
        _emit_json(snap["baseline"], out)
        return 0

    # compare mode requires --against
    if not args.against:
        _eprint("detection baseline: pass --snapshot OUT to create a baseline, or "
                "--against BASELINE to compare against one")
        return 2
    try:
        with open(args.against, "r", encoding="utf-8") as fh:
            baseline = json.load(fh)
    except (OSError, ValueError) as exc:
        _eprint(f"detection baseline: could not read baseline {args.against!r}: {exc}")
        return 2
    cmp = baseline_tool.handler({
        "mode": "compare", "audit": audit, "baseline": baseline,
        "allow_score_drop": args.allow_score_drop,
    }, None)
    if not cmp.get("ok"):
        _eprint(f"detection baseline: {cmp.get('message')}")
        return 2

    if args.json:
        _emit_json(cmp, None)
    else:
        print(f"Baseline compare: health {cmp['baseline']['health_score']} -> "
              f"{cmp['current']['health_score']} (delta {cmp['health_delta']})")
        for imp in cmp["improvements"]:
            print(f"  + {imp}")
        for r in cmp["reasons"]:
            print(f"  ! {r}")
        print("REGRESSED" if cmp["regressed"] else "OK (no regression)")
    return 1 if cmp["regressed"] else 0


def cmd_detection_ci(args: argparse.Namespace) -> int:
    """One-shot detection-library CI gate: audit + (optional) baseline regression
    compare + (optional) Navigator layer export, with a SINGLE combined exit code.

    Exits non-zero (1) if EITHER gate fails — health_score below ``--min-score`` OR
    a regression vs ``--against`` — so a pipeline can run one command. Exit 2 on bad
    input. Prints a combined report; ``--json`` emits a machine-readable summary."""
    techniques = None
    if args.techniques:
        techniques = [t.strip().upper() for t in args.techniques.split(",") if t.strip()]
    rc, audit = _audit_directory(args.directory, techniques)
    if rc != 0:
        return rc

    gate_failures: list = []

    # --- min-score gate ---
    score = audit["health_score"]
    if args.min_score is not None and score < args.min_score:
        gate_failures.append(f"health_score {score} < --min-score {args.min_score}")

    # --- regression gate (optional) ---
    compare = None
    if args.against:
        try:
            with open(args.against, "r", encoding="utf-8") as fh:
                baseline = json.load(fh)
        except (OSError, ValueError) as exc:
            _eprint(f"detection ci: could not read baseline {args.against!r}: {exc}")
            return 2
        compare = _load_tool_handler("detection_baseline").handler({
            "mode": "compare", "audit": audit, "baseline": baseline,
            "allow_score_drop": args.allow_score_drop,
        }, None)
        if not compare.get("ok"):
            _eprint(f"detection ci: {compare.get('message')}")
            return 2
        if compare["regressed"]:
            gate_failures.append("regressed vs baseline: " + "; ".join(compare["reasons"]))

    # --- Navigator export (optional side-effect; never affects the gate) ---
    if args.navigator_out:
        nav_event = {"rules": _collect_sigma_rules(args.directory)}
        if techniques is not None:
            nav_event["techniques"] = techniques
        nav = _load_tool_handler("detection_navigator").handler(nav_event, None)
        if nav.get("ok"):
            _emit_json(nav["layer"], args.navigator_out)
        else:
            _eprint(f"detection ci: navigator export skipped: {nav.get('message')}")

    passed = not gate_failures
    if args.json:
        _emit_json({
            "ok": True, "passed": passed, "health_score": score,
            "totals": audit["totals"], "gate_failures": gate_failures,
            "compare": compare,
        }, None)
    else:
        _print_audit_report(audit)
        if compare is not None:
            print(f"Baseline: health {compare['baseline']['health_score']} -> "
                  f"{score} (delta {compare['health_delta']})")
            for r in compare["reasons"]:
                print(f"  ! {r}")
        if gate_failures:
            print("CI GATE: FAIL")
            for g in gate_failures:
                print(f"  - {g}")
        else:
            print("CI GATE: PASS")
    return 0 if passed else 1


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
    cl.add_argument("--dry-run", action="store_true",
                    help="list the harnesses that WOULD be deleted, delete nothing")
    cl.set_defaults(func=cmd_cleanup)

    rs = sub.add_parser("run-scenario", help="run a bundled scenario")
    rs.add_argument("name", choices=sorted(_SCENARIOS), help="scenario to run")
    rs.set_defaults(func=cmd_run_scenario)

    ex = sub.add_parser(
        "export",
        help="emit editable Strands Agent code from a harness config (NO-LOCK-IN escape hatch)",
        description=(
            "No-lock-in escape hatch. Read a shipped harness config "
            "(harnesses/<name>/harness.yaml, given as a path OR a harness name) and "
            "EMIT editable Strands Agent Python — model id, system prompt, tool "
            "allowlist, and a memory note — a starting point to run the same agent on "
            "AgentCore Runtime or self-hosted, off the managed harness. The output is "
            "a text code artifact; running it later needs `strands-agents`, but this "
            "command does not."
        ),
    )
    ex.add_argument("harness", help="path to a harness.yaml OR a harness name under harnesses/")
    ex.add_argument("-o", "--out", help="write code to this file (default: stdout)")
    ex.set_defaults(func=cmd_export)

    # `sentinel detection audit <dir>` — deterministic, offline rule-library health
    # check over a directory of Sigma rules (lint + dedup + coverage aggregated).
    det = sub.add_parser("detection", help="deterministic detection-engineering tools (offline)")
    det_sub = det.add_subparsers(dest="detection_command", required=True)
    da = det_sub.add_parser(
        "audit",
        help="health-check a directory of Sigma rules (lint + dedup + ATT&CK coverage)",
        description=(
            "Run the deterministic, offline detection-library health check over every "
            ".yml/.yaml Sigma rule under DIRECTORY: aggregates sigma_yara_lint + "
            "detection_dedup + detection_coverage into a 0-100 health score and a "
            "prioritized findings list. Use --techniques to score ATT&CK coverage, "
            "--navigator to export a Navigator layer, and --min-score to gate CI."
        ),
    )
    da.add_argument("directory", help="directory of Sigma rule files (.yml/.yaml, recursive)")
    da.add_argument("--techniques",
                    help="comma-separated target ATT&CK technique ids (e.g. T1059,T1190.001)")
    da.add_argument("--json", action="store_true", help="emit the raw audit JSON")
    da.add_argument("--navigator", nargs="?", const="-", metavar="OUT",
                    help="emit an ATT&CK Navigator layer JSON (to OUT file, or stdout)")
    da.add_argument("--min-score", type=int, metavar="N",
                    help="exit non-zero if health_score < N (CI gate)")
    da.set_defaults(func=cmd_detection_audit)

    # `sentinel detection baseline <dir>` — regression gate: snapshot a health
    # baseline, or compare against one and fail on degradation.
    db = det_sub.add_parser(
        "baseline",
        help="snapshot or compare a rule-library health baseline (regression gate)",
        description=(
            "Snapshot DIRECTORY's current detection_audit health as a baseline "
            "(--snapshot OUT), or compare DIRECTORY against a saved baseline "
            "(--against BASELINE) and exit non-zero if the library REGRESSED (health "
            "drop beyond --allow-score-drop, or a new invalid rule / uncovered "
            "technique / duplicate pair). Deterministic; offline."
        ),
    )
    db.add_argument("directory", help="directory of Sigma rule files (.yml/.yaml, recursive)")
    db.add_argument("--techniques",
                    help="comma-separated target ATT&CK technique ids (must match the baseline's)")
    db.add_argument("--snapshot", nargs="?", const="-", metavar="OUT",
                    help="write a baseline snapshot (to OUT file, or stdout) instead of comparing")
    db.add_argument("--against", metavar="BASELINE",
                    help="compare against this baseline JSON file (created by --snapshot)")
    db.add_argument("--allow-score-drop", type=int, default=0, metavar="N",
                    help="tolerate a health-score decrease of up to N (default 0)")
    db.add_argument("--json", action="store_true", help="emit the raw compare JSON")
    db.set_defaults(func=cmd_detection_baseline)

    # `sentinel detection ci <dir>` — one-shot gate: audit + optional baseline
    # regression compare + optional Navigator export, one combined exit code.
    dc = det_sub.add_parser(
        "ci",
        help="one-shot CI gate: audit + baseline regression + navigator export",
        description=(
            "Run the whole detection suite as ONE CI gate over DIRECTORY: audit "
            "(lint + dedup + ATT&CK coverage), optionally compare against a baseline "
            "(--against) for regressions, and optionally export a Navigator layer "
            "(--navigator-out). Exits non-zero if health_score < --min-score OR a "
            "regression is detected — a single command for a pipeline step."
        ),
    )
    dc.add_argument("directory", help="directory of Sigma rule files (.yml/.yaml, recursive)")
    dc.add_argument("--techniques",
                    help="comma-separated target ATT&CK technique ids to score coverage")
    dc.add_argument("--min-score", type=int, metavar="N",
                    help="fail if health_score < N")
    dc.add_argument("--against", metavar="BASELINE",
                    help="also fail if regressed vs this baseline JSON (from `baseline --snapshot`)")
    dc.add_argument("--allow-score-drop", type=int, default=0, metavar="N",
                    help="tolerate a health-score decrease of up to N in the regression check")
    dc.add_argument("--navigator-out", metavar="OUT",
                    help="also write an ATT&CK Navigator layer JSON to OUT (does not affect the gate)")
    dc.add_argument("--json", action="store_true", help="emit a machine-readable gate summary")
    dc.set_defaults(func=cmd_detection_ci)

    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if getattr(args, "region", None):
        # Rebind the boto3 clients (constructed at import from SENTINEL_REGION), not
        # just the env var — otherwise --region would be a silent no-op for this run.
        sh.set_region(args.region)
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
