"""
adversarial-reviewer · A2A specialist Runtime (reference skeleton + real reasoning)
===================================================================================
A narrow **specialist** agent that a supervisor harness delegates to over A2A
(agent-to-agent). It mirrors ``specialists/cve-intel`` / ``specialists/attack-mapper``
exactly for the serving skeleton (guarded strands/a2a imports, an ``agent_card()``,
``build_agent()`` / ``build_app()`` / ``serve()``), and adds the piece that makes
this specialist *useful*: a REAL, deterministic, LLM-free critique reasoner
(:func:`review_detection`) that, given a generated detection rule / artifact,
returns a structured adversarial verdict
``{verdict: approve|revise, objections: [...], fp_risk, logic_flaws}``.

Why this specialist exists — generation != evaluation
-----------------------------------------------------
The ``detection-eng`` harness (``harnesses/detection-eng/harness.yaml``) *generates*
a Sigma/YARA rule and then delegates the *evaluation* to THIS specialist over the
Gateway (``@gateway/invoke_specialist``). Keeping the reviewer in its own microVM,
reached by A2A, is the structural guarantee that the thing being reviewed and the
thing doing the reviewing are NOT the same agent — no self-approval bias. The
reviewer's job is to *attack* the artifact: surface false-positive sources, logic
gaps, and unsupported claims, and withhold approval until they are addressed. A
human ``request_publish_approval`` inline_function gate is still the only path to
production; this specialist never publishes anything.

What is real vs. skeleton vs. advisory
--------------------------------------
- **REAL** — :func:`review_detection` is pure-python static analysis of a rule:
  same rule in, same verdict out. No LLM, no network, no tokens. Fully
  unit-testable offline. It is intentionally *conservative* (adversarial): any
  objection or logic flaw blocks approval, mirroring a skeptical human reviewer.
- **SKELETON** — the A2A serving wrapper (``build_agent`` / ``build_app`` /
  ``serve``) is the guarded skeleton: heavy deps imported lazily so the module
  (and its agent-card, and the reasoner) is importable and testable without the
  specialist stack installed.
- **ADVISORY / NON-AUTHORITATIVE** — this specialist only *critiques*. It never
  publishes, edits, or greenlights a rule into production; a human publish gate
  downstream owns that decision. An ``approve`` verdict is a recommendation, not
  a deployment.

Why LiteLLM here (and not on the supervisor)
--------------------------------------------
The supervisor is a config-only Bedrock **Harness** (Bedrock-model-only). A
specialist runs in its *own* Runtime microVM, so it can use ``LiteLLMModel`` to
reach a cheaper/narrower model. See BLUEPRINT §0 "Harness is Bedrock-model-only".

Why the imports are guarded
---------------------------
``strands`` / ``strands-agents[a2a,litellm]`` / ``bedrock-agentcore`` are heavy,
platform-specific runtime deps that are NOT needed to *inspect* or test the
skeleton (agent-card shape, capability metadata, the ``build_agent`` factory
contract) or to run the deterministic reasoner. They are imported lazily inside
the factory so this module is always importable — CI stays green without the
specialist stack installed. The real deps are only touched when you actually
``build_agent()`` / ``serve()`` inside the container.

Configuration (12-factor — no hardcoded account / ARN / model)
--------------------------------------------------------------
    export SENTINEL_SPECIALIST_MODEL="bedrock/global.anthropic.claude-haiku-4-5-20251001-v1:0"
    export SENTINEL_GATEWAY_URL="https://<gateway-id>.gateway.bedrock-agentcore.<region>.amazonaws.com/mcp"
    export SENTINEL_A2A_HOST="0.0.0.0"      # optional, default 0.0.0.0
    export SENTINEL_A2A_PORT="9000"         # optional, default 9000

Nothing in this file is customer- or company-specific.
"""
from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Tuple, Union

# --- Specialist identity -----------------------------------------------------
# The Registry entry and the A2A agent-card are both derived from these, so a
# supervisor can discover this specialist by *capability* (search_registry) and
# then address it by name (invoke_specialist). Keep names skill-based, not
# person- or org-based.
SPECIALIST_NAME = "adversarial-reviewer"
SPECIALIST_VERSION = "0.1.0"
SPECIALIST_DESCRIPTION = (
    "Adversarial detection-review specialist. Given a generated detection rule or "
    "artifact (Sigma/YARA), it ATTACKS the artifact and returns a structured "
    "critique verdict: approve|revise, the concrete objections (false-positive "
    "sources, over-broad selections, missing scoping), an fp_risk rating, and any "
    "logic flaws (e.g. a condition referencing an undefined selection). It is the "
    "independent reviewer that keeps generation != evaluation — it never authors, "
    "publishes, or self-approves a rule; a human publish gate owns production."
)

# LiteLLM model id. Provider-prefixed (``bedrock/...``, ``openai/...``, etc.) so a
# specialist can run a cheaper/narrower model than the supervisor. Read from env
# (12-factor); the default is a small Bedrock model routed through LiteLLM. Pinned
# with a full version suffix (matches cve-intel) so a container cannot ship a
# silently-broken bare model id.
DEFAULT_MODEL_ID = os.environ.get(
    "SENTINEL_SPECIALIST_MODEL", "bedrock/global.anthropic.claude-haiku-4-5-20251001-v1:0"
)

# The Gateway MCP endpoint this specialist pulls its tools from (sigma_yara_lint /
# attack_lookup). Optional at import time; required to actually build.
GATEWAY_URL = os.environ.get("SENTINEL_GATEWAY_URL")

DEFAULT_HOST = os.environ.get("SENTINEL_A2A_HOST", "0.0.0.0")
DEFAULT_PORT = int(os.environ.get("SENTINEL_A2A_PORT", "9000"))

# System prompt: narrow, adversarial, structured output. A specialist does ONE
# thing well and returns a machine-parseable envelope. The LLM's job is
# orchestration + explanation; the VERDICT itself comes from the deterministic
# review_detection reasoner, not from model intuition (so a supervisor cannot
# talk the reviewer into approving a bad rule).
SYSTEM_PROMPT = """\
You are the adversarial-reviewer specialist. You answer exactly one kind of \
question: given a generated detection rule / artifact, ATTACK it and return a \
structured review verdict. You are the independent adversary — you did NOT write \
this rule and you must NOT approve it out of politeness.

Rules:
- Call the review_detection reasoner to compute objections, fp_risk, and logic \
  flaws; use sigma_yara_lint to confirm the rule parses and attack_lookup to \
  check any claimed MITRE ATT&CK mapping. NEVER invent an approval, downgrade a \
  real objection, or re-score the verdict by intuition — the decision is \
  deterministic and lives in the reasoner.
- Withhold approval whenever there is any objection or logic flaw. Your job is to \
  find what the generator missed, not to rubber-stamp it.
- You never publish, edit, or deploy a rule. An `approve` verdict is a \
  recommendation only; a human publish gate owns production.
- Do not answer questions outside detection review; a supervisor routes those \
  elsewhere.

Return a single JSON object:
{"artifact_kind": str, "verdict": "approve"|"revise", \
 "objections": [{"code": str, "severity": str, "detail": str}], \
 "fp_risk": "low"|"medium"|"high", "logic_flaws": [str], \
 "summary": str, "grounded": bool}
`grounded` is true only if the verdict came from the deterministic reasoner over \
the provided artifact (never a confabulated approval).
"""

# Capabilities advertised to the Registry / A2A discovery. Each is a coarse
# capability label a supervisor matches against when it decomposes a task
# (search_registry filters on these). Keep them stable — they are part of the
# discovery contract.
CAPABILITIES: Tuple[str, ...] = (
    "detection.review",
    "detection.adversarial_review",
    "rule.critique",
    "falsepositive.analysis",
    "review.verdict",
)

# Tool names this specialist expects on the Gateway. Mirrors registry/tools.yaml;
# the supervisor never calls these directly — it delegates the whole subtask. The
# reviewer uses the deterministic linter to confirm syntax and attack_lookup to
# validate any claimed technique mapping.
GATEWAY_TOOLS: Tuple[str, ...] = ("sigma_yara_lint", "attack_lookup")


# ==========================================================================
# REAL deterministic critique reasoner (no LLM, no network, no tokens).
# This is the provable core the agent/tool reasons WITH; it is intentionally
# separable and unit-testable without any of the serving stack. It is
# adversarial by construction: any objection or logic flaw blocks approval.
# ==========================================================================

# Reserved words in a Sigma ``condition`` expression. Every OTHER bareword in a
# condition is an identifier that MUST be defined as a selection/filter block in
# the detection map — an undefined reference is a logic flaw (the rule matches
# nothing or errors at load). ``them``/``all``/``of``/``1`` are aggregation
# keywords; ``and``/``or``/``not`` are boolean operators.
_CONDITION_KEYWORDS = {"and", "or", "not", "of", "them", "all"}

# A lone wildcard value (``'*'`` / ``"*"`` / ``*``) makes a selection match every
# event — the single most common way a generated rule becomes an alert cannon.
# Detected as a high-severity objection driving fp_risk high. Two forms must match:
#   - inline scalar: ``CommandLine: '*'``  (colon then wildcard)
#   - YAML list item: ``  - '*'`` / the ``- *`` a dict artifact renders for a
#     single-element wildcard list (``CommandLine: ['*']``) — semantically identical
#     to the scalar, so the earlier colon-only regex was a false-negative.
_LONE_WILDCARD_RE = re.compile(
    r"""(?m)(?::\s*['"]?\*['"]?\s*$|^\s*-\s*['"]?\*['"]?\s*$)"""
)

# A detection-map identifier key line, e.g. ``    selection:`` or ``  filter_x:``.
# Used to know which condition identifiers are actually defined.
_IDENT_KEY_RE = re.compile(r"(?m)^\s+([A-Za-z_][A-Za-z0-9_]*)\s*:")


def _artifact_to_text(obj: Any, indent: int = 0) -> str:
    """Render a dict/list artifact into indented YAML-ish text.

    WHY: the static analysis below scans text (``title:``, ``condition:``,
    identifier key lines). Accepting a *parsed* artifact (a dict, e.g. from a
    generator that already emitted structured JSON) and flattening it through the
    same renderer means both a raw-YAML string and a structured artifact take the
    exact same, deterministic analysis path — no second code path to drift.
    """
    pad = "    " * indent
    lines: List[str] = []
    if isinstance(obj, dict):
        for key, val in obj.items():
            if isinstance(val, (dict, list)):
                lines.append(f"{pad}{key}:")
                lines.append(_artifact_to_text(val, indent + 1))
            else:
                lines.append(f"{pad}{key}: {val}")
    elif isinstance(obj, list):
        for item in obj:
            if isinstance(item, (dict, list)):
                lines.append(_artifact_to_text(item, indent + 1))
            else:
                lines.append(f"{pad}- {item}")
    else:
        lines.append(f"{pad}{obj}")
    return "\n".join(ln for ln in lines if ln)


def _normalize_rule(rule: Union[str, Dict[str, Any]]) -> str:
    """Coerce the reviewed artifact into a single text blob for analysis.

    Raises ``ValueError`` on empty / wrong-typed input — the reviewer refuses to
    fabricate a verdict for a nonexistent artifact (honesty over a false approve).
    """
    if isinstance(rule, dict):
        text = _artifact_to_text(rule)
    elif isinstance(rule, str):
        text = rule
    else:
        raise ValueError("rule must be a Sigma/YARA string or a parsed dict artifact")
    if not text.strip():
        raise ValueError("empty artifact; nothing to review")
    return text


def _condition_line(low: str) -> str | None:
    """Return the text AFTER the first ``condition:`` marker, lower-cased, or
    ``None`` when the rule declares no condition at all."""
    for line in low.splitlines():
        stripped = line.strip()
        if stripped.startswith("condition:"):
            return stripped.split("condition:", 1)[1].strip()
    return None


def _defined_identifiers(text: str) -> set:
    """Set of detection-map identifier keys defined in the rule (selection/filter
    block names), so a condition reference can be checked for definedness.

    Top-level Sigma keys (``title``/``logsource``/``detection``/``condition``/...)
    are excluded — a condition never references those.
    """
    reserved_keys = {
        "title", "id", "status", "description", "author", "date", "modified",
        "references", "tags", "logsource", "detection", "condition", "level",
        "falsepositives", "fields", "category", "product", "service",
    }
    return {
        m.group(1).lower()
        for m in _IDENT_KEY_RE.finditer(text)
        if m.group(1).lower() not in reserved_keys
    }


def review_detection(
    rule: Union[str, Dict[str, Any]], *, artifact_kind: str = "sigma"
) -> Dict[str, Any]:
    """Adversarially review a generated detection rule / artifact.

    This is the REAL reasoning core — pure, deterministic static analysis with no
    LLM and no network. Same ``rule`` always yields the same verdict.

    It is intentionally *conservative*: it withholds approval on ANY objection or
    logic flaw, mirroring a skeptical human reviewer whose job is to find what the
    generator missed. This is what makes the reviewer an adversary rather than a
    rubber stamp.

    Checks (each a distinct, auditable objection ``code``):
      - ``missing_title`` / ``missing_logsource`` / ``missing_level`` — the rule
        is not self-describing enough to triage or route (low/medium severity).
      - ``missing_condition`` — no ``condition:`` at all: the rule matches nothing
        or everything depending on the backend (high severity).
      - ``broad_selection`` — a lone-wildcard value (``'*'``) makes the selection
        fire on every event (high severity; the classic alert cannon).
      - ``no_fp_scoping`` — neither an exclusion filter (``and not <filter>``) nor
        documented ``falsepositives:`` — the rule has no false-positive story at
        all (high severity).
      - ``missing_fp_docs`` — a filter exists but ``falsepositives:`` are not
        documented (low severity; hygiene, not a blocker on its own).

    Logic flaws (each a human-readable string):
      - a ``condition`` that references a selection/filter identifier which is
        never defined in the detection map — the rule cannot match as written.

    ``fp_risk`` is ``high`` if any breadth/scoping objection fired, ``medium`` if
    only documentation is missing, else ``low``. ``verdict`` is ``revise`` if
    there is ANY objection or logic flaw, else ``approve``.

    Returns::

        {"artifact_kind": str, "verdict": "approve"|"revise",
         "objections": [{"code": str, "severity": str, "detail": str}],
         "fp_risk": "low"|"medium"|"high", "logic_flaws": [str],
         "rationale": str}

    Raises ``ValueError`` on an empty / wrong-typed artifact — we never silently
    approve a nonexistent rule.
    """
    text = _normalize_rule(rule)
    low = text.lower()

    objections: List[Dict[str, str]] = []

    def _object(code: str, severity: str, detail: str) -> None:
        objections.append({"code": code, "severity": severity, "detail": detail})

    # --- Self-describing metadata --------------------------------------------
    if "title:" not in low:
        _object("missing_title", "medium",
                "rule has no title; an analyst cannot triage or route an alert with no name.")
    if "logsource" not in low:
        _object("missing_logsource", "medium",
                "rule has no logsource; it is ambiguous which telemetry this even applies to.")
    if "level:" not in low:
        _object("missing_level", "low",
                "rule has no severity level; downstream routing/SLAs cannot be assigned.")

    # --- Condition presence + breadth ----------------------------------------
    condition = _condition_line(low)
    # An EMPTY/whitespace condition is functionally identical to a missing one (it
    # matches nothing or everything depending on the backend) — `_condition_line`
    # returns '' for a bare `condition:` marker, so guard on falsy, not `is None`,
    # or the high-severity objection is silently skipped (audited bypass).
    if not (condition or "").strip():
        _object("missing_condition", "high",
                "rule declares no condition; depending on the backend it matches nothing "
                "or every event — either way it is not a usable detection.")

    if _LONE_WILDCARD_RE.search(text):
        _object("broad_selection", "high",
                "a selection matches on a lone wildcard ('*'); this fires on effectively "
                "every event and will bury the SOC in false positives.")

    # --- False-positive scoping ----------------------------------------------
    has_filter = ("and not " in low) or ("not filter" in low)
    documents_fp = "falsepositive" in low
    if not has_filter and not documents_fp:
        _object("no_fp_scoping", "high",
                "no exclusion filter (e.g. 'and not filter') and no documented "
                "falsepositives; the rule has no false-positive story and is not "
                "safe to publish as-is.")
    elif not documents_fp:
        _object("missing_fp_docs", "low",
                "an exclusion filter exists but known false positives are not documented; "
                "add a 'falsepositives:' block so responders know what benign activity "
                "this can still trip on.")

    # --- Logic flaws: condition references an undefined identifier ------------
    logic_flaws: List[str] = []
    if (condition or "").strip():
        defined = _defined_identifiers(text)
        # Capture an optional trailing '*' so a Sigma glob reference ('selection*')
        # is extracted WHOLE — otherwise the '*' is dropped and a legitimate glob
        # looks like a bare 'selection' typo.
        referenced = [
            tok for tok in re.findall(r"[a-zA-Z_][a-zA-Z0-9_]*\*?", condition)
            if tok.rstrip("*") not in _CONDITION_KEYWORDS
        ]
        for ident in referenced:
            # Prefix/glob matching applies ONLY when the identifier is actually a
            # Sigma glob (ends with '*', e.g. 'selection*'); a plain identifier must
            # match a defined id EXACTLY. Treating every ident as a prefix meant a
            # typo like 'sel' (a prefix of 'selection') was silently accepted, so a
            # broken condition got APPROVE (audited false-negative).
            is_glob = ident.endswith("*")
            stem = ident.rstrip("*")
            if is_glob:
                ok = any(d == stem or d.startswith(stem) for d in defined)
            else:
                ok = ident in defined
            if ok:
                continue
            logic_flaws.append(
                f"condition references '{ident}', which is not defined as a "
                f"selection/filter in the detection map; the rule cannot match as written."
            )

    # --- Aggregate: fp_risk + verdict ----------------------------------------
    high_fp = any(o["code"] in {"broad_selection", "no_fp_scoping", "missing_condition"}
                  for o in objections)
    med_fp = any(o["code"] == "missing_fp_docs" for o in objections)
    fp_risk = "high" if high_fp else ("medium" if med_fp else "low")

    verdict = "revise" if (objections or logic_flaws) else "approve"

    if verdict == "approve":
        rationale = (
            "No objections or logic flaws found; the rule is self-describing, scoped "
            "against false positives, and its condition references only defined "
            "selections. Approval is a recommendation — a human publish gate still owns "
            "production."
        )
    else:
        rationale = (
            f"Withholding approval: {len(objections)} objection(s) and "
            f"{len(logic_flaws)} logic flaw(s) found (fp_risk={fp_risk}). The generator "
            f"must address these before this rule is fit to publish."
        )

    return {
        "artifact_kind": artifact_kind,
        "verdict": verdict,
        "objections": objections,
        "fp_risk": fp_risk,
        "logic_flaws": logic_flaws,
        "rationale": rationale,
    }


# ==========================================================================
# A2A serving skeleton (mirrors specialists/cve-intel exactly).
# ==========================================================================


def agent_card(
    *,
    name: str = SPECIALIST_NAME,
    version: str = SPECIALIST_VERSION,
    description: str = SPECIALIST_DESCRIPTION,
    url: str | None = None,
) -> dict:
    """Build the self-describing A2A agent-card.

    This is the metadata a specialist publishes so a supervisor can *discover* it
    by capability (via ``search_registry``) and address it (via
    ``invoke_specialist``) without any code change to the supervisor. It is pure
    data — no network, no heavy deps — so it is fully testable offline and is the
    single source of truth for both the A2A card and the Registry entry.

    ``url`` is the A2A endpoint; left ``None`` at build time it is resolved from
    the runtime environment when the server actually binds.
    """
    return {
        "name": name,
        "version": version,
        "description": description,
        "url": url,
        # A2A protocol/transport this card speaks. JSON-RPC message/send is the
        # A2A default the invoke_specialist wrapper targets.
        "protocol": "a2a",
        "capabilities": list(CAPABILITIES),
        # Skills is the A2A-native list-of-capability shape; we mirror CAPABILITIES
        # into it so either discovery convention works against this card.
        "skills": [
            {"id": cap, "name": cap, "description": f"{description}"}
            for cap in CAPABILITIES
        ],
        "defaultInputModes": ["text"],
        "defaultOutputModes": ["text"],
        # Non-authoritative hints for operators / the Registry seeder. The live
        # model/tool wiring is resolved from env at build time, not pinned here.
        "metadata": {
            "modelHint": DEFAULT_MODEL_ID,
            "gatewayTools": list(GATEWAY_TOOLS),
        },
    }


def _load_gateway_tools(gateway_url: str | None):
    """Return the MCP tools this specialist should be given.

    Isolated so tests can monkeypatch it (the real path hits an MCP client over
    the network, which we never do offline). Returns an empty list when no
    Gateway URL is configured — a valid state for a skeleton / smoke run where the
    agent is exercised with no tools. We never swallow a *misconfigured* URL: an
    explicitly set but unreachable Gateway surfaces as an MCP client error at
    build time rather than being silently dropped.
    """
    if not gateway_url:
        return []
    # Imported lazily: the MCP client is a heavy runtime-only dependency.
    from mcp.client.streamable_http import streamablehttp_client  # type: ignore
    from strands.tools.mcp import MCPClient  # type: ignore

    client = MCPClient(lambda: streamablehttp_client(gateway_url))
    client.start()
    return client.list_tools_sync()


def build_agent(
    *,
    model_id: str | None = None,
    gateway_url: str | None = None,
    system_prompt: str = SYSTEM_PROMPT,
):
    """Factory: construct the Strands ``Agent`` for this specialist.

    Heavy deps (``strands``, ``litellm``) are imported HERE, not at module top,
    so importing this module never requires the specialist stack. Call this only
    inside the container (or a test with the deps installed / stubbed).

    Returns the constructed ``Agent``. The A2A wrapping happens in :func:`serve`;
    keeping construction separate makes the agent unit-testable without binding a
    socket.
    """
    from strands import Agent  # type: ignore
    from strands.models.litellm import LiteLLMModel  # type: ignore

    model = LiteLLMModel(model_id=model_id or DEFAULT_MODEL_ID)
    tools = _load_gateway_tools(gateway_url if gateway_url is not None else GATEWAY_URL)
    return Agent(
        model=model,
        system_prompt=system_prompt,
        tools=tools,
        name=SPECIALIST_NAME,
        description=SPECIALIST_DESCRIPTION,
    )


def build_app(
    *,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    agent=None,
):
    """Wrap the agent in an ``A2AServer`` and mount a FastAPI ``/ping`` health
    endpoint (the AgentCore Runtime liveness contract).

    Returns the FastAPI ``app`` so a container CMD can hand it to uvicorn. Heavy
    deps imported lazily for the same reason as :func:`build_agent`.
    """
    from fastapi import FastAPI  # type: ignore
    from strands.multiagent.a2a import A2AServer  # type: ignore

    agent = agent or build_agent()
    # A2AServer serves the JSON-RPC message/send surface + publishes the card at
    # /.well-known/agent-card.json. We give it the same card we register.
    a2a = A2AServer(agent=agent, host=host, port=port)
    app = a2a.to_fastapi_app() if hasattr(a2a, "to_fastapi_app") else FastAPI()

    @app.get("/ping")  # nosemgrep: useless-inner-function -- not dead code; registered as a route via @app.get decorator (side effect), called by the ASGI server
    def ping() -> dict:
        # AgentCore polls this for liveness; keep it dependency-free and fast.
        return {"status": "healthy", "agent": SPECIALIST_NAME}

    return app


def serve(*, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> None:
    """Bind the A2A server (blocking). Container entrypoint."""
    import uvicorn  # type: ignore

    uvicorn.run(build_app(host=host, port=port), host=host, port=port)


if __name__ == "__main__":  # pragma: no cover - container entrypoint
    serve()
