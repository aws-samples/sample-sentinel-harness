"""
attack-mapper · A2A specialist Runtime (reference skeleton + real reasoning)
============================================================================
A narrow **specialist** agent that a supervisor harness delegates to over A2A
(agent-to-agent). It mirrors ``specialists/cve-intel`` exactly for the serving
skeleton (guarded strands/a2a imports, an ``agent_card()``, ``build_agent()`` /
``build_app()`` / ``serve()``), and adds the piece that makes this specialist
*useful*: a REAL, deterministic, LLM-free attack-path reasoner
(:func:`build_attack_paths`) that turns an exposure surface (from the
``asset_lookup`` tool) into ranked high-risk attack chains.

What is real vs. skeleton vs. simulated
---------------------------------------
- **REAL** — :func:`build_attack_paths` is pure-python graph reasoning: it finds
  entry nodes (internet-exposed AND carrying a known-vulnerable service),
  traverses trust edges, and ranks the resulting chains by exploitability and
  impact. Same surface in, same ranked chains out. No LLM, no network, no tokens.
  It is fully unit-testable offline.
- **SKELETON** — the A2A serving wrapper (``build_agent`` / ``build_app`` /
  ``serve``) is the guarded skeleton: heavy deps imported lazily so the module
  (and its agent-card, and the reasoner) is importable and testable without the
  specialist stack installed.
- **SIMULATED / NON-OFFENSIVE** — this specialist only *reasons about* attack
  paths from asset metadata. It performs NO exploitation, NO scanning, NO live
  network activity. Any downstream validation of a chain stays HITL-gated behind
  the existing Play Mode (``sentinel_harness/simulation.py``); detonation of a
  sample is a separate SIMULATED one-shot-microVM skeleton. Nothing here touches
  a real target.

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
from typing import Any, Dict, List, Optional, Tuple

# --- Specialist identity -----------------------------------------------------
# The Registry entry and the A2A agent-card are both derived from these, so a
# supervisor can discover this specialist by *capability* (search_registry) and
# then address it by name (invoke_specialist). Keep names skill-based, not
# person- or org-based.
SPECIALIST_NAME = "attack-mapper"
SPECIALIST_VERSION = "0.1.0"
SPECIALIST_DESCRIPTION = (
    "Attack-path reasoning specialist. Given an exposure surface (hosts, "
    "exposed services with known-vulnerability flags, and trust edges), returns "
    "ranked high-risk attack chains: entry via an internet-exposed known-vuln "
    "node, traversal across trust edges to high-impact targets, scored by "
    "exploitability and impact. Reasons only over asset metadata — it never "
    "exploits, scans, or touches a live target; downstream validation stays "
    "HITL-gated behind Play Mode."
)

# LiteLLM model id. Provider-prefixed (``bedrock/...``, ``openai/...``, etc.) so a
# specialist can run a cheaper/narrower model than the supervisor. Read from env
# (12-factor); the default is a small Bedrock model routed through LiteLLM.
DEFAULT_MODEL_ID = os.environ.get(
    "SENTINEL_SPECIALIST_MODEL", "bedrock/global.anthropic.claude-haiku-4-5-20251001-v1:0"
)

# The Gateway MCP endpoint this specialist pulls its tools from (asset_lookup /
# attack_lookup). Optional at import time; required to actually build.
GATEWAY_URL = os.environ.get("SENTINEL_GATEWAY_URL")

DEFAULT_HOST = os.environ.get("SENTINEL_A2A_HOST", "0.0.0.0")
DEFAULT_PORT = int(os.environ.get("SENTINEL_A2A_PORT", "9000"))

# System prompt: narrow, grounding-forbidden-to-confabulate, structured output.
# A specialist does ONE thing well and returns a machine-parseable envelope. The
# LLM's job is orchestration + explanation; the RANKING itself comes from the
# deterministic build_attack_paths reasoner, not from model judgement.
SYSTEM_PROMPT = """\
You are the attack-mapper specialist. You answer exactly one kind of question: \
given an environment (asset/subnet), return the ranked high-risk attack paths.

Rules:
- Use your tools: call asset_lookup to fetch the exposure surface (hosts, \
  exposed services, known-vuln flags, trust edges); use attack_lookup to attach \
  the relevant MITRE ATT&CK technique to each hop.
- The ranking of chains is computed by the deterministic reasoner over the \
  surface — do NOT invent, reorder, or re-score chains by intuition. Report the \
  chains it returns, in the order it returns them.
- NEVER claim a host is exploited, a chain is validated, or an exploit exists. \
  You reason over metadata only. Any real validation is HITL-gated elsewhere.
- Do not answer questions outside attack-path reasoning; a supervisor routes \
  those elsewhere.

Return a single JSON object:
{"query": str, "chains": [{"entry": str, "path": [str], "techniques": [str], \
  "score": number, "impact": str, "rationale": str}], "grounded": bool}
`grounded` is true only if the surface came from a tool response.
"""

# Capabilities advertised to the Registry / A2A discovery. Each is a coarse
# capability label a supervisor matches against when it decomposes a research
# question (search_registry filters on these). Keep them stable — they are part
# of the discovery contract.
CAPABILITIES: Tuple[str, ...] = (
    "attack.path",
    "attack.reachability",
    "attack.chain.ranking",
    "exposure.analysis",
    "attack.surface",
)

# Tool names this specialist expects on the Gateway. Mirrors registry/tools.yaml;
# the supervisor never calls these directly — it delegates the whole subtask.
GATEWAY_TOOLS: Tuple[str, ...] = ("asset_lookup", "attack_lookup")


# ==========================================================================
# REAL deterministic attack-path reasoner (no LLM, no network, no tokens).
# This is the provable core the agent/tool reasons WITH; it is intentionally
# separable and unit-testable without any of the serving stack.
# ==========================================================================

# Impact weight per crown-jewel-ness of a reached service. Higher = juicier.
# Keyed by service name; unknown services get a modest default so the score is
# always defined. Kept as a small, explicit table (not model judgement) so the
# ranking is deterministic and auditable.
_SERVICE_IMPACT: Dict[str, float] = {
    "postgres": 1.0,
    "mysql": 1.0,
    "mssql": 1.0,
    "oracle": 1.0,
    "redis": 0.8,
    "http-app": 0.6,
    "https": 0.6,
    "ssh": 0.5,
}
_DEFAULT_IMPACT = 0.4

# Per-edge traversal cost: how hard/likely a given trust relationship is to
# abuse. Lower cost => easier pivot => higher exploitability. Deterministic.
_EDGE_COST: Dict[str, float] = {
    "ssh_key_reuse": 0.2,
    "shared_admin_cred": 0.25,
    "service_account": 0.3,
    "flat_network": 0.5,
}
_DEFAULT_EDGE_COST = 0.6

# MITRE ATT&CK technique hints per hop kind, so the agent (or a caller) can
# attach a technique id to each step. Reasoner-side mapping only — the live
# attack_lookup tool enriches these with names/tactics.
_ENTRY_TECHNIQUE = "T1190"  # Exploit Public-Facing Application
_EDGE_TECHNIQUE: Dict[str, str] = {
    "ssh_key_reuse": "T1021",  # Remote Services
    "shared_admin_cred": "T1078",  # Valid Accounts
    "service_account": "T1078",  # Valid Accounts
    "flat_network": "T1021",  # Remote Services
}


def _index_surface(
    surface: Dict[str, Any]
) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, List[Dict[str, str]]]]:
    """Build host-by-id and outgoing-edges-by-src indices from a raw surface.

    WHY: the reasoner does repeated lookups ("is host X exposed?", "what edges
    leave X?"); indexing once keeps traversal linear and the logic readable. We
    validate shape defensively — a malformed surface raises rather than silently
    producing an empty/incorrect graph.
    """
    if not isinstance(surface, dict):
        raise ValueError("surface must be a dict")
    hosts_raw = surface.get("hosts")
    edges_raw = surface.get("trust_edges", [])
    if not isinstance(hosts_raw, list):
        raise ValueError("surface['hosts'] must be a list")
    if not isinstance(edges_raw, list):
        raise ValueError("surface['trust_edges'] must be a list")

    hosts: Dict[str, Dict[str, Any]] = {}
    for host in hosts_raw:
        if not isinstance(host, dict) or "id" not in host:
            raise ValueError("each host must be a dict with an 'id'")
        hosts[host["id"]] = host

    out_edges: Dict[str, List[Dict[str, str]]] = {}
    for edge in edges_raw:
        if not isinstance(edge, dict) or "src" not in edge or "dst" not in edge:
            raise ValueError("each trust edge must have 'src' and 'dst'")
        out_edges.setdefault(edge["src"], []).append(edge)
    return hosts, out_edges


def _entry_nodes(hosts: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Return hosts that are a valid attack ENTRY: internet-exposed AND running
    at least one service flagged ``known_vuln``.

    WHY both conditions: an internet-exposed but fully-patched host is not a
    foothold in this model (no known way in), and a known-vuln host with no
    external exposure is not *initial* access. Requiring both is what makes a
    fully-patched surface correctly yield zero chains. Sorted by id for stable
    output.
    """
    entries: List[Dict[str, Any]] = []
    for host in hosts.values():
        if not host.get("internet_exposed"):
            continue
        services = host.get("services") or []
        if any(svc.get("known_vuln") for svc in services):
            entries.append(host)
    return sorted(entries, key=lambda h: h["id"])


def _host_impact(host: Dict[str, Any]) -> float:
    """Impact of *reaching* a host = the max impact of any service it exposes.

    WHY max (not sum): compromising a host is as valuable as its most valuable
    service; summing would over-reward hosts that merely run many low-value
    ports.
    """
    services = host.get("services") or []
    if not services:
        return _DEFAULT_IMPACT
    return max(
        _SERVICE_IMPACT.get(svc.get("name", ""), _DEFAULT_IMPACT)
        for svc in services
    )


def _known_vuln_service(host: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Return the first known-vulnerable service on a host, if any (deterministic
    by service order)."""
    for svc in host.get("services") or []:
        if svc.get("known_vuln"):
            return svc
    return None


def _score_chain(path_hosts: List[Dict[str, Any]], edge_kinds: List[str]) -> float:
    """Score a chain by exploitability × impact (higher = worse for defender).

    Model (all inputs deterministic, no randomness):
      - exploitability starts at 1.0 for the entry (a known-vuln exposed node is
        assumed reachable) and is multiplied by ``(1 - edge_cost)`` for each hop
        traversed — an easier pivot (lower cost) preserves more exploitability.
      - impact is the impact of the DEEPEST (final) host reached — the chain is
        worth what it ultimately lets the attacker touch.
      - score = round(exploitability * final_impact, 6). Rounding keeps the
        value stable across platforms for exact-match tests.

    A longer chain is only ranked higher if the extra hops actually reach a
    higher-impact target that outweighs the exploitability decay — which is the
    intuitively correct trade-off.
    """
    exploitability = 1.0
    for kind in edge_kinds:
        exploitability *= 1.0 - _EDGE_COST.get(kind, _DEFAULT_EDGE_COST)
    final_impact = _host_impact(path_hosts[-1])
    return round(exploitability * final_impact, 6)


def _impact_label(score: float) -> str:
    """Coarse severity label for a chain score (presentation only)."""
    if score >= 0.6:
        return "critical"
    if score >= 0.4:
        return "high"
    if score >= 0.2:
        return "medium"
    return "low"


def build_attack_paths(
    surface: Dict[str, Any], *, max_depth: int = 6
) -> List[Dict[str, Any]]:
    """Compute ranked high-risk attack chains from an exposure surface.

    This is the REAL reasoning core — pure, deterministic graph traversal with
    no LLM and no network. Same ``surface`` always yields the same ranked list.

    Algorithm
    ---------
    1. Index the surface into host + outgoing-edge maps.
    2. Find ENTRY nodes: internet-exposed hosts that carry a ``known_vuln``
       service (initial access via T1190). No entries -> return ``[]`` (a
       fully-patched / non-exposed surface has no attack path).
    3. From each entry, DFS along trust edges (cycle-safe via a visited set,
       bounded by ``max_depth``), emitting a chain at EVERY reachable node
       (the entry itself is a length-1 chain, each pivot extends it). Emitting
       intermediate chains — not just leaves — means a high-value host reached
       mid-path is still surfaced even if the path continues past it.
    4. Score each chain by exploitability × impact (see :func:`_score_chain`).
    5. Rank descending by score; ties broken deterministically by (shorter
       path first, then entry id, then path) so output ordering is stable.

    Returns a list of chain dicts::

        {"entry": str, "path": [host_id, ...], "techniques": [str, ...],
         "edges": [kind, ...], "score": float, "impact": str,
         "entry_cve": str | None,
         "rationale": str}

    ``techniques`` is the ATT&CK technique per step: T1190 for the entry, then
    the per-edge technique for each pivot — a caller can enrich these via the
    ``attack_lookup`` tool. ``entry_cve`` surfaces the CVE that made the entry
    node vulnerable (grounding the "why is this the way in" claim).

    Raises ``ValueError`` on a malformed surface — we never silently degrade a
    bad graph into an empty (falsely reassuring) result.
    """
    hosts, out_edges = _index_surface(surface)
    entries = _entry_nodes(hosts)
    if not entries:
        return []

    chains: List[Dict[str, Any]] = []

    def walk(
        current_id: str,
        path_ids: List[str],
        edge_kinds: List[str],
        techniques: List[str],
        visited: set,
    ) -> None:
        # Emit a chain for the path as it currently stands (entry + pivots so
        # far). We do this at every node so a valuable mid-path host is ranked
        # even if traversal continues deeper.
        path_hosts = [hosts[h] for h in path_ids]
        entry_host = path_hosts[0]
        entry_svc = _known_vuln_service(entry_host)
        score = _score_chain(path_hosts, edge_kinds)
        target_id = path_ids[-1]
        if len(path_ids) == 1:
            rationale = (
                f"{entry_host['id']} is internet-exposed and runs a "
                f"known-vulnerable service; direct foothold."
            )
        else:
            rationale = (
                f"Foothold on {entry_host['id']} (internet-exposed known-vuln), "
                f"then pivot via {' -> '.join(edge_kinds)} to reach "
                f"{target_id}."
            )
        chains.append(
            {
                "entry": entry_host["id"],
                "path": list(path_ids),
                "edges": list(edge_kinds),
                "techniques": list(techniques),
                "score": score,
                "impact": _impact_label(score),
                "entry_cve": entry_svc.get("cve_id") if entry_svc else None,
                "rationale": rationale,
            }
        )

        if len(path_ids) >= max_depth:
            return
        for edge in sorted(
            out_edges.get(current_id, []), key=lambda e: (e["dst"], e.get("kind", ""))
        ):
            dst = edge["dst"]
            # Cycle-safe: never revisit a host within the same chain. An edge to
            # an unknown host is skipped (the destination is out of surface).
            if dst in visited or dst not in hosts:
                continue
            kind = edge.get("kind", "unknown")
            walk(
                dst,
                path_ids + [dst],
                edge_kinds + [kind],
                techniques + [_EDGE_TECHNIQUE.get(kind, "T1021")],
                visited | {dst},
            )

    for entry in entries:
        walk(
            entry["id"],
            [entry["id"]],
            [],
            [_ENTRY_TECHNIQUE],
            {entry["id"]},
        )

    # Rank: highest score first; deterministic tie-break so output is stable.
    chains.sort(key=lambda c: (-c["score"], len(c["path"]), c["entry"], c["path"]))
    return chains


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

    @app.get("/ping")
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
