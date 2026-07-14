"""
threat-hunt · A2A specialist Runtime (skeleton + real hunt-plan core)
=====================================================================
A narrow **specialist** agent that a supervisor harness delegates to over A2A
(agent-to-agent). It mirrors ``specialists/cve-intel`` exactly: a Strands
``Agent`` wrapped in an ``A2AServer``, driven by a ``LiteLLMModel`` (so
specialists are provider-agnostic, unlike the Bedrock-only supervisor harness),
a FastAPI ``/ping`` health probe, and a self-describing **agent-card** that the
supervisor discovers through the AgentCore Registry (BLUEPRINT §4.2).

What this specialist does
-------------------------
Given a hunting *hypothesis* in natural language ("possible credential dumping
on domain controllers"), it produces a **structured hunt plan**: the abductive
questions to ask, the observables/log sources to query, the MITRE ATT&CK
techniques implicated, and concrete starter queries. This is the classic
threat-hunting loop (hypothesis → observables → evidence) that a SOC runs.

Real vs. simulated (be scrupulous)
----------------------------------
- REAL, deterministic, offline: :func:`build_hunt_plan`. It is PURE PYTHON with
  NO LLM, NO tokens, NO network. It maps a hypothesis to observables/techniques
  from a small built-in TTP knowledge slice. Same input → same output. That is
  the provable core and it is fully unit-testable offline.
- SKELETON only: the A2A serving wrapper (:func:`build_agent` / :func:`build_app`
  / :func:`serve`). Heavy deps (``strands`` / ``litellm`` / ``bedrock-agentcore``)
  are import-guarded so this module is always importable and the agent-card is
  verifiable without the specialist stack installed.

The LLM (when present at runtime) narrates and prioritizes; it must call
``build_hunt_plan`` (exposed as a Gateway tool) for the actual observable/ATT&CK
mapping so no technique id or log source is ever confabulated.

Why the imports are guarded
---------------------------
``strands`` / ``strands-agents[a2a,litellm]`` / ``bedrock-agentcore`` are heavy,
platform-specific runtime deps that are NOT needed to *inspect* or test the
skeleton (agent-card shape, capability metadata, the ``build_agent`` factory
contract, and the pure ``build_hunt_plan`` core). They are imported lazily inside
the factory so this module is always importable — CI stays green without the
specialist stack installed.

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
from typing import Any, Dict, List

# --- Specialist identity -----------------------------------------------------
# The Registry entry and the A2A agent-card are both derived from these, so a
# supervisor can discover this specialist by *capability* (search_registry) and
# then address it by name (invoke_specialist). Keep names skill-based, not
# person- or org-based.
SPECIALIST_NAME = "threat-hunt"
SPECIALIST_VERSION = "0.1.0"
SPECIALIST_DESCRIPTION = (
    "Threat-hunting specialist. Given a hunting hypothesis (e.g. 'possible "
    "credential dumping on domain controllers'), returns a structured hunt "
    "plan: the abductive questions to answer, the observables / log sources to "
    "query, the implicated MITRE ATT&CK techniques, and concrete starter "
    "queries. The observable/technique mapping is produced by a deterministic "
    "offline function — never confabulated by the model."
)

# LiteLLM model id. Provider-prefixed (``bedrock/...``, ``openai/...``, etc.) so a
# specialist can run a cheaper/narrower model than the supervisor. Read from env
# (12-factor); the default is a small Bedrock model routed through LiteLLM.
DEFAULT_MODEL_ID = os.environ.get(
    "SENTINEL_SPECIALIST_MODEL", "bedrock/global.anthropic.claude-haiku-4-5-20251001-v1:0"
)

# The Gateway MCP endpoint this specialist pulls its tools from. Optional at
# import time; required to actually build.
GATEWAY_URL = os.environ.get("SENTINEL_GATEWAY_URL")

DEFAULT_HOST = os.environ.get("SENTINEL_A2A_HOST", "0.0.0.0")
DEFAULT_PORT = int(os.environ.get("SENTINEL_A2A_PORT", "9000"))

# System prompt: narrow, grounding-forbidden-to-confabulate, structured output.
# A specialist does ONE thing well and returns a machine-parseable envelope.
SYSTEM_PROMPT = """\
You are the threat-hunt specialist. You answer exactly one kind of question: \
given a hunting hypothesis in natural language, produce a structured, testable \
hunt plan.

Rules:
- Call the build_hunt_plan tool to derive the observables, log sources, and \
  MITRE ATT&CK techniques. NEVER invent a technique id, a log source, or a \
  detection query on your own — the mapping is deterministic and lives in that \
  tool.
- If the hypothesis matches no known TTP, the tool returns a safe generic \
  reconnaissance plan; relay it as-is and say plainly that it is generic.
- Do not answer questions outside threat hunting; a supervisor routes those \
  elsewhere.

Return a single JSON object:
{"hypothesis": str, "matched": bool,
 "abductive_questions": [str], "observables_to_query": [str],
 "attack_techniques": [str], "suggested_queries": [str], "grounded": bool}
`grounded` is true only if every technique/observable came from build_hunt_plan.
"""

# Capabilities advertised to the Registry / A2A discovery. Each is a coarse
# capability label a supervisor matches against when it decomposes a research
# question (search_registry filters on these). Keep them stable — they are part
# of the discovery contract.
CAPABILITIES: tuple[str, ...] = (
    "hunt.plan",
    "hunt.hypothesis",
    "hunt.observables",
    "attack.technique_mapping",
    "detection.query_suggestion",
)

# Tool names this specialist expects on the Gateway. The pure build_hunt_plan
# core is also exposed as a Gateway tool; attack_lookup enriches the returned
# ATT&CK ids. The supervisor never calls these directly — it delegates the
# whole subtask.
GATEWAY_TOOLS: tuple[str, ...] = ("build_hunt_plan", "attack_lookup", "sigma_yara_lint")


# ===========================================================================
# REAL deterministic hunt-plan core (pure Python, no LLM, no network)
# ===========================================================================
# A small built-in slice mapping common TTPs to the observables a hunter would
# query, the MITRE ATT&CK technique ids implicated, and concrete starter
# queries. This is intentionally a *reference* slice of well-known, public
# behaviours — not an exhaustive matrix. Each entry is keyed by a canonical TTP
# name and carries the trigger keywords a free-text hypothesis is matched on.
#
# WHY a fixed table (and not an LLM): a hunt plan that decides which log sources
# to pull and which techniques to chase must be deterministic and auditable — a
# SOC has to trust that the same hypothesis always yields the same plan. The LLM
# layer (when present) only narrates/prioritizes; the mapping is provable here.
_TTP_LIBRARY: Dict[str, Dict[str, Any]] = {
    "credential_dumping": {
        "keywords": (
            "credential dump", "credential dumping", "lsass", "mimikatz",
            "ntds", "sam dump", "dcsync", "hashdump", "dump credentials",
        ),
        "attack_techniques": ["T1003", "T1003.001", "T1003.003"],
        "observables_to_query": [
            "process_access events targeting lsass.exe (Sysmon Event ID 10)",
            "process_creation of comsvcs.dll MiniDump / procdump / mimikatz",
            "access to ntds.dit or the SAM/SYSTEM registry hives",
            "unexpected DRSUAPI replication (DCSync) from non-DC accounts",
        ],
        "abductive_questions": [
            "Which processes opened a handle to lsass with read/clone rights?",
            "Did any non-domain-controller principal request directory replication?",
            "Was ntds.dit or a registry hive copied off a domain controller?",
        ],
        "suggested_queries": [
            "sysmon EventID=10 TargetImage='*lsass.exe' GrantedAccess in (0x1010,0x1410,0x1438)",
            "process_creation CommandLine|contains any ('comsvcs.dll, MiniDump', 'sekurlsa', 'lsadump')",
            "directory_service_access operation=DRSGetNCChanges caller!=domain_controller",
        ],
    },
    "persistence_scheduled_task": {
        "keywords": (
            "scheduled task", "schtasks", "cron", "persistence", "autorun",
            "run key", "startup folder", "new service persist",
        ),
        "attack_techniques": ["T1053", "T1053.005", "T1547.001"],
        "observables_to_query": [
            "scheduled task creation (Windows Event ID 4698 / schtasks.exe)",
            "cron job / systemd unit creation on Linux hosts",
            "new autorun Run/RunOnce registry key values",
            "files dropped into per-user or common Startup folders",
        ],
        "abductive_questions": [
            "What new scheduled tasks or cron jobs appeared, and who created them?",
            "Do any autorun keys point at unsigned or user-writable paths?",
            "Does the persistence mechanism re-launch a known suspicious binary?",
        ],
        "suggested_queries": [
            "windows EventID=4698 | stats count by SubjectUserName, TaskName",
            "process_creation Image|endswith='\\schtasks.exe' CommandLine|contains='/create'",
            "registry_set TargetObject|contains 'CurrentVersion\\Run'",
        ],
    },
    "lateral_movement_remote_exec": {
        "keywords": (
            "lateral movement", "psexec", "wmi", "remote execution", "smb exec",
            "pass the hash", "pass-the-hash", "winrm", "rdp brute",
        ),
        "attack_techniques": ["T1021", "T1021.002", "T1021.006", "T1570"],
        "observables_to_query": [
            "network logon events (Windows Event ID 4624 Type 3) fan-out",
            "service creation from remote exec tooling (Event ID 7045 / PsExec)",
            "WMI process creation (Win32_Process Create) on remote hosts",
            "SMB admin-share ($ADMIN$/C$) file writes preceding execution",
        ],
        "abductive_questions": [
            "Which account authenticated to many hosts in a short window?",
            "Were services created remotely, and by which source host?",
            "Did remote WMI/WinRM spawn interpreters on the target?",
        ],
        "suggested_queries": [
            "windows EventID=4624 LogonType=3 | stats dc(Computer) by Account | where dc>10",
            "windows EventID=7045 ServiceFileName|contains any ('\\\\', 'psexesvc')",
            "process_creation ParentImage|endswith any ('\\wmiprvse.exe', '\\winrshost.exe')",
        ],
    },
    "exfiltration": {
        "keywords": (
            "exfiltration", "data exfil", "data theft", "large upload",
            "dns tunnel", "beacon", "c2", "command and control", "data transfer",
        ),
        "attack_techniques": ["T1041", "T1048", "T1071", "T1567"],
        "observables_to_query": [
            "outbound byte volume anomalies per host / per destination",
            "long-lived beaconing connections with regular jitter",
            "high-entropy or oversized DNS TXT/A queries (DNS tunneling)",
            "uploads to unsanctioned cloud storage / web services",
        ],
        "abductive_questions": [
            "Which internal hosts sent anomalously large volumes outbound?",
            "Are there periodic connections consistent with C2 beaconing?",
            "Do DNS query patterns suggest tunneling (entropy, length, volume)?",
        ],
        "suggested_queries": [
            "network_traffic direction=outbound | stats sum(bytes_out) by src_ip, dest_ip | sort -sum",
            "dns query_length>50 OR query_entropy>3.5 | stats count by src_ip",
            "proxy dest_category='cloud_storage' method=POST | stats sum(bytes) by src_ip",
        ],
    },
    "phishing_initial_access": {
        "keywords": (
            "phishing", "spear phish", "malicious attachment", "macro",
            "initial access", "malicious link", "email lure", "office macro",
        ),
        "attack_techniques": ["T1566", "T1566.001", "T1204", "T1204.002"],
        "observables_to_query": [
            "email gateway logs for attachments with macro-enabled documents",
            "office application spawning script interpreters (Word→cmd/powershell)",
            "user click-through on newly-registered or low-reputation domains",
            "child processes of Outlook / browser download folders",
        ],
        "abductive_questions": [
            "Did any Office app spawn a shell or scripting interpreter?",
            "Which users opened attachments from external senders?",
            "Were the linked domains newly registered or previously unseen?",
        ],
        "suggested_queries": [
            "process_creation ParentImage|endswith any ('\\winword.exe','\\excel.exe') "
            "Image|endswith any ('\\cmd.exe','\\powershell.exe','\\wscript.exe')",
            "email attachment_type in ('.docm','.xlsm','.iso','.lnk') sender_domain=external",
            "proxy domain_age_days<30 referrer=mail | stats count by user",
        ],
    },
    "privilege_escalation": {
        "keywords": (
            "privilege escalation", "privesc", "token manipulation", "uac bypass",
            "setuid", "sudo abuse", "getsystem", "elevate privileges",
        ),
        "attack_techniques": ["T1068", "T1134", "T1548", "T1548.002"],
        "observables_to_query": [
            "process token elevation / integrity-level changes",
            "UAC bypass patterns (fodhelper, eventvwr, sdclt auto-elevate)",
            "new setuid binaries or sudoers modifications on Linux",
            "special-privilege logon assignments (Windows Event ID 4672)",
        ],
        "abductive_questions": [
            "Did any medium-integrity process spawn a high-integrity child?",
            "Were sudoers or setuid bits changed outside change windows?",
            "Which accounts were newly assigned special privileges?",
        ],
        "suggested_queries": [
            "process_creation ParentImage|endswith any ('\\fodhelper.exe','\\eventvwr.exe')",
            "linux_audit syscall in ('chmod','chown') arg|contains '4000'",
            "windows EventID=4672 | stats count by SubjectUserName",
        ],
    },
}

# Safe generic fallback when a hypothesis matches no known TTP. It never crashes,
# never confabulates a specific technique — it returns a broad reconnaissance
# starting point so a hunter is not left empty-handed.
_GENERIC_PLAN: Dict[str, Any] = {
    "attack_techniques": ["T1057", "T1082"],  # process / system information discovery
    "observables_to_query": [
        "baseline process_creation activity on the scoped hosts",
        "authentication events (successful and failed) for the scoped accounts",
        "outbound network connections to rare or newly-seen destinations",
        "recently created/modified files and persistence locations",
    ],
    "abductive_questions": [
        "What is normal for this host/account, and what deviates from it?",
        "Which processes, logons, or connections are rare in the baseline window?",
        "Is there a narrower behaviour to pivot the hypothesis toward?",
    ],
    "suggested_queries": [
        "process_creation | rare Image by host",
        "authentication | stats count by Account, status | where status='failure'",
        "network_traffic direction=outbound | rare dest_ip",
    ],
}


def _normalize_hypothesis(hypothesis: str) -> str:
    """Lowercase + collapse whitespace so keyword matching is stable.

    WHY: matching must be deterministic regardless of casing or spacing in the
    free-text hypothesis; we never mutate the caller's original string, only a
    local normalized copy used for keyword containment tests.
    """
    return " ".join(hypothesis.lower().split())


def _match_ttps(normalized: str) -> List[str]:
    """Return the TTP-library keys whose trigger keywords appear in the text.

    Deterministic: iterates the library in insertion order and keeps a key the
    first time any of its keywords is a substring of the normalized hypothesis.
    Multiple TTPs can match (e.g. a hypothesis spanning access + exfiltration).
    """
    matched: List[str] = []
    for key, entry in _TTP_LIBRARY.items():
        if any(kw in normalized for kw in entry["keywords"]):
            matched.append(key)
    return matched


def _dedupe_preserve_order(items: List[str]) -> List[str]:
    """Stable de-duplication so merged multi-TTP plans stay deterministic."""
    seen: set[str] = set()
    out: List[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def build_hunt_plan(hypothesis: str) -> Dict[str, Any]:
    """Turn a hunting hypothesis into a structured, testable hunt plan.

    PURE PYTHON. No LLM, no tokens, no network, no secrets. Same input always
    yields the same output — this is the provable, auditable core of the
    specialist. The A2A/LLM wrapper only narrates around it.

    The hypothesis free text is keyword-matched against a small built-in library
    of common TTPs (credential dumping, persistence, lateral movement,
    exfiltration, phishing, privilege escalation). For each matched TTP the plan
    aggregates the abductive questions to answer, the observables / log sources
    to query, the implicated MITRE ATT&CK technique ids, and concrete starter
    queries. When nothing matches, a safe generic reconnaissance plan is returned
    (``matched=False``) so the function never raises for an unknown hypothesis.

    Args:
        hypothesis: free-text hunting hypothesis, e.g. "possible credential
            dumping on domain controllers".

    Returns:
        {
          "hypothesis": str,            # the original, unmodified input
          "matched": bool,              # did any TTP in the library match?
          "matched_ttps": [str],        # canonical TTP keys that matched
          "abductive_questions": [str],
          "observables_to_query": [str],
          "attack_techniques": [str],   # MITRE ATT&CK ids (deduped, ordered)
          "suggested_queries": [str],
        }

    Raises:
        ValueError: if ``hypothesis`` is not a non-empty string. We validate
            rather than silently coerce so a caller bug surfaces immediately
            instead of producing a misleading empty plan.
    """
    if not isinstance(hypothesis, str) or not hypothesis.strip():
        raise ValueError("hypothesis must be a non-empty string")

    normalized = _normalize_hypothesis(hypothesis)
    matched_keys = _match_ttps(normalized)

    if not matched_keys:
        # Safe generic plan — never crash, never confabulate a specific technique.
        return {
            "hypothesis": hypothesis,
            "matched": False,
            "matched_ttps": [],
            "abductive_questions": list(_GENERIC_PLAN["abductive_questions"]),
            "observables_to_query": list(_GENERIC_PLAN["observables_to_query"]),
            "attack_techniques": list(_GENERIC_PLAN["attack_techniques"]),
            "suggested_queries": list(_GENERIC_PLAN["suggested_queries"]),
        }

    abductive: List[str] = []
    observables: List[str] = []
    techniques: List[str] = []
    queries: List[str] = []
    for key in matched_keys:
        entry = _TTP_LIBRARY[key]
        abductive.extend(entry["abductive_questions"])
        observables.extend(entry["observables_to_query"])
        techniques.extend(entry["attack_techniques"])
        queries.extend(entry["suggested_queries"])

    return {
        "hypothesis": hypothesis,
        "matched": True,
        "matched_ttps": matched_keys,
        "abductive_questions": _dedupe_preserve_order(abductive),
        "observables_to_query": _dedupe_preserve_order(observables),
        "attack_techniques": _dedupe_preserve_order(techniques),
        "suggested_queries": _dedupe_preserve_order(queries),
    }


# ===========================================================================
# A2A serving skeleton (guarded, mirrors specialists/cve-intel)
# ===========================================================================
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
