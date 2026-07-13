"""attack_lookup — MITRE ATT&CK technique lookup tool (reference template).

SecOps purpose
--------------
When a security operations team analyzes an alert or writes a detection,
it needs to map observed behavior to the MITRE ATT&CK framework. Given an
ATT&CK technique id (e.g. ``T1059`` or a sub-technique ``T1059.001``),
this tool returns the technique name, tactic(s), a short description, the
platforms it applies to, and reference links.

This is a *reference implementation* for wiring into an Amazon Bedrock
AgentCore Gateway as an MCP target. It runs entirely OFFLINE from a small
embedded slice of the public ATT&CK knowledge base; a live path can pull
the full STIX bundle when explicitly enabled.

Egress & secrets posture
------------------------
- Egress is CONTROLLED. Live ATT&CK STIX download happens only when
  ``ATTACK_LIVE=1`` and the runtime network policy permits egress.
  Default mode does no network I/O.
- No secrets are required by ATT&CK; none are read or stored.
- Execution role / region are referenced via
  ``SENTINEL_EXECUTION_ROLE_ARN``, ``SENTINEL_REGION`` and ``AWS_PROFILE``.

Input contract
--------------
event = {"technique_id": "T1059.001"}

Output contract (on success)
----------------------------
{
    "ok": True,
    "source": "stub" | "live",
    "technique": {
        "id": "T1059.001",
        "name": "PowerShell",
        "is_subtechnique": True,
        "tactics": ["execution"],
        "platforms": ["Windows"],
        "description": "...",
        "references": ["https://attack.mitre.org/techniques/T1059/001/"],
    },
}
"""

from __future__ import annotations

import os
import re
from typing import Any, Dict

# ATT&CK technique id: Tnnnn optionally followed by .nnn sub-technique.
_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")

# Small offline slice of the public ATT&CK Enterprise matrix. These are
# well-known, public techniques used purely as reference examples.
_STUB_DB: Dict[str, Dict[str, Any]] = {
    "T1059": {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "is_subtechnique": False,
        "tactics": ["execution"],
        "platforms": ["Windows", "Linux", "macOS"],
        "description": (
            "Adversaries may abuse command and script interpreters to "
            "execute commands, scripts, or binaries."
        ),
        "references": ["https://attack.mitre.org/techniques/T1059/"],
    },
    "T1059.001": {
        "id": "T1059.001",
        "name": "PowerShell",
        "is_subtechnique": True,
        "tactics": ["execution"],
        "platforms": ["Windows"],
        "description": (
            "Adversaries may abuse PowerShell commands and scripts for "
            "execution, discovery, and defense evasion."
        ),
        "references": ["https://attack.mitre.org/techniques/T1059/001/"],
    },
    "T1190": {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "is_subtechnique": False,
        "tactics": ["initial-access"],
        "platforms": ["Windows", "Linux", "macOS", "Network"],
        "description": (
            "Adversaries may attempt to exploit a weakness in an "
            "Internet-facing host or system to gain initial access "
            "(e.g. exploiting a vulnerable dependency such as Log4Shell)."
        ),
        "references": ["https://attack.mitre.org/techniques/T1190/"],
    },
    "T1046": {
        "id": "T1046",
        "name": "Network Service Discovery",
        "is_subtechnique": False,
        "tactics": ["discovery"],
        "platforms": ["Windows", "Linux", "macOS", "Network"],
        "description": (
            "Adversaries may attempt to get a listing of services running "
            "on remote hosts and local network infrastructure devices."
        ),
        "references": ["https://attack.mitre.org/techniques/T1046/"],
    },
    "T1195": {
        "id": "T1195",
        "name": "Supply Chain Compromise",
        "is_subtechnique": False,
        "tactics": ["initial-access"],
        "platforms": ["Windows", "Linux", "macOS"],
        "description": (
            "Adversaries may manipulate products or delivery mechanisms "
            "prior to receipt by a consumer (e.g. malicious npm packages)."
        ),
        "references": ["https://attack.mitre.org/techniques/T1195/"],
    },
}


def _validate(event: Dict[str, Any]) -> str:
    """Validate input and return the normalized technique id."""
    if not isinstance(event, dict):
        raise ValueError("event must be a dict")
    tid = event.get("technique_id")
    if not isinstance(tid, str) or not tid.strip():
        raise ValueError("missing required string field 'technique_id'")
    tid = tid.strip().upper()
    if not _TECHNIQUE_RE.match(tid):
        raise ValueError(
            "invalid 'technique_id' format; expected Tnnnn or Tnnnn.nnn, "
            f"got: {tid!r}"
        )
    return tid


def _fetch_live(technique_id: str) -> Dict[str, Any]:
    """Pull the technique from the live ATT&CK STIX bundle.

    Only reached when ATTACK_LIVE=1. The STIX client (mitreattack /
    stix2) is imported lazily so the default offline path has no third
    party dependency. If the library is unavailable the caller receives an
    explicit upstream_error rather than a silent fallback.
    """
    import json
    import urllib.request

    url = (
        "https://raw.githubusercontent.com/mitre/cti/master/"
        "enterprise-attack/enterprise-attack.json"
    )
    # Bound the read so a hostile/oversized upstream cannot force unbounded memory
    # buffering (mirrors the sibling *_LIVE tools). The real ATT&CK bundle is ~35MB,
    # so cap generously at 64MB and refuse anything larger rather than OOM.
    _MAX_LIVE_BODY_BYTES = 64 * 1024 * 1024
    req = urllib.request.Request(url, headers={"User-Agent": "sentinel-harness"})
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
        raw = resp.read(_MAX_LIVE_BODY_BYTES + 1)
    if len(raw) > _MAX_LIVE_BODY_BYTES:
        raise RuntimeError(
            f"ATT&CK bundle exceeds {_MAX_LIVE_BODY_BYTES} bytes; refusing to parse"
        )
    bundle = json.loads(raw.decode("utf-8"))

    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        ext_id = None
        refs = []
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                ext_id = ref.get("external_id")
                if ref.get("url"):
                    refs.append(ref["url"])
        if ext_id != technique_id:
            continue
        tactics = [
            phase.get("phase_name")
            for phase in obj.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack"
        ]
        return {
            "id": technique_id,
            "name": obj.get("name"),
            "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique")),
            "tactics": tactics,
            "platforms": obj.get("x_mitre_platforms", []),
            "description": obj.get("description", ""),
            "references": refs,
        }
    raise LookupError(f"technique not found in ATT&CK: {technique_id}")


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Look up a single MITRE ATT&CK technique by id.

    Offline (stub) by default; live STIX lookup only when ATTACK_LIVE=1.
    Egress is controlled by environment configuration; no secrets required.
    """
    try:
        technique_id = _validate(event)
    except ValueError as exc:
        return {"ok": False, "error": "validation_error", "message": str(exc)}

    live = os.environ.get("ATTACK_LIVE") == "1"
    try:
        if live:
            technique = _fetch_live(technique_id)
            source = "live"
        else:
            if technique_id not in _STUB_DB:
                return {
                    "ok": False,
                    "error": "not_found",
                    "message": (
                        f"{technique_id} not in offline stub set; set "
                        "ATTACK_LIVE=1 to query the full ATT&CK bundle"
                    ),
                }
            technique = _STUB_DB[technique_id]
            source = "stub"
    except LookupError as exc:
        return {"ok": False, "error": "not_found", "message": str(exc)}
    except Exception as exc:  # never swallow upstream failures
        return {"ok": False, "error": "upstream_error", "message": str(exc)}

    return {"ok": True, "source": source, "technique": technique}


if __name__ == "__main__":
    import json

    print(json.dumps(handler({"technique_id": "T1059.001"}, None), indent=2))
