"""M4 acceptance smoke suite — freeze the live M4 proofs into re-runnable checks.

WHY this file exists
--------------------
M4 (the L3 "defense-in-depth + real GA control-plane" milestone) was validated
once, live, against a real non-prod dev account in us-east-1. A one-time live
proof rots: the evidence JSONs can drift, the CDK app can stop synthesizing, the
JWT authorizer shape can regress, and the deterministic BAS blind-spot arithmetic
can silently change. This suite is the ROADMAP-M7 ``tests/smoke`` habit applied
to M4 — it re-asserts, on every ``pytest`` run, the facts that are OFFLINE-provable
without touching AWS, so a regression in any M4 promise fails CI immediately.

Honesty boundary (label live vs offline vs skeleton precisely)
--------------------------------------------------------------
* By DEFAULT (no creds, no ``SENTINEL_SMOKE_LIVE``) this suite is 100% OFFLINE:
  it reads the account-id-scrubbed evidence files, synthesizes the CDK app
  locally, builds the JWT authorizer block in-process, and runs the pure-Python
  BAS replay. It proves the evidence *is what it claims to be* and that the
  offline machinery still works — it does NOT re-prove the live AWS round-trip.
* The evidence files themselves record the LIVE result captured at M4 time; this
  suite does not fabricate liveness. The four "verdict-key" checks assert that
  the recorded verdict still says what the M4 audit found (e.g. the guardrail
  really did ``GUARDRAIL_INTERVENED`` and masked both tokens).
* The LIVE re-verification (actually calling AWS again) is opt-in only, guarded
  by ``SENTINEL_SMOKE_LIVE=1`` + resolvable credentials. Absent that, live checks
  SKIP (never fail, never pretend).

HARD RULE: the default path makes ZERO AWS calls and ZERO network calls. The CDK
synth check shells out to the *local* ``node_modules/.bin/cdk`` (offline synth,
no deploy) and SKIPS entirely if node_modules is absent.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

# --------------------------------------------------------------------------- #
# Hermetic import env (mirror the sibling suites): dummy region/role/creds so    #
# importing the harness never resolves a real profile or hits the metadata svc. #
# --------------------------------------------------------------------------- #
os.environ.setdefault("SENTINEL_REGION", "us-east-1")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("SENTINEL_EXECUTION_ROLE_ARN", "arn:aws:iam::000000000000:role/test-harness-role")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")

# Repo layout anchors (this file: <repo>/tests/smoke/test_m4_acceptance.py).
_REPO_ROOT = Path(__file__).resolve().parents[2]
_EVIDENCE = _REPO_ROOT / "evidence"
_IAC_CDK = _REPO_ROOT / "iac-cdk"

# Repo root on path so `import sentinel_harness` resolves from a source checkout.
sys.path.insert(0, str(_REPO_ROOT))

# The CDK stacks the app synthesizes (native AWS::BedrockAgentCore::* + supporting).
# The 8 M4 foundation stacks plus the specialist / long-running Runtime stack
# (sentinel-runtime) wired in via bin/sentinel.ts.
_EXPECTED_STACKS = {
    "sentinel-gateway",
    "sentinel-registry",
    "sentinel-memory",
    "sentinel-network",
    "sentinel-identity",
    "sentinel-guardrail",
    "sentinel-observability",
    "sentinel-harness",
    "sentinel-runtime",
}

# Live re-verification is opt-in. Absent this flag, live checks SKIP (they never
# fail offline and never pretend a live round-trip happened).
_LIVE = os.environ.get("SENTINEL_SMOKE_LIVE") == "1"


def _load_evidence(name: str) -> dict:
    """Read + parse an evidence JSON, failing loudly if it is missing/corrupt.

    Never swallow: a missing or unparseable evidence file is a real regression in
    the M4 proof set, not a condition to skip past.
    """
    path = _EVIDENCE / name
    assert path.is_file(), f"M4 evidence file missing: {path}"
    text = path.read_text(encoding="utf-8")
    return json.loads(text)


# --------------------------------------------------------------------------- #
# (a) The four M4 evidence files exist + parse + carry the expected verdict     #
#     keys. These assert the RECORDED (offline-readable) verdict, which was      #
#     captured live at M4 time; they do not re-call AWS.                         #
# --------------------------------------------------------------------------- #
def test_guardrail_evidence_intervened_and_masked():
    """m4_guardrail_result.json: the Guardrail really intervened + masked tokens."""
    ev = _load_evidence("m4_guardrail_result.json")
    v = ev["verdict"]
    assert v["guardrail_deployed_live"] is True
    assert v["region"] == "us-east-1"
    assert v["action"] == "GUARDRAIL_INTERVENED"
    # Both a fake AWS key and an sk- API token were masked to their placeholders.
    assert v["aws_key_masked_to"] == "{aws-access-key-id}"
    assert v["api_token_masked_to"] == "{generic-api-token}"
    assert set(v["regex_matches"]) == {"aws-access-key-id", "generic-api-token"}
    assert v["closed"] is True


def test_guardrail_evidence_is_account_scrubbed():
    """The recorded evidence must not leak a real 12-digit account id (public repo)."""
    raw = (_EVIDENCE / "m4_guardrail_result.json").read_text(encoding="utf-8")
    _assert_no_real_account_id(raw)


def test_live_deploy_evidence_region_and_stacks():
    """m4_live_deploy_result.json: unified region us-east-1 + the three retained controls."""
    ev = _load_evidence("m4_live_deploy_result.json")
    v = ev["verdict"]
    # Region unified to us-east-1 (the stray us-west-2 deploy was torn down).
    assert v["region"].startswith("us-east-1")
    assert v["guardrail"]["deployed"] is True
    assert v["guardrail"]["action"] == "GUARDRAIL_INTERVENED"
    assert set(v["guardrail"]["masked"]) == {"{aws-access-key-id}", "{generic-api-token}"}
    # Cognito identity: OIDC reachable, RS256, authorizer contract verified.
    ident = v["identity"]
    assert ident["deployed"] is True
    assert ident["oidc_discovery_reachable"] is True
    assert ident["signing_alg"] == "RS256"
    assert ident["authorizer_contract_ok"] is True
    assert ident["oidc_region"] == "us-east-1"
    # Observability: dashboard + metric namespace + budget alarm.
    obs = v["observability"]
    assert obs["deployed"] is True
    assert obs["dashboard"] == "sentinel-observability"
    assert obs["metric_namespace"] == "SentinelHarness"
    # The only standing ~$30/mo cost (PrivateLink endpoints) stays gated OFF.
    assert v["vpc_endpoints_cost_gated_off"] is True
    assert v["closed"] is True


def test_live_deploy_evidence_is_account_scrubbed():
    raw = (_EVIDENCE / "m4_live_deploy_result.json").read_text(encoding="utf-8")
    _assert_no_real_account_id(raw)


def test_gateway_lifecycle_evidence_created_and_deleted():
    """gateway_lifecycle_result.json: a real GA gateway was created AND deleted (no leftover)."""
    ev = _load_evidence("gateway_lifecycle_result.json")
    v = ev["verdict"]
    assert v["region"] == "us-east-1"
    assert v["protocol"] == "MCP"
    # Full self-cleaning round-trip on the real GA control plane.
    assert v["created"] is True
    assert v["reached_ready"] is True
    assert v["deleted"] is True
    assert v["deleted_confirmed_gone"] is True
    # The probe left nothing behind and did not touch the retained demo controls.
    assert v["leftover_after_cleanup"] == []
    # scenario_named_supervisor.py stays import-safe offline.
    assert v["named_supervisor_import_safe_offline"] is True
    assert v["closed"] is True


def test_gateway_lifecycle_evidence_is_account_scrubbed():
    """ARNs in the lifecycle evidence must be scrubbed to <ACCOUNT_ID>."""
    raw = (_EVIDENCE / "gateway_lifecycle_result.json").read_text(encoding="utf-8")
    _assert_no_real_account_id(raw)
    # The gateway ARN specifically must carry the placeholder, not a real acct id.
    assert "<ACCOUNT_ID>" in raw


def test_egress_control_evidence_if_present():
    """egress_control_result.json is OPTIONAL: only assert its shape if it exists.

    The M4 network posture (private VPC, no NAT/IGW, cost-gated endpoints) is proven
    by the network-stack synth + the live-deploy verdict's ``vpc_endpoints_cost_gated_off``
    flag. A dedicated egress-control evidence file is not required for M4 to be
    complete, so its absence is not a failure — but if present, it must parse and be
    account-scrubbed like every other evidence file.
    """
    path = _EVIDENCE / "egress_control_result.json"
    if not path.is_file():
        pytest.skip("egress_control_result.json not present (optional M4 evidence)")
    ev = json.loads(path.read_text(encoding="utf-8"))
    assert "verdict" in ev, "egress evidence must carry a 'verdict' block"
    _assert_no_real_account_id(path.read_text(encoding="utf-8"))


def _assert_no_real_account_id(raw: str) -> None:
    """Fail if a real 12-digit AWS account id leaked into a public evidence file.

    The only tolerated 12-digit run is the ``000000000000`` placeholder; anything
    else (e.g. the real dev account) must have been scrubbed to ``<ACCOUNT_ID>``.
    """
    import re

    for match in re.findall(r"\b\d{12}\b", raw):
        assert match == "000000000000", (
            f"evidence leaks a real 12-digit account id {match!r}; "
            "scrub to <ACCOUNT_ID> or the 000000000000 placeholder"
        )


# --------------------------------------------------------------------------- #
# (b) The CDK app synthesizes all 8 stacks.                                     #
#     Runs the LOCAL cdk (offline synth, no deploy). SKIPS if node_modules      #
#     is absent (importorskip-style guard via skipif on a computed condition).  #
# --------------------------------------------------------------------------- #
def _cdk_available() -> bool:
    """True iff the local CDK CLI + ts-node deps are installed (offline synth possible)."""
    cdk_bin = _IAC_CDK / "node_modules" / ".bin" / "cdk"
    ts_node = _IAC_CDK / "node_modules" / "ts-node"
    return cdk_bin.is_file() and ts_node.is_dir()


@pytest.mark.skipif(not _cdk_available(), reason="iac-cdk/node_modules absent — CDK synth needs a local install")
def test_cdk_app_synthesizes_all_eight_stacks(tmp_path):
    """`cdk synth` (offline, no deploy) produces exactly the expected stack set.

    That is the 8 M4 foundation stacks plus the specialist / long-running
    sentinel-runtime stack (9 total). We synth into a throwaway output dir so we
    never depend on / clobber the committed cdk.out, then read the manifest to
    confirm all expected CloudFormation stacks are present. Offline: `cdk synth`
    does not call AWS.
    """
    cdk_bin = _IAC_CDK / "node_modules" / ".bin" / "cdk"
    out_dir = tmp_path / "cdk.out"
    # `--all` synths every stack; `-o` isolates output; no `--no-lookups` needed
    # because the app uses static context only (no env-bound Fn lookups).
    env = dict(os.environ)
    env.setdefault("CDK_DISABLE_VERSION_CHECK", "1")
    proc = subprocess.run(
        [str(cdk_bin), "synth", "--all", "-o", str(out_dir)],
        cwd=str(_IAC_CDK),
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert proc.returncode == 0, f"cdk synth failed:\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"

    manifest_path = out_dir / "manifest.json"
    assert manifest_path.is_file(), f"cdk synth produced no manifest at {manifest_path}"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    synthed = {
        name
        for name, art in manifest.get("artifacts", {}).items()
        if art.get("type") == "aws:cloudformation:stack"
    }
    assert synthed == _EXPECTED_STACKS, (
        f"CDK synth stack set drifted.\n  expected: {sorted(_EXPECTED_STACKS)}\n"
        f"  got:      {sorted(synthed)}"
    )
    # Each stack must have emitted a template file (synth actually produced IaC).
    for stack in _EXPECTED_STACKS:
        assert (out_dir / f"{stack}.template.json").is_file(), f"{stack} template not emitted"


# --------------------------------------------------------------------------- #
# (c) gateway.cognito_jwt_authorizer builds the right customJWTAuthorizer shape.#
#     Pure in-process helper — fully offline, no AWS.                            #
# --------------------------------------------------------------------------- #
_DISCOVERY = (
    "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_pool/.well-known/openid-configuration"
)


def test_cognito_jwt_authorizer_human_audience_shape():
    """Human path (ID token has an ``aud`` claim) => allowedAudience, no allowedClients."""
    from sentinel_harness import gateway as gw

    cfg = gw.cognito_jwt_authorizer(_DISCOVERY, allowed_audience=["app-client-id"])
    assert cfg == {
        "customJWTAuthorizer": {
            "discoveryUrl": _DISCOVERY,
            "allowedAudience": ["app-client-id"],
        }
    }
    assert "allowedClients" not in cfg["customJWTAuthorizer"]


def test_cognito_jwt_authorizer_machine_clients_shape():
    """Machine path (M2M access token has NO ``aud``) => allowedClients, no allowedAudience."""
    from sentinel_harness import gateway as gw

    cfg = gw.cognito_jwt_authorizer(_DISCOVERY, allowed_clients=["m2m-client-id"])
    assert cfg == {
        "customJWTAuthorizer": {
            "discoveryUrl": _DISCOVERY,
            "allowedClients": ["m2m-client-id"],
        }
    }
    assert "allowedAudience" not in cfg["customJWTAuthorizer"]


def test_cognito_jwt_authorizer_rejects_ambiguous_config():
    """Neither / both audience+clients is a local misconfiguration — raised, not swallowed."""
    from sentinel_harness import gateway as gw

    with pytest.raises(ValueError, match="exactly one"):
        gw.cognito_jwt_authorizer(_DISCOVERY)
    with pytest.raises(ValueError, match="exactly one"):
        gw.cognito_jwt_authorizer(_DISCOVERY, allowed_audience=["a"], allowed_clients=["c"])


# --------------------------------------------------------------------------- #
# (d) sigma_match + bas_cases produce the deterministic blind-spot result.      #
#     Pure Python (no eval, no network, no AWS) — this is the M3->M4 L2 core.    #
# --------------------------------------------------------------------------- #
def _load_bas_cases_module():
    """Load longrunning/bas-runner/bas_cases.py by path (it is a scripts tree)."""
    import importlib.util

    path = _REPO_ROOT / "longrunning" / "bas-runner" / "bas_cases.py"
    assert path.is_file(), f"bas_cases module missing: {path}"
    spec = importlib.util.spec_from_file_location("smoke_bas_cases", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# A single rule that catches ONLY encoded-PowerShell (T1059.001), so the other
# three library techniques are provably blind spots — a deterministic outcome.
_POWERSHELL_ONLY_RULE = """
title: Suspicious PowerShell Encoded Command
id: 7e2b1c9a-1111-2222-3333-444455556666
status: experimental
level: high
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\\powershell.exe'
        CommandLine|contains: '-enc'
    condition: selection
"""


def test_bas_replay_deterministic_blind_spots():
    """One PowerShell rule catches T1059.001; the other 3 techniques are blind spots."""
    bas = _load_bas_cases_module()
    cases = bas.generate_cases()
    report = bas.replay(cases, [_POWERSHELL_ONLY_RULE])

    assert report["total_cases"] == 4
    assert report["detected_count"] == 1
    assert report["coverage"] == pytest.approx(0.25)
    # PowerShell caught; LSASS dump, network discovery, and run-key persistence missed.
    assert report["blind_spots"] == ["T1003.001", "T1046", "T1547.001"]

    # The one detected technique is T1059.001, matched by our rule's title.
    detected = [r for r in report["results"] if r["detected"]]
    assert [r["technique_id"] for r in detected] == ["T1059.001"]
    assert detected[0]["matched_rules"] == ["Suspicious PowerShell Encoded Command"]


def test_bas_replay_is_deterministic():
    """Same inputs -> byte-identical report (LLM-free, token-free, deterministic)."""
    bas = _load_bas_cases_module()
    cases = bas.generate_cases()
    a = bas.replay(cases, [_POWERSHELL_ONLY_RULE])
    b = bas.replay(cases, [_POWERSHELL_ONLY_RULE])
    assert a == b


def test_bas_replay_empty_ruleset_is_all_blind_spots():
    """No rules => nothing detected => every technique is a blind spot, coverage 0.0."""
    bas = _load_bas_cases_module()
    cases = bas.generate_cases()
    report = bas.replay(cases, [])
    assert report["detected_count"] == 0
    assert report["coverage"] == 0.0
    assert report["blind_spots"] == [c["technique_id"] for c in cases]


# --------------------------------------------------------------------------- #
# LIVE re-verification (opt-in only). Guarded by SENTINEL_SMOKE_LIVE=1 + creds.  #
# Absent the flag these SKIP — they never fail offline and never fake liveness.  #
# --------------------------------------------------------------------------- #
def _live_creds_available() -> bool:
    """True iff real AWS credentials resolve (so a live call could actually run)."""
    if not _LIVE:
        return False
    try:
        import boto3

        creds = boto3.Session().get_credentials()
        return creds is not None
    except Exception:
        return False


@pytest.mark.skipif(
    not _live_creds_available(),
    reason="live re-verification is opt-in: set SENTINEL_SMOKE_LIVE=1 with resolvable AWS creds",
)
def test_live_caller_identity_region():
    """LIVE: confirm we can reach STS and are operating in us-east-1 (M4 unified region).

    This is the minimal, non-destructive live probe: it proves credentials resolve
    against the real account without creating or mutating anything. Heavier live
    round-trips (gateway create/delete, apply_guardrail) are exercised by the M4
    scenarios themselves, not duplicated here.
    """
    import boto3

    session = boto3.Session()
    region = session.region_name or os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
    assert region == "us-east-1", f"M4 is unified on us-east-1; live session region is {region!r}"
    ident = session.client("sts", region_name="us-east-1").get_caller_identity()
    # Read-only: just confirm a well-formed account id came back (do NOT print it).
    assert ident["Account"].isdigit() and len(ident["Account"]) == 12
