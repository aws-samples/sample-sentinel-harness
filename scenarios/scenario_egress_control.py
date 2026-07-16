"""
Scenario — LIVE validation of default-deny egress (M4 acceptance proof)
=======================================================================
Layer 4 (Governance & Isolation) · the network-isolation guarantee.

WHY this scenario exists
------------------------
``docs/BLUEPRINT.md`` §2/§5 promises that a SecOps harness "cannot phone home to
the open internet": it lands in a PRIVATE_ISOLATED subnet with NO NAT and NO
Internet Gateway, and reaches the handful of AWS APIs it genuinely needs over
PrivateLink interface endpoints + the free S3 gateway endpoint. Every other M4
item (Guardrail masking, Cognito identity, observability) has a live, evidence-
producing proof. This is the ONE remaining M4 acceptance item that was asserted
by construction (the CDK ``NetworkStack``) but never *validated against a
deployed VPC*. This scenario closes that gap.

WHY topology inspection instead of a probe instance
---------------------------------------------------
The naive "proof" is to launch an EC2 instance in the isolated subnet and watch
``curl https://example.com`` hang while ``aws sts get-caller-identity`` succeeds
over PrivateLink. That is slow (minutes to boot), costly (instance + endpoint
hours), and — crucially — WEAKER evidence: a single timed-out request does not
prove there is *no* egress path, only that *one* attempt failed. Inspecting the
topology deterministically is STRONGER and CHEAPER: if the VPC has no IGW
attached and no route table carries a ``0.0.0.0/0`` route to an IGW or NAT, then
public egress is not "filtered", it is *physically unroutable* — there is nowhere
for a packet destined off-VPC to go. We assert exactly that, and separately
confirm the sanctioned PrivateLink interface endpoints exist so the AWS-service
path is genuinely open. This is real, evidence-producing proof read straight off
the live VPC's routing state.

What is LIVE vs offline (be scrupulous)
---------------------------------------
- LIVE (guarded under ``build`` / ``run`` with creds): reads the deployed
  ``sentinel-network`` CloudFormation stack outputs (or accepts vpcId via
  env/args) and describes the VPC's IGWs, route tables, subnets, and VPC
  endpoints with read-only EC2 API calls. No instance is launched; nothing is
  created or mutated.
- OFFLINE / unit-testable: :func:`classify_egress` takes a boto3 EC2 client +
  vpcId and computes the verdict booleans deterministically. Tests monkeypatch a
  fake EC2 client, so importing this module makes ZERO AWS calls.

Honesty: if the network stack is not deployed, :func:`run` says so plainly and
records ``closed=false`` with a "deploy sentinel-network first" note. It never
fabricates a passing verdict.

All content is generic infrastructure security — no org-specific data. Evidence
scrubs the account id out of any ARN before it is written.
"""
from __future__ import annotations

import json
import os
import re
import sys
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Name of the deployed network CloudFormation stack (bin/sentinel.ts:
# `new NetworkStack(app, `${appName}-network`, ...)` with default appName
# "sentinel"). Overridable via env for a differently-named deploy.
NETWORK_STACK_NAME = os.environ.get("SENTINEL_NETWORK_STACK", "sentinel-network")

# CfnOutput logical ids emitted by NetworkStack (lib/network-stack.ts).
OUT_VPC_ID = "VpcId"
OUT_SUBNET_IDS = "IsolatedSubnetIds"
OUT_SECURITY_GROUP_ID = "SecurityGroupId"
OUT_ENDPOINTS_DEPLOYED = "VpcEndpointsDeployed"

# The interface (PrivateLink) endpoints NetworkStack provisions when
# `deployVpcEndpoints` is on. Keyed by the service-name suffix that appears in
# `ServiceName` (com.amazonaws.<region>.<suffix>). bedrock-agentcore has no named
# CDK enum and is built explicitly; the rest come from AWS-managed enums.
REQUIRED_ENDPOINT_SUFFIXES: List[str] = [
    "bedrock-agentcore",
    "logs",
    "ecr.api",
    "ecr.dkr",
    "sts",
]

RESULT: Dict[str, Any] = {"scenario": "egress_control_default_deny", "steps": []}

# Account-id scrubber — identical pattern to the other scenarios. Masks the
# 12-digit account id inside any ARN to <ACCOUNT_ID> before evidence is written.
_ACCT_RE = re.compile(r"(arn:aws[^:]*:[^:]*:[^:]*:)\d{12}(:)")


def _scrub(obj: Any) -> Any:
    if isinstance(obj, str):
        return _ACCT_RE.sub(r"\1<ACCOUNT_ID>\2", obj)
    if isinstance(obj, dict):
        return {k: _scrub(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_scrub(v) for v in obj]
    return obj


def rec(step: str, data: Any) -> None:
    data = _scrub(data)
    RESULT["steps"].append({"step": step, "data": data})
    print(f"[{step}] {json.dumps(data, ensure_ascii=False, default=str)[:220]}", flush=True)


# --------------------------------------------------------------------------
# The unit-testable core: given a boto3 EC2 client + vpcId, deterministically
# compute the egress-control verdict booleans by INSPECTING live topology.
# --------------------------------------------------------------------------
def classify_egress(ec2_client: Any, vpc_id: str) -> Dict[str, Any]:
    """Inspect a VPC and decide whether egress is default-deny.

    Read-only. Makes four kinds of EC2 describe calls (all filtered to
    ``vpc_id``): internet gateways, route tables, subnets, and VPC endpoints.
    Returns a verdict dict with the booleans the scenario records.

    Definitions (deterministic, no heuristics):
      * ``no_igw``: the VPC has NO Internet Gateway attached. Without an IGW there
        is no device that can forward a packet to the public internet, regardless
        of routes.
      * ``no_default_route_to_internet``: NO route table in the VPC carries a
        ``0.0.0.0/0`` (or ``::/0``) route whose target is an IGW (``igw-``),
        NAT gateway (``nat-``), or egress-only IGW (``eigw-``). Such a route is
        the only way a subnet learns a path off-VPC to the internet.
      * ``isolated_subnet``: at least one subnet in the VPC is associated with a
        route table that has NO internet-bound default route (an isolated subnet).
        A subnet with no explicit association uses the VPC main route table, which
        is likewise checked.
      * ``privatelink_endpoints_present``: the sorted list of required interface
        endpoint service suffixes that are present with an ``available`` (or
        ``pendingAcceptance``) interface endpoint in the VPC.
      * ``egress_default_deny``: ``no_igw and no_default_route_to_internet`` — the
        core guarantee. If both hold, an off-VPC/internet destination is
        unroutable, so egress is deny-by-topology, not by filtering.

    We never swallow exceptions: any EC2 API error propagates to the caller so a
    permissions/region problem is not silently misreported as a passing verdict.
    """
    # --- Internet gateways attached to this VPC. ---
    igw_resp = ec2_client.describe_internet_gateways(
        Filters=[{"Name": "attachment.vpc-id", "Values": [vpc_id]}]
    )
    igws = igw_resp.get("InternetGateways", [])
    no_igw = len(igws) == 0

    # --- Route tables: hunt for any internet-bound default route. ---
    rt_resp = ec2_client.describe_route_tables(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
    )
    route_tables = rt_resp.get("RouteTables", [])

    # Route-target fields (top-level keys in a boto3 Route) that forward a default
    # route OFF the VPC toward the public internet — directly (IGW/NAT/EIGW) or via
    # another network (Transit Gateway, NAT instance, VPC peering, carrier/vgw). The
    # ONLY containing target for a 0.0.0.0/0 route is the implicit "local" route,
    # which never has a 0.0.0.0/0 destination anyway. We enumerate the escape targets
    # and FAIL CLOSED on anything else (see _is_internet_default_route).
    _INTERNET_TARGET_FIELDS = (
        "NatGatewayId", "TransitGatewayId", "InstanceId", "NetworkInterfaceId",
        "VpcPeeringConnectionId", "CarrierGatewayId", "EgressOnlyInternetGatewayId",
        "LocalGatewayId", "CoreNetworkArn", "VpcEndpointId",
    )

    def _is_internet_default_route(route: Dict[str, Any]) -> bool:
        """A default route (0.0.0.0/0 or ::/0) whose target can reach the internet.

        FAIL CLOSED: a default route is treated as internet-capable unless its ONLY
        target is the implicit ``local`` gateway. The prior allowlist recognized only
        igw-/eigw-/NatGateway and MISSED off-VPC escapes — a 0.0.0.0/0 route via a
        Transit Gateway (the standard AWS centralized-egress pattern), a NAT instance
        (InstanceId/NetworkInterfaceId), VPC peering, or a carrier gateway — so a VPC
        with full internet egress was falsely certified "contained"."""
        dest = route.get("DestinationCidrBlock") or route.get("DestinationIpv6CidrBlock")
        if dest not in ("0.0.0.0/0", "::/0"):
            return False
        gw = route.get("GatewayId") or ""
        if gw == "local":
            return False  # the implicit in-VPC route — the only contained target
        if gw.startswith("igw-") or gw.startswith("eigw-"):
            return True
        if any(route.get(f) for f in _INTERNET_TARGET_FIELDS):
            return True
        # A default route with SOME other/unknown non-local target is treated as
        # internet-capable (fail closed) rather than silently assumed contained.
        return bool(gw) or any(
            v for k, v in route.items()
            if k.endswith("Id") or k.endswith("Arn")
        )

    def _rt_has_internet_route(rt: Dict[str, Any]) -> bool:
        return any(_is_internet_default_route(r) for r in rt.get("Routes", []))

    internet_route_tables = [
        rt.get("RouteTableId") for rt in route_tables if _rt_has_internet_route(rt)
    ]
    no_default_route_to_internet = len(internet_route_tables) == 0

    # --- Subnets: is at least one isolated (its route table has no internet route)? ---
    # Map each explicitly-associated subnet to its route table's internet status;
    # subnets with no explicit association fall back to the VPC main route table.
    main_rt_has_internet = any(
        _rt_has_internet_route(rt)
        for rt in route_tables
        if any(a.get("Main") for a in rt.get("Associations", []))
    )
    subnet_resp = ec2_client.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
    )
    subnets = subnet_resp.get("Subnets", [])
    explicit_assoc: Dict[str, bool] = {}
    for rt in route_tables:
        has_inet = _rt_has_internet_route(rt)
        for a in rt.get("Associations", []):
            sid = a.get("SubnetId")
            if sid:
                explicit_assoc[sid] = has_inet
    isolated_subnet = False
    for s in subnets:
        sid = s.get("SubnetId")
        has_inet = explicit_assoc.get(sid, main_rt_has_internet)
        if not has_inet:
            isolated_subnet = True
            break

    # --- VPC interface endpoints (the sanctioned PrivateLink path). ---
    ep_resp = ec2_client.describe_vpc_endpoints(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
    )
    endpoints = ep_resp.get("VpcEndpoints", [])
    present_suffixes: set[str] = set()
    for ep in endpoints:
        if ep.get("VpcEndpointType") != "Interface":
            continue
        if ep.get("State") not in ("available", "pendingAcceptance", "pending"):
            continue
        service = ep.get("ServiceName", "")
        # ServiceName looks like com.amazonaws.<region>.<suffix> (suffix may
        # contain dots, e.g. ecr.api). Match against our required suffixes.
        for suffix in REQUIRED_ENDPOINT_SUFFIXES:
            if service.endswith("." + suffix) or service.endswith(suffix):
                present_suffixes.add(suffix)
    privatelink_endpoints_present = sorted(present_suffixes)

    egress_default_deny = no_igw and no_default_route_to_internet

    return {
        "vpc_id": vpc_id,
        "isolated_subnet": isolated_subnet,
        "no_igw": no_igw,
        "no_default_route_to_internet": no_default_route_to_internet,
        "internet_route_tables": internet_route_tables,
        "privatelink_endpoints_present": privatelink_endpoints_present,
        "egress_default_deny": egress_default_deny,
    }


# --------------------------------------------------------------------------
# Live wiring: read the deployed stack outputs, then classify.
# --------------------------------------------------------------------------
def read_network_outputs(cfn_client: Any, stack_name: str = NETWORK_STACK_NAME) -> Optional[Dict[str, str]]:
    """Return the network stack's outputs as a dict, or None if it isn't deployed.

    Distinguishes "stack does not exist" (returns None so the caller can print
    honest deploy guidance) from any other error (which propagates — we do not
    hide a permissions/throttling problem behind a fake "not deployed").
    """
    try:
        resp = cfn_client.describe_stacks(StackName=stack_name)
    except Exception as e:  # noqa: BLE001 — inspect the error, re-raise if not "missing"
        msg = str(e)
        if "does not exist" in msg or "ValidationError" in msg:
            return None
        raise
    stacks = resp.get("Stacks", [])
    if not stacks:
        return None
    outputs = {}
    for o in stacks[0].get("Outputs", []):
        outputs[o.get("OutputKey")] = o.get("OutputValue")
    return outputs


def _endpoints_expected(outputs: Dict[str, str]) -> bool:
    """Whether the deploy provisioned interface endpoints (VpcEndpointsDeployed=true)."""
    return str(outputs.get(OUT_ENDPOINTS_DEPLOYED, "")).lower() == "true"


def build() -> Dict[str, Any]:
    """Resolve the target VPC id + endpoint expectation from the live environment.

    Order of resolution (first hit wins):
      1. ``SENTINEL_VPC_ID`` env var (and ``SENTINEL_VPC_ENDPOINTS_DEPLOYED``).
      2. CloudFormation outputs of the ``sentinel-network`` stack.

    Guarded here (called only from :func:`run` / ``__main__``) so importing the
    module never builds a boto3 client. Returns a context dict; if the network is
    not resolvable, ``vpc_id`` is None and ``reason`` explains why.
    """
    import boto3  # imported lazily so import of this module is offline-safe

    region = os.environ.get("SENTINEL_REGION") or os.environ.get("AWS_REGION") or "us-east-1"

    env_vpc = os.environ.get("SENTINEL_VPC_ID")
    if env_vpc:
        endpoints_expected = str(
            os.environ.get("SENTINEL_VPC_ENDPOINTS_DEPLOYED", "true")
        ).lower() == "true"
        rec("resolved_vpc", {"source": "env", "vpc_id": env_vpc,
                             "endpoints_expected": endpoints_expected})
        return {"vpc_id": env_vpc, "endpoints_expected": endpoints_expected,
                "region": region, "reason": None}

    cfn = boto3.client("cloudformation", region_name=region)
    outputs = read_network_outputs(cfn)
    if outputs is None:
        rec("resolved_vpc", {"source": "cloudformation", "vpc_id": None,
                             "stack": NETWORK_STACK_NAME, "deployed": False})
        return {"vpc_id": None, "endpoints_expected": False, "region": region,
                "reason": (
                    f"CloudFormation stack '{NETWORK_STACK_NAME}' is not deployed. "
                    "Deploy it first, e.g.:\n"
                    "    cd iac-cdk && npx cdk deploy sentinel-network "
                    "-c sentinel:deployVpcEndpoints=true\n"
                    "(or set SENTINEL_VPC_ID=<vpc-...> to point at an existing VPC)."
                )}
    vpc_id = outputs.get(OUT_VPC_ID)
    endpoints_expected = _endpoints_expected(outputs)
    rec("resolved_vpc", {"source": "cloudformation", "vpc_id": vpc_id,
                         "stack": NETWORK_STACK_NAME, "deployed": True,
                         "endpoints_expected": endpoints_expected})
    return {"vpc_id": vpc_id, "endpoints_expected": endpoints_expected,
            "region": region, "reason": None}


def run(ctx: Dict[str, Any]) -> Dict[str, Any]:
    """Classify the resolved VPC and record the scrubbed egress-control verdict.

    If the network is not deployed/resolvable, record ``closed=false`` with an
    honest "deploy sentinel-network first" note and return — no AWS inspection.
    """
    vpc_id = ctx.get("vpc_id")
    if not vpc_id:
        RESULT["verdict"] = {
            "isolated_subnet": False,
            "no_igw": False,
            "no_default_route_to_internet": False,
            "privatelink_endpoints_present": [],
            "egress_default_deny": False,
            "closed": False,
            "note": ctx.get("reason")
            or "network stack not deployed; deploy sentinel-network -c "
               "sentinel:deployVpcEndpoints=true first",
        }
        rec("not_deployed", RESULT["verdict"])
        return RESULT

    import boto3  # lazy, offline-safe

    ec2 = boto3.client("ec2", region_name=ctx["region"])
    verdict = classify_egress(ec2, vpc_id)
    rec("classify", verdict)

    endpoints_expected = ctx.get("endpoints_expected", False)
    present = verdict["privatelink_endpoints_present"]
    # If endpoints were deployed, all required ones must be present for the
    # sanctioned AWS-service path to be genuinely usable. If they were NOT
    # deployed, their absence is expected (free-S3-only mode) and does not
    # weaken the default-deny guarantee — but we say so explicitly.
    endpoints_ok = (not endpoints_expected) or (
        set(REQUIRED_ENDPOINT_SUFFIXES).issubset(set(present))
    )
    missing = sorted(set(REQUIRED_ENDPOINT_SUFFIXES) - set(present))

    closed = (
        verdict["egress_default_deny"]
        and verdict["isolated_subnet"]
        and endpoints_ok
    )

    if endpoints_expected:
        endpoints_note = (
            f"PrivateLink interface endpoints present for {present}"
            + (f"; MISSING {missing}" if missing else " (all required present)")
        )
    else:
        endpoints_note = (
            "interface endpoints not deployed (VpcEndpointsDeployed=false): free "
            "S3 gateway endpoint only. The default-deny topology still holds; the "
            "sanctioned AWS-service path is unproven until -c "
            "sentinel:deployVpcEndpoints=true is deployed."
        )

    RESULT["verdict"] = {
        "isolated_subnet": verdict["isolated_subnet"],
        "no_igw": verdict["no_igw"],
        "no_default_route_to_internet": verdict["no_default_route_to_internet"],
        "privatelink_endpoints_present": present,
        "egress_default_deny": verdict["egress_default_deny"],
        "closed": closed,
        "note": (
            "LIVE topology inspection of the deployed private VPC (no probe "
            "instance launched). egress_default_deny = no IGW attached AND no "
            "route table with a 0.0.0.0/0 route to an IGW/NAT — public egress is "
            "unroutable, not merely filtered. " + endpoints_note
        ),
    }
    rec("verdict", RESULT["verdict"])
    return RESULT


if __name__ == "__main__":
    context = build()
    run(context)
    out = os.path.join(os.path.dirname(__file__), "..", "evidence", "egress_control_result.json")
    json.dump(_scrub(RESULT), open(out, "w"), indent=2, ensure_ascii=False, default=str)
    print("\nsaved evidence/egress_control_result.json  ·  verdict:", RESULT.get("verdict"))
