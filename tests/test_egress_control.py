"""Offline tests for scenario_egress_control — the M4 default-deny egress proof.

100% offline, ZERO AWS/network. We monkeypatch a fake EC2 client and assert the
unit-testable core (:func:`classify_egress`) classifies two topologies correctly:

  (a) an ISOLATED VPC — no IGW attached, no 0.0.0.0/0 route -> egress_default_deny True,
  (b) a VPC WITH an IGW + a default route -> egress_default_deny False.

We also assert importing the scenario module makes no AWS call (all boto3 work is
guarded under build()/run()/__main__), and that read_network_outputs treats a
missing stack as "not deployed" (returns None) rather than raising.
"""
from __future__ import annotations

import importlib
import os
import sys
from typing import Any, Dict, List

import pytest

# Dummy env so anything that ever builds a boto3 client stays offline-safe.
os.environ.setdefault("SENTINEL_EXECUTION_ROLE_ARN", "arn:aws:iam::000000000000:role/test")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import scenarios.scenario_egress_control as eg  # noqa: E402


# --------------------------------------------------------------------------
# Fake EC2 client — a plain object returning canned describe_* responses. It
# makes NO network call; it only proves classify_egress reads the shapes right.
# --------------------------------------------------------------------------
class FakeEc2:
    def __init__(
        self,
        *,
        internet_gateways: List[Dict[str, Any]],
        route_tables: List[Dict[str, Any]],
        subnets: List[Dict[str, Any]],
        vpc_endpoints: List[Dict[str, Any]],
    ) -> None:
        self._igws = internet_gateways
        self._rts = route_tables
        self._subnets = subnets
        self._eps = vpc_endpoints
        self.calls: List[str] = []

    def describe_internet_gateways(self, **_kw: Any) -> Dict[str, Any]:
        self.calls.append("describe_internet_gateways")
        return {"InternetGateways": self._igws}

    def describe_route_tables(self, **_kw: Any) -> Dict[str, Any]:
        self.calls.append("describe_route_tables")
        return {"RouteTables": self._rts}

    def describe_subnets(self, **_kw: Any) -> Dict[str, Any]:
        self.calls.append("describe_subnets")
        return {"Subnets": self._subnets}

    def describe_vpc_endpoints(self, **_kw: Any) -> Dict[str, Any]:
        self.calls.append("describe_vpc_endpoints")
        return {"VpcEndpoints": self._eps}


def _interface_endpoints(region: str = "us-east-1") -> List[Dict[str, Any]]:
    """All required PrivateLink interface endpoints, available."""
    services = {
        "bedrock-agentcore": f"com.amazonaws.{region}.bedrock-agentcore",
        "logs": f"com.amazonaws.{region}.logs",
        "ecr.api": f"com.amazonaws.{region}.ecr.api",
        "ecr.dkr": f"com.amazonaws.{region}.ecr.dkr",
        "sts": f"com.amazonaws.{region}.sts",
    }
    return [
        {"VpcEndpointType": "Interface", "State": "available", "ServiceName": name}
        for name in services.values()
    ]


def _isolated_ec2() -> FakeEc2:
    """Topology (a): no IGW, an isolated route table with only the local route,
    an isolated subnet, and all interface endpoints present."""
    return FakeEc2(
        internet_gateways=[],  # no IGW attached
        route_tables=[
            {
                "RouteTableId": "rtb-isolated",
                "Associations": [{"Main": True}, {"SubnetId": "subnet-iso", "Main": False}],
                # Only the implicit local route; no 0.0.0.0/0.
                "Routes": [{"DestinationCidrBlock": "10.0.0.0/24", "GatewayId": "local"}],
            }
        ],
        subnets=[{"SubnetId": "subnet-iso"}],
        vpc_endpoints=_interface_endpoints(),
    )


def _public_ec2() -> FakeEc2:
    """Topology (b): an IGW attached + a route table with a 0.0.0.0/0 -> igw route
    associated to the subnet. This is a classic public subnet -> NOT default-deny."""
    return FakeEc2(
        internet_gateways=[{"InternetGatewayId": "igw-abc123"}],
        route_tables=[
            {
                "RouteTableId": "rtb-public",
                "Associations": [{"SubnetId": "subnet-pub", "Main": False}],
                "Routes": [
                    {"DestinationCidrBlock": "10.0.0.0/24", "GatewayId": "local"},
                    {"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-abc123"},
                ],
            }
        ],
        subnets=[{"SubnetId": "subnet-pub"}],
        vpc_endpoints=[],
    )


# --------------------------------------------------------------------------
# Core classification tests.
# --------------------------------------------------------------------------
def test_isolated_vpc_is_default_deny():
    ec2 = _isolated_ec2()
    v = eg.classify_egress(ec2, "vpc-iso")
    assert v["no_igw"] is True
    assert v["no_default_route_to_internet"] is True
    assert v["isolated_subnet"] is True
    assert v["egress_default_deny"] is True
    # All required PrivateLink endpoints detected.
    assert v["privatelink_endpoints_present"] == sorted(eg.REQUIRED_ENDPOINT_SUFFIXES)
    # No internet route tables flagged.
    assert v["internet_route_tables"] == []


def test_public_vpc_is_not_default_deny():
    ec2 = _public_ec2()
    v = eg.classify_egress(ec2, "vpc-pub")
    assert v["no_igw"] is False
    assert v["no_default_route_to_internet"] is False
    assert v["egress_default_deny"] is False
    # The public route table is flagged as having an internet-bound default route.
    assert v["internet_route_tables"] == ["rtb-public"]
    # No endpoints deployed in this topology.
    assert v["privatelink_endpoints_present"] == []


def test_nat_default_route_also_counts_as_internet():
    """A 0.0.0.0/0 -> NAT gateway route (no IGW attached) still means egress is
    NOT default-deny: NAT is default-allow to the internet."""
    ec2 = FakeEc2(
        internet_gateways=[],  # NAT VPCs do have an IGW in practice, but test the route logic alone
        route_tables=[
            {
                "RouteTableId": "rtb-nat",
                "Associations": [{"SubnetId": "subnet-priv", "Main": False}],
                "Routes": [
                    {"DestinationCidrBlock": "10.0.0.0/24", "GatewayId": "local"},
                    {"DestinationCidrBlock": "0.0.0.0/0", "NatGatewayId": "nat-0abc"},
                ],
            }
        ],
        subnets=[{"SubnetId": "subnet-priv"}],
        vpc_endpoints=[],
    )
    v = eg.classify_egress(ec2, "vpc-nat")
    assert v["no_igw"] is True  # no IGW in this crafted case...
    assert v["no_default_route_to_internet"] is False  # ...but the NAT route is caught
    assert v["egress_default_deny"] is False


def test_pending_and_partial_endpoints():
    """pendingAcceptance endpoints count as present; a missing one is absent."""
    eps = _interface_endpoints()
    eps[0]["State"] = "pendingAcceptance"  # bedrock-agentcore pending -> still present
    eps = [e for e in eps if not e["ServiceName"].endswith(".sts")]  # drop sts
    ec2 = FakeEc2(
        internet_gateways=[],
        route_tables=[{"RouteTableId": "rtb", "Associations": [{"Main": True}], "Routes": []}],
        subnets=[{"SubnetId": "s"}],
        vpc_endpoints=eps,
    )
    v = eg.classify_egress(ec2, "vpc-x")
    assert "bedrock-agentcore" in v["privatelink_endpoints_present"]
    assert "sts" not in v["privatelink_endpoints_present"]


def test_ipv6_default_route_counts():
    """A ::/0 route to an egress-only IGW is also internet-bound."""
    ec2 = FakeEc2(
        internet_gateways=[],
        route_tables=[
            {
                "RouteTableId": "rtb-v6",
                "Associations": [{"Main": True}],
                "Routes": [
                    {"DestinationIpv6CidrBlock": "::/0", "EgressOnlyInternetGatewayId": "eigw-0a"},
                ],
            }
        ],
        subnets=[{"SubnetId": "s"}],
        vpc_endpoints=[],
    )
    v = eg.classify_egress(ec2, "vpc-v6")
    assert v["no_default_route_to_internet"] is False
    assert v["egress_default_deny"] is False


# --------------------------------------------------------------------------
# Offline-safety + honesty tests.
# --------------------------------------------------------------------------
def test_import_is_offline_safe():
    """Reimporting the module must not touch AWS — module-level code builds no
    boto3 client and needs no network."""
    importlib.reload(eg)
    assert callable(eg.classify_egress)
    assert callable(eg.build)
    assert callable(eg.run)


def test_read_network_outputs_missing_stack_returns_none():
    """A ValidationError 'stack does not exist' -> None (not an exception), so the
    scenario can print honest deploy guidance instead of crashing."""

    class FakeCfn:
        def describe_stacks(self, **_kw: Any) -> Dict[str, Any]:
            raise Exception("Stack with id sentinel-network does not exist (ValidationError)")

    assert eg.read_network_outputs(FakeCfn(), "sentinel-network") is None


def test_read_network_outputs_parses_outputs():
    class FakeCfn:
        def describe_stacks(self, **_kw: Any) -> Dict[str, Any]:
            return {"Stacks": [{"Outputs": [
                {"OutputKey": "VpcId", "OutputValue": "vpc-123"},
                {"OutputKey": "VpcEndpointsDeployed", "OutputValue": "true"},
            ]}]}

    outs = eg.read_network_outputs(FakeCfn(), "sentinel-network")
    assert outs == {"VpcId": "vpc-123", "VpcEndpointsDeployed": "true"}
    assert eg._endpoints_expected(outs) is True


def test_read_network_outputs_reraises_unexpected_error():
    """A non-'missing' error (e.g. AccessDenied) must propagate — we never hide a
    permissions problem behind a fake 'not deployed'."""

    class FakeCfn:
        def describe_stacks(self, **_kw: Any) -> Dict[str, Any]:
            raise Exception("AccessDenied: not authorized to DescribeStacks")

    with pytest.raises(Exception, match="AccessDenied"):
        eg.read_network_outputs(FakeCfn(), "sentinel-network")


def test_run_records_honest_not_deployed_verdict():
    """When build() couldn't resolve a VPC, run() records closed=false with a
    deploy note and makes no AWS call (no ec2 client involved)."""
    ctx = {"vpc_id": None, "endpoints_expected": False, "region": "us-east-1",
           "reason": "network stack not deployed; deploy sentinel-network first"}
    result = eg.run(ctx)
    v = result["verdict"]
    assert v["closed"] is False
    assert v["egress_default_deny"] is False
    assert "deploy sentinel-network" in v["note"]
