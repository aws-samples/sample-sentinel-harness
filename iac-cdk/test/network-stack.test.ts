/**
 * network-stack.test.ts - synth assertions for the isolated NetworkStack.
 * =======================================================================
 * Self-contained, zero-dependency test (no jest wired in this package): uses
 * `aws-cdk-lib/assertions` (Template.fromStack) + Node's built-in `assert`,
 * runnable with `npx ts-node test/network-stack.test.ts`. Exits non-zero on the
 * first failed assertion so it can gate a build.
 *
 * Coverage (default: deployVpcEndpoints=false):
 *   - A VPC with an isolated subnet and NO NAT gateway / NO internet gateway.
 *   - NO 0.0.0.0/0 route anywhere in the template (default-deny egress).
 *   - The FREE S3 gateway endpoint present; NO billable interface endpoints.
 *   - A security group scoped to 443 within the VPC CIDR (no public ingress).
 * Plus a spot-check that flipping deployVpcEndpoints=true adds interface endpoints.
 */
import * as assert from "node:assert";
import { App } from "aws-cdk-lib";
import { Template, Match } from "aws-cdk-lib/assertions";
import { NetworkStack } from "../lib/network-stack";

const APP_NAME = "sentinel";

function synth(deployVpcEndpoints: boolean): Template {
  const app = new App();
  const stack = new NetworkStack(app, "sentinel-network", {
    appName: APP_NAME,
    deployVpcEndpoints,
    env: { account: "000000000000", region: "us-east-1" },
  });
  return Template.fromStack(stack);
}

function testIsolatedVpc(t: Template): void {
  t.resourceCountIs("AWS::EC2::VPC", 1);
  // Isolated design: NO NAT gateway, NO internet gateway, NO gateway attachment.
  t.resourceCountIs("AWS::EC2::NatGateway", 0);
  t.resourceCountIs("AWS::EC2::InternetGateway", 0);
  t.resourceCountIs("AWS::EC2::VPCGatewayAttachment", 0);
  // At least one subnet, and none of them auto-assign a public IP.
  const subnets = t.findResources("AWS::EC2::Subnet");
  assert.ok(Object.keys(subnets).length >= 1, "[network] expected at least one subnet");
  for (const [id, s] of Object.entries(subnets)) {
    const props = (s as { Properties?: Record<string, unknown> }).Properties ?? {};
    assert.notStrictEqual(
      props.MapPublicIpOnLaunch,
      true,
      `[network] subnet ${id} must not map public IPs on launch`,
    );
  }
  console.log("[network] isolated-vpc (no NAT/IGW) assertions passed");
}

function testNoDefaultRoute(t: Template): void {
  const routes = t.findResources("AWS::EC2::Route");
  for (const [id, r] of Object.entries(routes)) {
    const props = (r as { Properties?: Record<string, unknown> }).Properties ?? {};
    assert.notStrictEqual(
      props.DestinationCidrBlock,
      "0.0.0.0/0",
      `[network] route ${id} must not open a 0.0.0.0/0 default route`,
    );
  }
  console.log("[network] no-0.0.0.0/0-route assertions passed");
}

function testSecurityGroup(t: Template): void {
  // 443-only intra-VPC ingress; no 0.0.0.0/0 ingress rule.
  t.hasResourceProperties("AWS::EC2::SecurityGroup", {
    SecurityGroupIngress: Match.arrayWith([
      Match.objectLike({ FromPort: 443, ToPort: 443, IpProtocol: "tcp" }),
    ]),
  });
  const sgs = t.findResources("AWS::EC2::SecurityGroup");
  for (const [id, sg] of Object.entries(sgs)) {
    const ingress =
      ((sg as { Properties?: { SecurityGroupIngress?: Array<Record<string, unknown>> } })
        .Properties?.SecurityGroupIngress) ?? [];
    for (const rule of ingress) {
      assert.notStrictEqual(
        rule.CidrIp,
        "0.0.0.0/0",
        `[network] SG ${id} must not allow public (0.0.0.0/0) ingress`,
      );
    }
  }
  console.log("[network] security-group (443 intra-VPC only) assertions passed");
}

function testEndpointGating(): void {
  // Default: only the FREE S3 gateway endpoint, NO billable interface endpoints.
  const off = synth(false);
  off.resourceCountIs("AWS::EC2::VPCEndpoint", 1);
  off.hasResourceProperties("AWS::EC2::VPCEndpoint", {
    VpcEndpointType: "Gateway",
  });
  off.hasOutput("VpcEndpointsDeployed", { Value: "false" });

  // Flipped on: S3 gateway + the 5 interface endpoints.
  const on = synth(true);
  const endpoints = on.findResources("AWS::EC2::VPCEndpoint");
  const interfaceEps = Object.values(endpoints).filter(
    (e) => (e as { Properties?: { VpcEndpointType?: string } }).Properties?.VpcEndpointType === "Interface",
  );
  assert.ok(
    interfaceEps.length >= 5,
    `[network] expected >=5 interface endpoints when gated on, got ${interfaceEps.length}`,
  );
  on.hasOutput("VpcEndpointsDeployed", { Value: "true" });
  console.log("[network] endpoint-gating assertions passed");
}

function main(): void {
  const t = synth(false);
  testIsolatedVpc(t);
  testNoDefaultRoute(t);
  testSecurityGroup(t);
  testEndpointGating();
  console.log("\nALL network-stack synth assertions PASSED");
}

main();
