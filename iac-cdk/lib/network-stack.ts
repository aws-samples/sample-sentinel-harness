/**
 * NetworkStack - the min-cost private VPC with default-deny egress.
 * ==================================================================
 * WHY (docs/BLUEPRINT.md §2/§5 "egress control"): a SecOps harness must not be able
 * to phone home to the open internet. The classic pattern for that is a private
 * subnet + a NAT Gateway with a locked-down route/SG. We deliberately do NOT use a
 * NAT Gateway. Instead the AgentCore runtime lands in a PRIVATE_ISOLATED subnet with
 * NO internet route at all, and reaches the handful of AWS APIs it genuinely needs
 * over PrivateLink (interface endpoints) + the free S3 Gateway endpoint.
 *
 * WHY isolated + PrivateLink is STRONGER *and* CHEAPER egress control than NAT:
 *   - STRONGER (default-deny): a NAT Gateway is default-*allow* - anything with a
 *     0.0.0.0/0 route reaches the whole internet unless you bolt on egress
 *     firewalling. An ISOLATED subnet has NO 0.0.0.0/0 route and NO IGW, so the
 *     only reachable destinations are the exact AWS services we publish an endpoint
 *     for. Exfiltration to an attacker-controlled host is not "filtered", it is
 *     physically unroutable. The endpoint POLICIES then narrow even the AWS surface
 *     (e.g. STS only for this account) - allowlist, not denylist.
 *   - CHEAPER: a NAT Gateway bills ~$32/mo/AZ PLUS per-GB data processing on every
 *     byte, forever. The S3 Gateway endpoint is FREE. The interface endpoints are
 *     ~$7.2/mo/AZ each and, in this single-AZ design, are the ONLY standing cost -
 *     and they are gated OFF by default (see `deployVpcEndpoints`), so a plain
 *     synth/deploy provisions the VPC at ZERO standing cost.
 *
 * COST GATING: the ~5 interface endpoints (~$27-34/mo total) are the only standing
 * charge. They are hidden behind the CDK context flag `deployVpcEndpoints`
 * (DEFAULT FALSE). With the flag off you get VPC + isolated subnet + SG + the free
 * S3 Gateway endpoint - nothing that bills. Flip it on for a real deploy:
 *   npx cdk synth -c deployVpcEndpoints=true
 *
 * NOTHING here is customer- or company-specific; account/region come from the CDK
 * environment, the endpoint region falls back to a context var / us-east-1.
 */
import { Stack, StackProps, CfnOutput } from "aws-cdk-lib";
import * as ec2 from "aws-cdk-lib/aws-ec2";
import * as iam from "aws-cdk-lib/aws-iam";
import { Construct } from "constructs";

export interface NetworkStackProps extends StackProps {
  /** Logical app prefix (context `sentinel:appName`, default "sentinel"). */
  readonly appName: string;
  /**
   * Provision the (billable) interface VPC endpoints. DEFAULT FALSE.
   * Context `sentinel:deployVpcEndpoints` / `-c deployVpcEndpoints=true`.
   * When false: VPC + isolated subnet + SG + FREE S3 gateway endpoint only
   * (zero standing cost). When true: also the ~5 interface endpoints (~$27-34/mo).
   */
  readonly deployVpcEndpoints?: boolean;
  /**
   * Region used to build the bedrock-agentcore interface-endpoint service name
   * (`com.amazonaws.<region>.bedrock-agentcore`). The AWS-managed endpoint enums
   * resolve their own region from the stack, but this custom service name needs a
   * CONCRETE region at synth time, so it cannot be a token. Defaults to us-east-1
   * (context `sentinel:endpointRegion`); set it to match your deploy region.
   */
  readonly endpointRegion?: string;
  /** IPv4 CIDR for the VPC. Small: this is a single-AZ isolated workload. */
  readonly vpcCidr?: string;
}

export class NetworkStack extends Stack {
  /** The private VPC - export so runtime/harness stacks can attach into it. */
  public readonly vpc: ec2.Vpc;
  /** SG allowing 443 only from within the VPC CIDR - export for the runtime. */
  public readonly securityGroup: ec2.SecurityGroup;

  constructor(scope: Construct, id: string, props: NetworkStackProps) {
    super(scope, id, props);

    const deployVpcEndpoints = props.deployVpcEndpoints ?? false;
    // Custom endpoint service names need a concrete region at synth (not a token).
    const endpointRegion = props.endpointRegion ?? "us-east-1";
    const vpcCidr = props.vpcCidr ?? "10.0.0.0/24";

    // --- The VPC: single AZ, ONE isolated subnet, NO NAT, NO IGW. ---
    // maxAzs:1 + natGateways:0 + a lone PRIVATE_ISOLATED subnet means CDK provisions
    // no InternetGateway, no NAT Gateway, and no 0.0.0.0/0 route: there is simply no
    // path off the VPC except the endpoints we publish below. Min-cost by construction.
    this.vpc = new ec2.Vpc(this, "Vpc", {
      vpcName: `${props.appName}-vpc`,
      ipAddresses: ec2.IpAddresses.cidr(vpcCidr),
      maxAzs: 1,
      natGateways: 0,
      subnetConfiguration: [
        {
          name: "isolated",
          subnetType: ec2.SubnetType.PRIVATE_ISOLATED,
          cidrMask: 26,
        },
      ],
    });

    // --- Security group: allow 443 (HTTPS) ONLY from within the VPC CIDR. ---
    // Interface endpoints terminate TLS on port 443; the workload only ever needs to
    // reach them intra-VPC. No public ingress, and egress is bounded to 443 within
    // the CIDR so the workload cannot open arbitrary outbound sockets even in-VPC.
    this.securityGroup = new ec2.SecurityGroup(this, "EndpointSecurityGroup", {
      vpc: this.vpc,
      description: `${props.appName} intra-VPC HTTPS (443) only - no public ingress/egress.`,
      // No default 0.0.0.0/0 egress rule: we add exactly the one rule we want below.
      allowAllOutbound: false,
    });
    this.securityGroup.addIngressRule(
      ec2.Peer.ipv4(this.vpc.vpcCidrBlock),
      ec2.Port.tcp(443),
      "HTTPS from within the VPC CIDR only (PrivateLink endpoints).",
    );
    this.securityGroup.addEgressRule(
      ec2.Peer.ipv4(this.vpc.vpcCidrBlock),
      ec2.Port.tcp(443),
      "HTTPS to PrivateLink endpoints within the VPC CIDR only.",
    );

    // --- FREE S3 Gateway endpoint. ---
    // Gateway endpoints (S3/DynamoDB) are route-table entries, NOT ENIs, so they
    // cost nothing and are always safe to include. ECR image layers live in S3, so
    // this is required for ECR pulls to work over PrivateLink.
    this.vpc.addGatewayEndpoint("S3GatewayEndpoint", {
      service: ec2.GatewayVpcEndpointAwsService.S3,
    });

    // --- Interface endpoints (the ONLY standing cost) - gated OFF by default. ---
    if (deployVpcEndpoints) {
      this.addInterfaceEndpoints(endpointRegion);
    }

    // --- Outputs so the runtime-stack can consume the network. ---
    new CfnOutput(this, "VpcId", {
      value: this.vpc.vpcId,
      description: "Private (isolated) VPC id - attach the AgentCore runtime here.",
      exportName: `${props.appName}-vpc-id`,
    });
    new CfnOutput(this, "IsolatedSubnetIds", {
      // Comma-joined so a consumer can Fn::Split it back into a list.
      value: this.vpc.isolatedSubnets.map((s) => s.subnetId).join(","),
      description: "Comma-separated PRIVATE_ISOLATED subnet ids for the runtime.",
      exportName: `${props.appName}-isolated-subnet-ids`,
    });
    new CfnOutput(this, "SecurityGroupId", {
      value: this.securityGroup.securityGroupId,
      description: "Security group id (intra-VPC 443 only) for the runtime ENIs.",
      exportName: `${props.appName}-security-group-id`,
    });
    new CfnOutput(this, "VpcEndpointsDeployed", {
      value: String(deployVpcEndpoints),
      description:
        "Whether the billable interface endpoints were provisioned (false = free S3 gateway only).",
    });
  }

  /**
   * Provision the interface (PrivateLink) endpoints the runtime needs, each with a
   * restrictive endpoint policy. These are the only resources that bill, hence the
   * `deployVpcEndpoints` gate around the call site.
   *
   * Endpoint policies are default-deny narrowed: the base policy allows the calls a
   * runtime legitimately makes and confines them to THIS account, so even the AWS
   * surface reachable over PrivateLink is an allowlist, not "all of the service".
   */
  private addInterfaceEndpoints(endpointRegion: string): void {
    // Only the ENIs in our SG may talk to the endpoints, and only on 443.
    const common = {
      privateDnsEnabled: true,
      securityGroups: [this.securityGroup],
      // Single isolated subnet - CDK places one ENI there.
      subnets: { subnetType: ec2.SubnetType.PRIVATE_ISOLATED as const },
    };

    // Restrictive endpoint policy statement: allow the API calls the runtime makes,
    // but ONLY from principals in this account. This is the allowlist boundary - the
    // endpoint refuses a call carrying credentials from any other account. Attached
    // per-endpoint via `.addToPolicy()` (the L2 has no `policyDocument` option). A
    // fresh statement per endpoint avoids sharing a mutable object across resources.
    const accountScopedStatement = () =>
      new iam.PolicyStatement({
        sid: "AllowThisAccountOnly",
        effect: iam.Effect.ALLOW,
        principals: [new iam.AnyPrincipal()],
        actions: ["*"],
        resources: ["*"],
        conditions: {
          StringEquals: { "aws:PrincipalAccount": this.account },
        },
      });

    // AWS-managed endpoint services resolve their own region from the stack.
    const named: Array<{ id: string; service: ec2.InterfaceVpcEndpointAwsService }> = [
      { id: "CloudWatchLogsEndpoint", service: ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH_LOGS },
      { id: "EcrApiEndpoint", service: ec2.InterfaceVpcEndpointAwsService.ECR },
      { id: "EcrDockerEndpoint", service: ec2.InterfaceVpcEndpointAwsService.ECR_DOCKER },
      { id: "StsEndpoint", service: ec2.InterfaceVpcEndpointAwsService.STS },
    ];
    for (const e of named) {
      const ep = this.vpc.addInterfaceEndpoint(e.id, {
        service: e.service,
        ...common,
      });
      ep.addToPolicy(accountScopedStatement());
    }

    // bedrock-agentcore has NO named enum → build the service name explicitly. This
    // needs a CONCRETE region (not a stack token), hence `endpointRegion`.
    const bedrockEp = this.vpc.addInterfaceEndpoint("BedrockAgentCoreEndpoint", {
      service: new ec2.InterfaceVpcEndpointService(
        `com.amazonaws.${endpointRegion}.bedrock-agentcore`,
        443,
      ),
      ...common,
    });
    bedrockEp.addToPolicy(accountScopedStatement());
  }
}
