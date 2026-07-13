/**
 * IdentityStack - the Cognito identity provider for the Gateway CUSTOM_JWT path.
 * ==============================================================================
 * WHY (docs/BLUEPRINT.md §5 "human callers front the Gateway with Cognito/OAuth"):
 * the GatewayStack's CUSTOM_JWT authorizer needs an OIDC issuer plus the audience /
 * client ids to trust. This stack stands up a self-contained Cognito User Pool that
 * mints BOTH kinds of token the Gateway must accept:
 *
 *   1. HUMAN tokens - an interactive app client (SRP + OAuth authorization-code
 *      flow, NO client secret). Cognito ID tokens carry an `aud` claim = the app
 *      client id, so the Gateway trusts these via `allowedAudience`.
 *   2. MACHINE (M2M) tokens - a confidential app client (client secret) using the
 *      OAuth `client_credentials` grant against the pool's custom resource-server
 *      scope. This is the token a headless harness/service uses.
 *
 * AUD-CLAIM GOTCHA (VERIFIED): Cognito ACCESS tokens minted by the
 * `client_credentials` grant have NO `aud` claim (only `client_id` + `scope`). So
 * the Gateway must match M2M callers on `allowedClients` (the machine client id),
 * NOT `allowedAudience`. Human ID tokens DO carry `aud`, matched via
 * `allowedAudience`. The two CfnOutputs below (humanClientId → jwtAllowedAudience,
 * machineClientId → jwtAllowedClients) feed exactly those two Gateway context keys.
 *
 * The `client_credentials` grant additionally REQUIRES: a UserPoolDomain (to expose
 * the `/oauth2/token` endpoint), a UserPoolResourceServer declaring custom scopes,
 * and a confidential client (generateSecret=true). All three are provisioned here.
 *
 * Non-prod target: self-signup is OFF and the pool uses removalPolicy DESTROY so
 * `cdk destroy` leaves no orphan. This is a dev identity provider, not a prod IdP.
 */
import { Stack, StackProps, CfnOutput, RemovalPolicy, Duration, Token } from "aws-cdk-lib";
import * as cognito from "aws-cdk-lib/aws-cognito";
import { Construct } from "constructs";

export interface IdentityStackProps extends StackProps {
  /** Logical app prefix (context `sentinel:appName`, default "sentinel"). */
  readonly appName: string;
  /**
   * Globally-unique Cognito hosted-UI domain prefix (context
   * `sentinel:cognitoDomainPrefix`). Required for the `client_credentials`
   * `/oauth2/token` endpoint. Defaults to the app name; override if it collides
   * (Cognito domain prefixes are unique per region).
   */
  readonly cognitoDomainPrefix?: string;
  /**
   * Custom resource-server identifier for the M2M scope (default "sentinel").
   * The full scope the machine client requests is `<identifier>/<scope>`.
   */
  readonly resourceServerId?: string;
}

export class IdentityStack extends Stack {
  /** The Cognito User Pool (the OIDC issuer the Gateway trusts). */
  public readonly userPool: cognito.UserPool;
  /** Human interactive client (no secret; ID token carries `aud`). */
  public readonly humanClient: cognito.UserPoolClient;
  /** Machine (M2M) confidential client (client_credentials; token has no `aud`). */
  public readonly machineClient: cognito.UserPoolClient;
  /** OIDC issuer URL (https://cognito-idp.<region>.amazonaws.com/<poolId>). */
  public readonly issuer: string;
  /** OIDC discovery URL feeding the Gateway `jwtDiscoveryUrl` context key. */
  public readonly discoveryUrl: string;

  constructor(scope: Construct, id: string, props: IdentityStackProps) {
    super(scope, id, props);

    // Cognito hosted-UI domain prefixes are GLOBALLY scarce (unique per region, and a
    // bare "sentinel" collides trivially / lingers after a delete in another region).
    // Default to an account+region-derived suffix so a plain deploy never collides;
    // an explicit `sentinel:cognitoDomainPrefix` context value still wins for a vanity domain.
    const acct = Stack.of(this).account;
    const region = Stack.of(this).region;
    // A Cognito domainPrefix must be lowercase [a-z0-9-] only. When the stack is
    // region-agnostic (no CDK env), `acct`/`region` are UNRESOLVED CDK tokens like
    // `${Token[AWS.Region.4]}` - embedding them yields braces/uppercase that fail
    // validation at synth. So we only fold account/region into the suffix when they
    // are resolved concrete strings; otherwise fall back to a static lowercase-safe
    // prefix (`<appName>-auth`). An explicit context value still wins for a vanity domain.
    const suffixBase =
      Token.isUnresolved(acct) || Token.isUnresolved(region)
        ? `${props.appName}-auth`
        : `${props.appName}-${acct.slice(-6)}-${region}`;
    const autoSuffix = suffixBase.toLowerCase().replace(/[^a-z0-9-]/g, "-").slice(0, 63);
    const domainPrefix = props.cognitoDomainPrefix ?? autoSuffix;
    const resourceServerId = props.resourceServerId ?? "sentinel";

    // --- User Pool: the OIDC issuer. LITE tier, self-signup OFF (admin-created
    // users only - this is a governance-adjacent dev IdP, not a public sign-up). ---
    this.userPool = new cognito.UserPool(this, "UserPool", {
      userPoolName: `${props.appName}-users`,
      featurePlan: cognito.FeaturePlan.LITE,
      selfSignUpEnabled: false,
      signInAliases: { username: true, email: true },
      passwordPolicy: {
        minLength: 12,
        requireLowercase: true,
        requireUppercase: true,
        requireDigits: true,
        requireSymbols: true,
        tempPasswordValidity: Duration.days(3),
      },
      accountRecovery: cognito.AccountRecovery.EMAIL_ONLY,
      // Non-prod target: DESTROY so `cdk destroy` removes the pool cleanly.
      removalPolicy: RemovalPolicy.DESTROY,
    });

    // --- Resource server + custom scope for M2M (client_credentials). The machine
    // client requests `<resourceServerId>/invoke`; the Gateway sees this in the
    // access token's `scope` claim. ---
    const invokeScope = new cognito.ResourceServerScope({
      scopeName: "invoke",
      scopeDescription: "Invoke the Sentinel Gateway as a machine (M2M) principal.",
    });
    const resourceServer = this.userPool.addResourceServer("ResourceServer", {
      identifier: resourceServerId,
      userPoolResourceServerName: `${props.appName}-m2m`,
      scopes: [invokeScope],
    });

    // --- Hosted-UI domain: REQUIRED for the client_credentials /oauth2/token
    // endpoint. Yields https://<prefix>.auth.<region>.amazoncognito.com. ---
    const domain = this.userPool.addDomain("Domain", {
      cognitoDomain: { domainPrefix },
    });

    // --- Human client: interactive, NO secret, SRP + OAuth authorization-code
    // flow. Cognito ID tokens carry `aud` = this client id → Gateway allowedAudience. ---
    this.humanClient = this.userPool.addClient("HumanClient", {
      userPoolClientName: `${props.appName}-human`,
      generateSecret: false,
      authFlows: { userSrp: true },
      oAuth: {
        flows: { authorizationCodeGrant: true },
        scopes: [cognito.OAuthScope.OPENID, cognito.OAuthScope.EMAIL, cognito.OAuthScope.PROFILE],
        // Placeholder callback; a real front-end replaces this. Kept local-only so
        // no external URL / customer reference leaks into the public repo.
        callbackUrls: ["http://localhost:3000/callback"],
        logoutUrls: ["http://localhost:3000/logout"],
      },
      supportedIdentityProviders: [cognito.UserPoolClientIdentityProvider.COGNITO],
      preventUserExistenceErrors: true,
    });

    // --- Machine (M2M) client: confidential (secret), client_credentials grant,
    // requesting the custom resource-server scope. Its access token has NO `aud`
    // claim → Gateway must match on allowedClients (this client id). ---
    this.machineClient = this.userPool.addClient("MachineClient", {
      userPoolClientName: `${props.appName}-machine`,
      generateSecret: true,
      authFlows: {},
      oAuth: {
        flows: { clientCredentials: true },
        scopes: [cognito.OAuthScope.resourceServer(resourceServer, invokeScope)],
      },
      supportedIdentityProviders: [cognito.UserPoolClientIdentityProvider.COGNITO],
    });
    // The machine client's OAuth config depends on the resource server existing.
    this.machineClient.node.addDependency(resourceServer);

    // --- Issuer + discovery URL. `this.region` resolves to the stack's region at
    // synth (a token when the stack is region-agnostic; the concrete region when
    // env is set). This is exactly the value the Gateway CUSTOM_JWT authorizer wants. ---
    this.issuer = `https://cognito-idp.${this.region}.amazonaws.com/${this.userPool.userPoolId}`;
    this.discoveryUrl = `${this.issuer}/.well-known/openid-configuration`;

    new CfnOutput(this, "UserPoolId", {
      value: this.userPool.userPoolId,
      description: "Cognito User Pool id (the OIDC issuer backing the Gateway CUSTOM_JWT authorizer).",
      exportName: `${props.appName}-user-pool-id`,
    });
    new CfnOutput(this, "Issuer", {
      value: this.issuer,
      description: "OIDC issuer URL (https://cognito-idp.<region>.amazonaws.com/<poolId>).",
      exportName: `${props.appName}-oidc-issuer`,
    });
    new CfnOutput(this, "DiscoveryUrl", {
      value: this.discoveryUrl,
      description:
        "Set as -c sentinel:jwtDiscoveryUrl=... for the Gateway CUSTOM_JWT authorizer.",
      exportName: `${props.appName}-oidc-discovery-url`,
    });
    new CfnOutput(this, "HumanClientId", {
      value: this.humanClient.userPoolClientId,
      description:
        "Human app client id. ID tokens carry aud=this → set as -c sentinel:jwtAllowedAudience=...",
      exportName: `${props.appName}-human-client-id`,
    });
    new CfnOutput(this, "MachineClientId", {
      value: this.machineClient.userPoolClientId,
      description:
        "Machine (M2M) client id. Access tokens have NO aud → set as -c sentinel:jwtAllowedClients=...",
      exportName: `${props.appName}-machine-client-id`,
    });
    new CfnOutput(this, "DomainBaseUrl", {
      value: domain.baseUrl(),
      description:
        "Hosted-UI base URL; the client_credentials token endpoint is <base>/oauth2/token.",
      exportName: `${props.appName}-cognito-domain-base-url`,
    });
  }
}
