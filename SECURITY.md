# Security Policy

`sentinel-harness` is a **reference implementation and educational sample** for
**authorized, defensive** security operations on Amazon Bedrock AgentCore. It ships
offline/stubbed tools and only public threat data (MITRE ATT&CK, public CVEs). It is
**not** a managed product, and it is not intended to be run against production data or
credentials without the hardening described in [`docs/SETUP.md`](docs/SETUP.md) and
[`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md).

We take the security of the code and its documented patterns seriously and welcome
coordinated disclosure.

## Supported versions

Security fixes are applied to the latest minor release line only. This project uses
[Semantic Versioning](https://semver.org/); the version is the single source of truth in
[`pyproject.toml`](pyproject.toml).

| Version | Supported          |
| ------- | ------------------ |
| 0.2.x   | :white_check_mark: |
| 0.1.x   | :x:                |
| < 0.1   | :x:                |

When a `0.3.0` (or later) line ships, the previous minor line receives security fixes for
90 days, after which only the newest minor line is supported.

## Reporting a vulnerability

**Please do not open a public issue for a security vulnerability.** Public issues are
visible to everyone and can put users at risk before a fix is available.

Instead, report privately through **GitHub Private Vulnerability Reporting**:

1. Go to the repository's **Security** tab.
2. Click **Report a vulnerability** (this opens a private advisory visible only to you and
   the maintainers).
3. Describe the issue: affected file(s)/component, the impact, and a minimal reproduction
   or proof of concept if you have one.

If you cannot use GitHub's private reporting for any reason, open a regular issue that
contains **only** the sentence "I would like to report a security issue privately" — with
no technical details — and a maintainer will open a private channel.

### What to include

- The affected component (e.g. `sentinel_harness/sandbox_hooks.py`, a CDK stack, a tool
  handler) and file path.
- The class of issue (e.g. sandbox-allowlist bypass, IAM over-grant, egress escape,
  secret exposure, prompt-injection control gap).
- Steps to reproduce, expected vs. actual behavior, and the impact.
- Any suggested remediation.

### Response SLA

| Stage                                   | Target                       |
| --------------------------------------- | ---------------------------- |
| Acknowledge receipt                     | within **3 business days**   |
| Initial triage + severity assessment    | within **10 business days**  |
| Fix or documented mitigation (High/Crit)| within **30 days** of triage |
| Coordinated public disclosure           | after a fix ships, by mutual agreement |

We will keep you updated through the private advisory and credit you in the release notes
and advisory unless you prefer to remain anonymous.

## Scope

**In scope** — issues in *this repository's own code and its documented deployment
patterns*, for example:

- A bypass of the `sandbox_hooks` command/path validators
  ([`sentinel_harness/sandbox_hooks.py`](sentinel_harness/sandbox_hooks.py)).
- An IAM policy in `iac-cdk/lib/*` that grants materially more than the least privilege it
  documents (e.g. an unintended wildcard, a missing account/namespace condition).
- An egress escape from the default-deny network posture
  ([`iac-cdk/lib/network-stack.ts`](iac-cdk/lib/network-stack.ts)).
- A path where a real secret can be logged, echoed, or committed (the repo's own handling
  — see [`docs/SECRETS.md`](docs/SECRETS.md)).
- A governance gap in the dual-gate registry or the human-in-the-loop resume contract that
  lets an unapproved capability or an ungated action run.

**Out of scope**

- Vulnerabilities in **Amazon Bedrock AgentCore, AWS services, or any AWS-managed control
  plane** — report those to AWS via <https://aws.amazon.com/security/vulnerability-reporting/>.
- Vulnerabilities in **third-party dependencies** — report upstream; we will bump the
  pin once a fix is released.
- Findings that require already-compromised AWS credentials, a role with more privilege
  than this repo grants, or disabling a shipped control (these are configuration choices,
  not defects in the reference).
- Offensive/dual-use requests. This is a **defensive-only** reference; we do not accept
  reports asking us to add attack tooling.

## A note on the offensive-looking surface

Some tools reason about attack paths, ATT&CK techniques, and detection blind spots. These
operate on a fictional offline mock world and public threat data by default; every
side-effecting or live-egress path is opt-in behind an explicit `*_LIVE` environment flag
and, for high-stakes actions, a human-in-the-loop approval gate. See
[`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) for the full control map.
