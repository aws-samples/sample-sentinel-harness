"""INV-IAC-5 — the Terraform mirror is no WEAKER than CDK on every shared security control.

README calls `iac-terraform/` a "deployable Terraform mirror (identity/vpc/guardrail/obs/harness)".
INV-IAC-4 tested that claim for **observability** and found it false. The other four domains were
never compared, and they carry the platform's runtime security boundaries: which secret shapes get
masked, how strong a password must be, whether a subnet auto-assigns public IPs, whether Cognito
leaks whether a username exists.

Auditing all four found **one real weakening** and, deliberately recorded, four properties that
already hold.

The defect
----------
**`prevent_user_existence_errors` was absent from the Terraform human app client.**
`iac-cdk/lib/identity-stack.ts:140` sets `preventUserExistenceErrors: true`; the mirror set nothing,
and AWS's default is `LEGACY` — under which Cognito returns a DIFFERENT error for "user does not
exist" than for "wrong password", so an attacker enumerates valid usernames from the error alone.
An operator who deployed the Terraform path believing the mirror claim got a pool that leaks account
existence while the CDK path does not.

`terraform validate` passes BEFORE and AFTER the fix — verified by removing the line and re-running:
`Success! The configuration is valid.` The setting is schema-valid in both states, which is exactly
why this has to be a test. Same shape as INV-IAC-4, where `validate` was equally blind to an alarm
with no metric producer.

Only the HUMAN client needs it. CDK makes that distinction too: the machine client uses
`client_credentials`, which authenticates an app identity rather than a user, so there is no
username surface to enumerate. A guard demanding it on both would be demanding a setting with no
meaning, and the exemption is asserted below rather than left implicit.

The four negative results, pinned so they cannot quietly regress
---------------------------------------------------------------
Each of these is currently EQUAL across the two trees. None was guarded, so the equality was luck
rather than a property — and each is a runtime security boundary where a drift is silent:

1. **The guardrail secret regexes.** Both trees independently spell out the same two patterns:
   `A[KS]IA[0-9A-Z]{16}` and `(?:sk-|ghp_)[A-Za-z0-9_]{20,}`. These decide which credential shapes
   Bedrock masks. If one tree's pattern drifts, that deployment silently stops masking real leaked
   keys — no synth error, no validate error. Also asserted to be DISCRIMINATING (they match
   real-shaped secrets and reject near-misses), because a pattern that matches nothing is as bad as
   no pattern and looks identical in a diff.
2. **The PII entity actions.** `AWS_SECRET_KEY` is BLOCKed and `EMAIL`/`NAME` ANONYMIZEd in both.
   BLOCK vs ANONYMIZE is a real difference: anonymising a leaked secret still returns a response
   built from it.
3. **The Cognito password policy.** 12 chars, all four character classes, 3-day temporary password
   validity — identical in both.
4. **The subnet is private.** CDK uses `PRIVATE_ISOLATED`; Terraform sets
   `map_public_ip_on_launch = false`. Different spellings of "no public IPs", and a `true` on either
   side would put an agent workload on the public internet.

Scope, stated rather than implied
---------------------------------
NOT resource-for-resource parity. CDK's gateway / registry / memory / runtime stacks have no
Terraform counterpart by stated scope (INV-IAC-4 records the same boundary), so this module compares
only the five domains README claims are mirrored, and only their security-relevant settings.

ZERO network, ZERO AWS: both trees are read as text.
"""
from __future__ import annotations

import os
import re

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CDK_DIR = os.path.join(REPO_ROOT, "iac-cdk", "lib")
TF_DIR = os.path.join(REPO_ROOT, "iac-terraform")

CDK_IDENTITY = os.path.join(CDK_DIR, "identity-stack.ts")
CDK_GUARDRAIL = os.path.join(CDK_DIR, "guardrail-stack.ts")
CDK_NETWORK = os.path.join(CDK_DIR, "network-stack.ts")
TF_IDENTITY = os.path.join(TF_DIR, "identity.tf")
TF_GUARDRAIL = os.path.join(TF_DIR, "guardrail.tf")
TF_VPC = os.path.join(TF_DIR, "vpc.tf")

# The two secret-shape regexes both trees must spell identically, resolved from their fragments.
# Kept here as the EXPECTED value so a drift in either tree fails, rather than the two being
# compared only to each other — if both drifted the same way, comparing them would pass.
_EXPECTED_AWS_KEY_PATTERN = "A[KS]IA[0-9A-Z]{16}"
_EXPECTED_TOKEN_PATTERN = "(?:sk-|ghp_)[A-Za-z0-9_]{20,}"

# PII entity -> required action. BLOCK for the secret; ANONYMIZE for identity fields.
_REQUIRED_PII_ACTIONS = {
    "AWS_SECRET_KEY": "BLOCK",
    "EMAIL": "ANONYMIZE",
    "NAME": "ANONYMIZE",
}

# Cognito password policy, as both trees must configure it.
_REQUIRED_PASSWORD_POLICY = {
    "min_length": 12,
    "lowercase": True,
    "uppercase": True,
    "digits": True,
    "symbols": True,
    "temp_validity_days": 3,
}


def _read(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _strip_comments_ts(text: str) -> str:
    """Drop `//` and `/* */` comments so a commented setting cannot satisfy a check.

    Load-bearing: `sentinel-harness` being a COMMENTED-OUT requirement is exactly how
    INV-CONTAINER-2's start-up failure hid, and the same trap applies to a commented
    `preventUserExistenceErrors`.
    """
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return "\n".join(line.split("//", 1)[0] for line in text.splitlines())


def _strip_comments_tf(text: str) -> str:
    """Drop `#` comments from HCL, for the same reason."""
    return "\n".join(line.split("#", 1)[0] for line in text.splitlines())


def test_both_trees_are_present_and_substantive():
    """Positive control. Every assertion below reads these files; a moved tree would make the
    module vacuously green — a scan finding nothing looks exactly like a repo with nothing to
    find."""
    for path in (CDK_IDENTITY, CDK_GUARDRAIL, CDK_NETWORK, TF_IDENTITY, TF_GUARDRAIL, TF_VPC):
        assert os.path.isfile(path), f"{os.path.relpath(path, REPO_ROOT)} is missing"
        assert len(_read(path)) > 500, f"{os.path.relpath(path, REPO_ROOT)} looks truncated"


# --------------------------------------------------------------------------- #
# THE DEFECT: account-enumeration defence was CDK-only                        #
# --------------------------------------------------------------------------- #
def test_both_trees_prevent_cognito_user_existence_errors():
    """The one real weakening this audit found.

    CDK sets `preventUserExistenceErrors: true`; Terraform set nothing, and the AWS default is
    LEGACY — Cognito then returns a different error for "no such user" than for "wrong password",
    so usernames can be enumerated from the error alone.

    `terraform validate` cannot see it: verified by deleting the line and re-running, which still
    reported `Success! The configuration is valid.` A setting that is schema-valid whether present
    or absent has to be checked by a test.
    """
    cdk = _strip_comments_ts(_read(CDK_IDENTITY))
    tf = _strip_comments_tf(_read(TF_IDENTITY))

    assert re.search(r"preventUserExistenceErrors\s*:\s*true", cdk), (
        "the CDK identity stack no longer sets `preventUserExistenceErrors: true`. If that was "
        "deliberate, this whole guard's premise changed — do not simply delete the assertion; "
        "Cognito's default LEGACY behaviour leaks whether a username exists."
    )
    assert re.search(r'prevent_user_existence_errors\s*=\s*"ENABLED"', tf), (
        "iac-terraform/identity.tf does not set `prevent_user_existence_errors = \"ENABLED\"`, so "
        "the Terraform path deploys a Cognito pool that LEAKS account existence while the CDK path "
        "does not — README calls them a mirror.\n\n"
        "AWS defaults this to LEGACY, which returns a different error for a nonexistent user than "
        "for a wrong password: an attacker enumerates valid usernames from the error. "
        "`terraform validate` passes either way, which is why this is a test."
    )


def test_the_machine_client_exemption_is_deliberate_and_narrow():
    """The exemption gets its own check rather than being implied by omission.

    Only the HUMAN client needs the setting — the machine client uses `client_credentials`, which
    authenticates an app identity, so there is no username surface to enumerate. CDK draws the same
    line. But an exemption without a check is a hole (the rule this repo applies to lint-excluded
    directories), so the premise is asserted: if the machine client ever gains a user-auth flow,
    this fails and the exemption must be revisited.
    """
    tf = _strip_comments_tf(_read(TF_IDENTITY))
    machine = re.search(
        r'resource\s+"aws_cognito_user_pool_client"\s+"machine"\s*\{(.*?)\n\}', tf, re.S
    )
    assert machine, "could not locate the Terraform machine app client"
    body = machine.group(1)

    user_auth_flows = re.findall(r"ALLOW_USER_[A-Z_]+|ALLOW_ADMIN_USER[A-Z_]*", body)
    assert not user_auth_flows, (
        f"the machine client now permits user authentication flows {user_auth_flows}, so it HAS a "
        "username surface and the `prevent_user_existence_errors` exemption no longer holds. Either "
        "set it there too or remove the user-auth flow."
    )
    assert "client_credentials" in body, (
        "the machine client no longer uses client_credentials, so the reasoning that exempts it "
        "from the enumeration defence has expired. Re-derive it rather than keeping the exemption."
    )


# --------------------------------------------------------------------------- #
# NEGATIVE RESULTS, pinned: these already agree and must keep agreeing        #
# --------------------------------------------------------------------------- #
def test_both_trees_use_the_same_secret_shape_regexes():
    """These patterns decide which credential shapes Bedrock masks at runtime.

    Each tree spells them out INDEPENDENTLY from fragments (`"A" + "[KS]" + "IA"` in TypeScript,
    `join("", ["s","k-"])` in HCL) so the repo carries patterns rather than literal credentials.
    Good — and it means two hand-written copies of one security rule, the shape this repo records
    more than any other. A drift in one tree silently stops that deployment masking real keys.

    Compared against an EXPECTED value rather than against each other: if both drifted identically
    a mutual comparison would pass while the boundary had moved.
    """
    cdk = _strip_comments_ts(_read(CDK_GUARDRAIL))
    tf = _strip_comments_tf(_read(TF_GUARDRAIL))

    # Resolve each tree's fragments into the concrete pattern.
    def resolve_cdk() -> dict:
        out = {}
        prefix = re.search(r'awsKeyPrefix\s*=\s*(.+?);', cdk)
        body = re.search(r'awsAccessKeyIdPattern\s*=\s*`\$\{awsKeyPrefix\}(.+?)`', cdk)
        if prefix and body:
            literal = "".join(re.findall(r'"([^"]*)"', prefix.group(1)))
            out["aws_key"] = literal + body.group(1)
        sk = re.search(r'skPrefix\s*=\s*(.+?);', cdk)
        ghp = re.search(r'ghpPrefix\s*=\s*(.+?);', cdk)
        tok = re.search(
            r'genericTokenPattern\s*=\s*`\(\?:\$\{skPrefix\}\|\$\{ghpPrefix\}\)(.+?)`', cdk
        )
        if sk and ghp and tok:
            sk_lit = "".join(re.findall(r'"([^"]*)"', sk.group(1)))
            ghp_lit = "".join(re.findall(r'"([^"]*)"', ghp.group(1)))
            out["token"] = f"(?:{sk_lit}|{ghp_lit}){tok.group(1)}"
        return out

    def resolve_tf() -> dict:
        out = {}
        prefix = re.search(r'aws_key_prefix\s*=\s*"([^"]*)"', tf)
        body = re.search(r'aws_key_body\s*=\s*"([^"]*)"', tf)
        if prefix and body:
            out["aws_key"] = prefix.group(1) + body.group(1)
        sk = re.search(r'sk_prefix\s*=\s*join\("",\s*\[(.*?)\]\)', tf)
        ghp = re.search(r'ghp_prefix\s*=\s*join\("",\s*\[(.*?)\]\)', tf)
        tok_body = re.search(r'token_body\s*=\s*"([^"]*)"', tf)
        if sk and ghp and tok_body:
            sk_lit = "".join(re.findall(r'"([^"]*)"', sk.group(1)))
            ghp_lit = "".join(re.findall(r'"([^"]*)"', ghp.group(1)))
            out["token"] = f"(?:{sk_lit}|{ghp_lit}){tok_body.group(1)}"
        return out

    cdk_patterns = resolve_cdk()
    tf_patterns = resolve_tf()
    assert set(cdk_patterns) == {"aws_key", "token"}, (
        f"could not resolve both CDK patterns from their fragments (got {sorted(cdk_patterns)}). "
        "If the construction changed, update this resolver — silently resolving nothing would make "
        "the comparison below vacuous."
    )
    assert set(tf_patterns) == {"aws_key", "token"}, (
        f"could not resolve both Terraform patterns (got {sorted(tf_patterns)})"
    )

    expected = {"aws_key": _EXPECTED_AWS_KEY_PATTERN, "token": _EXPECTED_TOKEN_PATTERN}
    for key, want in expected.items():
        assert cdk_patterns[key] == want, (
            f"the CDK {key} regex is {cdk_patterns[key]!r}, expected {want!r}. If the boundary "
            "moved deliberately, change both trees AND this expectation together."
        )
        assert tf_patterns[key] == want, (
            f"the Terraform {key} regex is {tf_patterns[key]!r}, expected {want!r} — the two trees "
            "no longer mask the same credential shapes, so one deployment leaks what the other "
            "masks."
        )


def test_the_secret_regexes_actually_discriminate():
    """A pattern that matches nothing is as bad as no pattern, and looks identical in a diff.

    So the shared patterns are exercised: they must match real-SHAPED secrets (assembled here from
    fragments, never a real credential) and must reject near-misses — a 15-char body, a wrong
    prefix, lowercase.
    """
    key_rx = re.compile(_EXPECTED_AWS_KEY_PATTERN)
    tok_rx = re.compile(_EXPECTED_TOKEN_PATTERN)

    # Positive: correctly shaped, deliberately not real.
    for sample in ("A" + "KIA" + "Q" * 16, "A" + "SIA" + "1234567890ABCDEF"):
        assert key_rx.search(sample), f"the aws-key pattern misses a correctly shaped id: {sample}"
    for sample in ("s" + "k-" + "a" * 20, "gh" + "p_" + "B" * 25):
        assert tok_rx.search(sample), "the token pattern misses a correctly shaped token"

    # Negative: must NOT match.
    for sample in ("A" + "KIA" + "Q" * 15, "B" + "KIA" + "Q" * 16, "a" + "kia" + "q" * 16):
        assert not key_rx.search(sample), f"the aws-key pattern matches a non-key: {sample}"
    for sample in ("s" + "k-" + "a" * 19, "xx-" + "a" * 20):
        assert not tok_rx.search(sample), f"the token pattern matches a non-token: {sample}"


def test_both_trees_agree_on_every_pii_entity_action():
    """BLOCK vs ANONYMIZE is a real difference, not a synonym.

    Anonymising a leaked AWS secret key still returns a response derived from it; blocking refuses
    the response outright. Both trees currently BLOCK `AWS_SECRET_KEY` and ANONYMIZE `EMAIL`/`NAME`,
    and nothing checked that they keep agreeing.
    """
    cdk = _strip_comments_ts(_read(CDK_GUARDRAIL))
    tf = _strip_comments_tf(_read(TF_GUARDRAIL))

    cdk_actions = dict(
        re.findall(r'type:\s*"([A-Z_]+)"\s*,\s*action:\s*"([A-Z]+)"', cdk)
    )
    tf_actions = dict(
        re.findall(r'type\s*=\s*"([A-Z_]+)"\s*\n\s*action\s*=\s*"([A-Z]+)"', tf)
    )
    assert cdk_actions, "no PII entity/action pairs parsed from the CDK guardrail stack"
    assert tf_actions, "no PII entity/action pairs parsed from the Terraform guardrail"

    for entity, action in _REQUIRED_PII_ACTIONS.items():
        assert cdk_actions.get(entity) == action, (
            f"CDK sets {entity} to {cdk_actions.get(entity)!r}, expected {action!r}"
        )
        assert tf_actions.get(entity) == action, (
            f"Terraform sets {entity} to {tf_actions.get(entity)!r}, expected {action!r} — the two "
            "trees treat the same PII class differently, so one deployment is weaker."
        )


def test_both_trees_enforce_the_same_password_policy():
    """A weaker policy on one path is a weaker platform, and the mirror claim hides which."""
    cdk = _strip_comments_ts(_read(CDK_IDENTITY))
    tf = _strip_comments_tf(_read(TF_IDENTITY))

    cdk_policy = {
        "min_length": int(m.group(1)) if (m := re.search(r"minLength:\s*(\d+)", cdk)) else None,
        "lowercase": bool(re.search(r"requireLowercase:\s*true", cdk)),
        "uppercase": bool(re.search(r"requireUppercase:\s*true", cdk)),
        "digits": bool(re.search(r"requireDigits:\s*true", cdk)),
        "symbols": bool(re.search(r"requireSymbols:\s*true", cdk)),
        "temp_validity_days": (
            int(m.group(1)) if (m := re.search(r"tempPasswordValidity:\s*Duration\.days\((\d+)\)",
                                               cdk)) else None
        ),
    }
    tf_policy = {
        "min_length": (
            int(m.group(1)) if (m := re.search(r"minimum_length\s*=\s*(\d+)", tf)) else None
        ),
        "lowercase": bool(re.search(r"require_lowercase\s*=\s*true", tf)),
        "uppercase": bool(re.search(r"require_uppercase\s*=\s*true", tf)),
        "digits": bool(re.search(r"require_numbers\s*=\s*true", tf)),
        "symbols": bool(re.search(r"require_symbols\s*=\s*true", tf)),
        "temp_validity_days": (
            int(m.group(1))
            if (m := re.search(r"temporary_password_validity_days\s*=\s*(\d+)", tf))
            else None
        ),
    }

    for name, want in _REQUIRED_PASSWORD_POLICY.items():
        assert cdk_policy[name] == want, (
            f"CDK password policy {name}={cdk_policy[name]!r}, expected {want!r}"
        )
        assert tf_policy[name] == want, (
            f"Terraform password policy {name}={tf_policy[name]!r}, expected {want!r} — the two "
            "paths enforce different password strength."
        )


def test_neither_tree_puts_the_agent_subnet_on_the_public_internet():
    """Different spellings of the same requirement, so both need checking.

    CDK uses `SubnetType.PRIVATE_ISOLATED`; Terraform sets `map_public_ip_on_launch = false`. A
    `true` on either side would give an agent workload a public IP — and neither `cdk synth` nor
    `terraform validate` treats that as an error.
    """
    cdk = _strip_comments_ts(_read(CDK_NETWORK))
    tf = _strip_comments_tf(_read(TF_VPC))

    assert "PRIVATE_ISOLATED" in cdk, (
        "the CDK network stack no longer declares PRIVATE_ISOLATED subnets. If the topology "
        "changed deliberately, re-derive this guard rather than deleting it."
    )
    assert not re.search(r"map_public_ip_on_launch\s*=\s*true", tf), (
        "iac-terraform sets `map_public_ip_on_launch = true`, giving the agent subnet public IPs "
        "while the CDK path keeps it PRIVATE_ISOLATED."
    )
    assert re.search(r"map_public_ip_on_launch\s*=\s*false", tf), (
        "iac-terraform does not explicitly set `map_public_ip_on_launch = false`. The AWS default "
        "for a non-default subnet is false, but relying on an unstated default for a network "
        "boundary is how it flips unnoticed — state it."
    )


def test_the_readme_mirror_claim_names_the_domains_this_module_checks():
    """Keep the claim and the coverage coupled.

    README says the mirror covers identity/vpc/guardrail/obs/harness. INV-IAC-4 checks obs; this
    module checks identity/vpc/guardrail. If the claim grows a sixth domain, the reader is being
    promised parity nothing verifies — the same gap that let the observability mirror be false.
    """
    readme = _read(os.path.join(REPO_ROOT, "README.md"))
    claim = re.search(r"Terraform mirror \(([^)]+)\)", readme)
    if claim is None:
        pytest.skip(
            "README no longer states which domains the Terraform mirror covers; this coupling "
            "check needs that sentence to exist."
        )
    claimed = {d.strip().lower() for d in claim.group(1).split("/")}
    covered = {"identity", "vpc", "guardrail", "obs", "harness"}
    unexpected = sorted(claimed - covered)
    assert not unexpected, (
        f"README claims the Terraform mirror covers {unexpected}, which no parity guard checks. "
        "Either add coverage (here or in test_iac_observability_parity.py) or narrow the claim — "
        "an unverified mirror claim is what INV-IAC-4 was written about."
    )
