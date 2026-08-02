"""
Round-17 part 3 — the IaC permission boundary. A NEGATIVE result, made executable.
=================================================================================
``iac-cdk/`` and ``iac-terraform/`` had never been audited, and they define real IAM
permission boundaries — so they were the third target of this round.

**They held up.** That is the finding, and it is recorded here as tests rather than as
a claim, because "we looked and it was fine" is worth nothing a month later. What the
tests pin is the specific properties that made it fine, so a future change that breaks
one fails the build.

Three things were checked, and the first two corrected my own initial framing:

1. **Wildcards are not automatically defects — the STATEMENT TYPE decides.**
   ``network-stack.ts`` carries ``actions: ["*"], resources: ["*"]``, which looks
   alarming and is correct: it is a **VPC endpoint policy**, whose semantics are
   "what may traverse this endpoint", INTERSECTED with the caller's own IAM. Its
   boundary is the ``aws:PrincipalAccount`` condition. Narrowing the actions would
   break AWS-managed service calls without adding any restriction.
   In an IAM ROLE policy a wildcard resource expands power; in an endpoint or resource
   policy with a condition it contracts it. Same characters, opposite direction.

2. **The two stacks are COMPLEMENTARY, not parallel.** CDK names 17 IAM actions;
   Terraform names none, because it provisions no IAM role at all — it does
   Cognito/VPC/Guardrail/Observability and *accepts* an execution role ARN by variable.
   So the question "do the two express the same boundary?" is the wrong one. The right
   one is "does the split leave a gap?", which led to the third check.

3. **The Terraform variable regex IS the boundary** for every Terraform-provisioned
   harness, since nothing else constrains the role it is handed. Tested against 15
   shapes; it admits exactly the four legitimate ones (including non-default partitions
   and a role path) and refuses a user ARN, the account root, an STS assumed-role
   session, malformed account ids, an empty role name, and leading junk.

The two remaining IAM wildcards (``cloudwatch:PutMetricData``,
``xray:Put*``) are the documented cases where AWS provides no resource-level scoping;
the first is confined by a ``cloudwatch:namespace`` condition and the second by the
account boundary, each argued in a comment at the site. Pinned below so the argument
cannot quietly stop being true.

Zero network, zero AWS: this reads the IaC sources as text and re-implements the
Terraform regex.
"""
from __future__ import annotations

import pathlib
import re

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
CDK_LIB = REPO_ROOT / "iac-cdk" / "lib"
TERRAFORM = REPO_ROOT / "iac-terraform"


def _cdk_sources() -> dict[str, str]:
    return {p.name: p.read_text(encoding="utf-8") for p in sorted(CDK_LIB.glob("*.ts"))}


def _terraform_sources() -> dict[str, str]:
    return {p.name: p.read_text(encoding="utf-8")
            for p in sorted(TERRAFORM.glob("*.tf"))}


# --------------------------------------------------------------------------- #
# INV-IAC-1 — every wildcard is one of the argued exceptions                   #
# --------------------------------------------------------------------------- #
class TestIamWildcardsAreArgued:
    """A wildcard resource in an IAM role policy expands what the role can reach. The
    three in this codebase are each a case where AWS offers no resource-level scoping,
    and each carries the argument at the site. This test is the mechanism that stops a
    FOURTH from appearing without one."""

    # `sid` of every statement allowed to use `resources: ["*"]`, with the reason.
    _ARGUED = {
        "Metrics": "cloudwatch:PutMetricData has no resource-level scoping; confined "
                   "by a cloudwatch:namespace condition",
        "Tracing": "the X-Ray write APIs support neither resource scoping nor the "
                   "namespace condition; the account boundary is the guard",
        "AllowThisAccountOnly": "a VPC ENDPOINT policy, not a role policy — its "
                                "wildcard is intersected with the caller's own IAM "
                                "and bounded by aws:PrincipalAccount",
    }

    def test_the_source_files_are_found(self):
        """Guard the guard: an empty source set passes every assertion below."""
        sources = _cdk_sources()
        assert len(sources) >= 8, f"only found {len(sources)} CDK lib files"
        assert "iam.ts" in sources and "network-stack.ts" in sources

    def test_every_wildcard_resource_statement_is_argued(self):
        """Find each `resources: ["*"]` and require its statement to carry an
        allowlisted `sid`. A new one gets a build failure and has to state its case."""
        offenders = []
        for name, source in _cdk_sources().items():
            for match in re.finditer(r'resources:\s*\["\*"\]', source):
                # Walk back to the nearest `sid:` — the statement this belongs to.
                preceding = source[:match.start()]
                sid_matches = re.findall(r'sid:\s*"([^"]+)"', preceding)
                sid = sid_matches[-1] if sid_matches else None
                if sid not in self._ARGUED:
                    line = source[:match.start()].count("\n") + 1
                    offenders.append(f"{name}:{line} (sid={sid!r})")
        assert not offenders, (
            "IAM statement(s) with `resources: [\"*\"]` and no argued exception:\n  "
            + "\n  ".join(offenders)
            + "\n\nEither scope the resource, or add the sid to _ARGUED here with the "
              "reason AWS offers no resource-level scoping for those actions."
        )

    def test_the_argued_exceptions_still_exist(self):
        """The other direction: if an exception is no longer used, remove it. A stale
        allowlist entry is how a list rots into a blanket skip (INV-COERCE's lesson)."""
        joined = "\n".join(_cdk_sources().values())
        for sid in self._ARGUED:
            assert f'sid: "{sid}"' in joined, (
                f"argued exception {sid!r} no longer appears — remove it from _ARGUED"
            )

    def test_the_metrics_statement_keeps_its_namespace_condition(self):
        """`PutMetricData` with an unconditioned `*` would let the role write to any
        namespace in the account. The condition IS the scoping."""
        source = _cdk_sources()["iam.ts"]
        metrics = source[source.index('sid: "Metrics"'):]
        metrics = metrics[:metrics.index("}),")]
        assert "cloudwatch:namespace" in metrics, (
            "the Metrics statement lost its namespace condition — its wildcard "
            "resource is now unbounded"
        )
        assert "bedrock-agentcore" in metrics

    def test_the_tracing_statement_is_separate_from_metrics(self):
        """Recorded at the site and pinned here: the X-Ray actions do NOT support the
        namespace condition, so merging them into the Metrics statement would attach an
        invalid condition — which AWS ignores, silently widening the metrics grant."""
        source = _cdk_sources()["iam.ts"]
        tracing = source[source.index('sid: "Tracing"'):]
        tracing = tracing[:tracing.index("}),")]
        assert "xray:PutTraceSegments" in tracing
        assert "cloudwatch:namespace" not in tracing, (
            "the namespace condition was attached to the X-Ray statement, where it is "
            "invalid — AWS ignores an unrecognized condition key, so this would widen "
            "rather than restrict"
        )

    def test_no_role_policy_uses_a_wildcard_ACTION(self):
        """A wildcard resource is sometimes forced; a wildcard ACTION in a role policy
        never is. The only `actions: ["*"]` must be the endpoint policy."""
        offenders = []
        for name, source in _cdk_sources().items():
            for match in re.finditer(r'actions:\s*\["\*"\]', source):
                preceding = source[:match.start()]
                sid_matches = re.findall(r'sid:\s*"([^"]+)"', preceding)
                sid = sid_matches[-1] if sid_matches else None
                if sid != "AllowThisAccountOnly":
                    line = preceding.count("\n") + 1
                    offenders.append(f"{name}:{line} (sid={sid!r})")
        assert not offenders, (
            f"wildcard ACTION outside the VPC endpoint policy: {offenders}"
        )

    def test_the_endpoint_policy_is_account_bounded(self):
        """The endpoint policy's wildcard is only safe because of this condition."""
        source = _cdk_sources()["network-stack.ts"]
        statement = source[source.index('sid: "AllowThisAccountOnly"'):]
        statement = statement[:statement.index("});")]
        assert "aws:PrincipalAccount" in statement, (
            "the VPC endpoint policy lost its account condition — its "
            "actions/resources wildcards are now genuinely unbounded"
        )


# --------------------------------------------------------------------------- #
# INV-IAC-2 — the Terraform variable regex IS the boundary                     #
# --------------------------------------------------------------------------- #
class TestTerraformExecutionRoleGate:
    """The Terraform path provisions NO IAM role — it accepts one by variable. So the
    variable's validation regex is the entire boundary for every harness created that
    way, and what it admits is a security decision rather than an input-hygiene one."""

    @staticmethod
    def _role_arn_regex() -> str:
        source = (TERRAFORM / "variables-harness.tf").read_text(encoding="utf-8")
        block = source[source.index('variable "harness_execution_role_arn"'):]
        match = re.search(r'regex\("([^"]+)"', block)
        assert match, "no validation regex found on harness_execution_role_arn"
        return match.group(1)

    def test_the_variable_is_validated_at_all(self):
        source = (TERRAFORM / "variables-harness.tf").read_text(encoding="utf-8")
        block = source[source.index('variable "harness_execution_role_arn"'):]
        block = block[:block.index("\nvariable ")] if "\nvariable " in block else block
        assert "validation" in block, (
            "harness_execution_role_arn has no validation block — the Terraform path "
            "creates no IAM role, so this variable is the only boundary"
        )
        assert "default" not in block, (
            "the execution role must have NO default: a default would let a harness be "
            "created against an unreviewed role"
        )

    @pytest.mark.parametrize("arn", [
        "arn:aws:iam::000000000000:role/sentinel-exec",
        "arn:aws-cn:iam::000000000000:role/x",            # China partition
        "arn:aws-us-gov:iam::000000000000:role/x",        # GovCloud
        "arn:aws:iam::000000000000:role/path/to/role",    # roles may carry a path
    ])
    def test_a_legitimate_role_arn_is_accepted(self, arn):
        """CONTROL: over-refusing here blocks legitimate deployments, including the
        non-default partitions."""
        assert re.match(self._role_arn_regex(), arn), arn

    @pytest.mark.parametrize("arn,why", [
        ("arn:aws:iam::000000000000:user/alice", "a USER, not a role"),
        ("arn:aws:iam::000000000000:root", "the account root principal"),
        ("arn:aws:sts::000000000000:assumed-role/x/y", "an STS session, not a role"),
        ("arn:aws:iam::0000000000:role/x", "10-digit account id"),
        ("arn:aws:iam::0000000000000:role/x", "13-digit account id"),
        ("arn:aws:iam::abcdefghijkl:role/x", "non-numeric account id"),
        ("arn:aws:iam::000000000000:role/", "empty role name"),
        ("", "the empty string"),
        ("not-an-arn", "free text"),
        ("prefix arn:aws:iam::000000000000:role/x", "leading junk"),
        ("arn:aws:iam::000000000000:role/x\narn:aws:iam::000000000000:role/y",
         "two ARNs on separate lines"),
    ])
    def test_a_non_role_or_malformed_arn_is_refused(self, arn, why):
        assert not re.match(self._role_arn_regex(), arn), why

    def test_the_regex_is_anchored_at_both_ends(self):
        """An unanchored pattern would accept anything CONTAINING a valid ARN. Checked
        structurally as well as behaviourally, because the behavioural cases above can
        only sample."""
        regex = self._role_arn_regex()
        assert regex.startswith("^"), f"not anchored at the start: {regex}"
        assert regex.endswith("$"), f"not anchored at the end: {regex}"

    def test_terraform_provisions_no_iam_role(self):
        """The premise this whole class rests on. If Terraform starts creating roles,
        those roles need the same scrutiny INV-IAC-1 applies to the CDK ones, and this
        test is where a reviewer will be told."""
        for name, source in _terraform_sources().items():
            assert 'resource "aws_iam_role"' not in source, (
                f"{name} now creates an IAM role — it must be audited against "
                "INV-IAC-1's wildcard rules, and this test updated"
            )
            assert 'resource "aws_iam_policy"' not in source, (
                f"{name} now creates an IAM policy — same"
            )


# --------------------------------------------------------------------------- #
# INV-IAC-3 — no account id, secret, or real ARN is committed                   #
# --------------------------------------------------------------------------- #
class TestIacCarriesNoHardcodedIdentity:
    """The CI secret-scan covers the whole repo; this states the property for the IaC
    layer specifically, where a leaked account id would also be a deployment target."""

    _PLACEHOLDER = "000000000000"

    def test_no_iac_file_carries_a_non_placeholder_account_id(self):
        offenders = []
        for tree in (_cdk_sources(), _terraform_sources()):
            for name, source in tree.items():
                for match in re.finditer(r"(?<![\d])(\d{12})(?![\d])", source):
                    if match.group(1) != self._PLACEHOLDER:
                        line = source[:match.start()].count("\n") + 1
                        offenders.append(f"{name}:{line} -> {match.group(1)}")
        assert not offenders, (
            f"12-digit account id(s) other than the {self._PLACEHOLDER} placeholder: "
            f"{offenders}"
        )

    def test_the_execution_role_is_never_hardcoded(self):
        """Both stacks must take it from a variable / context, never a literal."""
        for name, source in _terraform_sources().items():
            for match in re.finditer(r'execution_role_arn\s*=\s*"([^"]*)"', source):
                pytest.fail(
                    f"{name} hardcodes an execution role ARN: {match.group(1)!r}"
                )

    def test_no_iac_file_carries_an_access_key(self):
        for tree in (_cdk_sources(), _terraform_sources()):
            for name, source in tree.items():
                assert not re.search(r"A[KS]IA[0-9A-Z]{16}", source), (
                    f"{name} contains something shaped like an AWS access key id"
                )


# --------------------------------------------------------------------------- #
# The suite's own positive control — what makes a NEGATIVE result meaningful   #
# --------------------------------------------------------------------------- #
class TestTheIacGuardsCanDetectADefect:
    """This whole module reports that the IaC layer is sound. That claim is worth
    nothing unless the instruments demonstrably work, so each guard is shown to fire
    on a synthesized defect.

    Operates on source TEXT held in memory — the checks are pure string/regex
    predicates over file contents, so a test that mutated tracked files to prove a
    point would be a defect of its own.
    """

    @staticmethod
    def _wildcard_resource_offenders(sources: dict[str, str],
                                     argued: set[str]) -> list[str]:
        """Re-implementation of the INV-IAC-1 predicate, over supplied text."""
        offenders = []
        for name, source in sources.items():
            for match in re.finditer(r'resources:\s*\["\*"\]', source):
                sids = re.findall(r'sid:\s*"([^"]+)"', source[:match.start()])
                if (sids[-1] if sids else None) not in argued:
                    offenders.append(name)
        return offenders

    def test_an_unargued_wildcard_resource_is_detected(self):
        argued = set(TestIamWildcardsAreArgued._ARGUED)
        clean = _cdk_sources()
        assert self._wildcard_resource_offenders(clean, argued) == [], (
            "the real tree is not clean, so the injection below proves nothing"
        )
        injected = dict(clean)
        injected["iam.ts"] = clean["iam.ts"] + (
            '\nconst bad = new iam.PolicyStatement({\n'
            '  sid: "Injected",\n  actions: ["s3:*"],\n  resources: ["*"],\n});\n'
        )
        assert self._wildcard_resource_offenders(injected, argued) == ["iam.ts"], (
            "an unargued `resources: [\"*\"]` was NOT detected — the guard is blind"
        )

    def test_a_wildcard_action_outside_the_endpoint_policy_is_detected(self):
        def offenders(sources):
            found = []
            for name, source in sources.items():
                for match in re.finditer(r'actions:\s*\["\*"\]', source):
                    sids = re.findall(r'sid:\s*"([^"]+)"', source[:match.start()])
                    if (sids[-1] if sids else None) != "AllowThisAccountOnly":
                        found.append(name)
            return found

        clean = _cdk_sources()
        assert offenders(clean) == []
        injected = dict(clean)
        injected["iam.ts"] = clean["iam.ts"] + (
            '\nconst bad = new iam.PolicyStatement({\n'
            '  sid: "InjectedAction",\n  actions: ["*"],\n  resources: ["arn:x"],\n});\n'
        )
        assert offenders(injected) == ["iam.ts"]

    def test_a_terraform_iam_role_is_detected(self):
        clean = _terraform_sources()
        assert all('resource "aws_iam_role"' not in s for s in clean.values())
        injected = clean["harness.tf"] + '\nresource "aws_iam_role" "x" {\n}\n'
        assert 'resource "aws_iam_role"' in injected, "the predicate cannot see it"

    def test_a_hardcoded_account_id_is_detected(self):
        def offenders(source: str) -> list[str]:
            return [m.group(1) for m in re.finditer(r"(?<![\d])(\d{12})(?![\d])", source)
                    if m.group(1) != TestIacCarriesNoHardcodedIdentity._PLACEHOLDER]

        clean = _terraform_sources()["harness.tf"]
        assert offenders(clean) == []
        assert offenders(clean + '\nlocals { acct = "123456789099" }\n') == \
            ["123456789099"]

    def test_the_arn_regex_check_can_fail(self):
        """The INV-IAC-2 predicate, shown to reject something. An always-accepting
        regex (e.g. one that lost its anchors) would pass every case above."""
        regex = TestTerraformExecutionRoleGate._role_arn_regex()
        assert re.match(regex, "arn:aws:iam::000000000000:role/x")
        assert not re.match(regex, "arn:aws:iam::000000000000:user/x")
        # An UNANCHORED variant would wrongly accept a prefixed value — the mistake
        # this pins against.
        unanchored = regex.lstrip("^").rstrip("$")
        assert re.search(unanchored, "junk arn:aws:iam::000000000000:role/x"), (
            "the pattern body no longer matches at all; this control is vacuous"
        )
        assert not re.match(regex, "junk arn:aws:iam::000000000000:role/x")
