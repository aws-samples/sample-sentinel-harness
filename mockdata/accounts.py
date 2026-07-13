"""mockdata.accounts — a FICTIONAL multi-account cloud inventory for ops-automation.

.. warning::
   **CLEARLY-LABELED MOCK DATA for POC / testing only.** This is *not* a real
   AWS Organization, *not* a real account inventory, and describes *no* real
   company or environment. The 12-digit account ids below
   (``111111111111`` / ``222222222222`` / ``333333333333`` / ``444444444444``)
   are **obviously-fictional repeated-digit demo ids** — they are NOT real AWS
   account numbers. They are used only as opaque keys in this data file and are
   deliberately never placed in an ``arn:`` / ``iam::`` context anywhere.

Why this module exists
----------------------
The ops-automation capability ("MCP does multi-account ticketing / resource
queries") needs a coherent multi-account world to reason over: a supervisor
agent should be able to enumerate accounts, list the open operational findings
in each, and open a ticket for the real ones. Rather than let the ops tool
invent its own disconnected fixtures, it reads *this* inventory so every query
agrees on the same accounts, resource counts, and findings.

This inventory is intentionally SEPARATE from :mod:`mockdata.world` (the
alert-triage SecOps world). Multi-account cloud posture is a different plane
than per-host SIEM/asset data, so it gets its own self-contained loader; the
world's Log4Shell narrative is untouched.

Determinism
-----------
Everything here is literal Python data. There is no clock, no randomness, no
I/O. :func:`accounts` returns a fresh deep copy each call, so a caller mutating
the result can never corrupt the shared source. Same call in -> same data out.

Finding types
-------------
Each account carries zero or more open operational findings. The ``finding_type``
values are a small closed vocabulary the ops tool filters on:

- ``public_s3``            — an S3 bucket exposed to the public internet.
- ``over_permissive_role`` — an IAM role with a wildcard / admin-style policy.
- ``unencrypted_volume``   — an EBS volume without at-rest encryption.
- ``mfa_disabled``         — a privileged principal without MFA enforced.

API
---
- :func:`accounts` -> the full account inventory (fresh deep copy each call).
- :func:`finding_types` -> the sorted set of finding_type values present.
"""

from __future__ import annotations

import copy
from typing import Any, Dict, List

# --------------------------------------------------------------------------- #
# Fictional multi-account inventory (synthetic, deterministic).
#
# Four accounts spanning prod + non-prod. The two prod accounts each carry a
# genuine open finding (a public S3 bucket; an over-permissive role) so the
# triage supervisor has real issues to open tickets for; dev-sandbox has a
# low-severity finding; security-audit is clean (a negative case so the agent
# must not over-report). Resource counts are small, round, and fictional.
#
# Account ids are OBVIOUSLY-FICTIONAL repeated-digit demo ids, NOT real AWS
# account numbers, and never appear in an arn:/iam:: context.
# --------------------------------------------------------------------------- #
_ACCOUNTS: List[Dict[str, Any]] = [
    {
        "account_id": "111111111111",  # fictional demo id, not a real AWS account
        "name": "prod-payments (fictional)",
        "environment": "prod",
        "region": "us-east-1",
        "resources": {"ec2": 24, "s3_buckets": 12, "iam_roles": 18},
        "findings": [
            {
                "finding_id": "OPS-111-001",
                "finding_type": "public_s3",
                "severity": "high",
                "resource": "payments-invoices-archive",  # bucket name, no arn
                "description": (
                    "S3 bucket 'payments-invoices-archive' has a public-read "
                    "bucket policy; block-public-access is off."
                ),
            },
            {
                "finding_id": "OPS-111-002",
                "finding_type": "over_permissive_role",
                "severity": "high",
                "resource": "payments-batch-runner",  # role name, no arn
                "description": (
                    "IAM role 'payments-batch-runner' attaches a policy with "
                    "Action:'*' Resource:'*' (admin-equivalent)."
                ),
            },
        ],
    },
    {
        "account_id": "222222222222",  # fictional demo id, not a real AWS account
        "name": "prod-web (fictional)",
        "environment": "prod",
        "region": "us-west-2",
        "resources": {"ec2": 16, "s3_buckets": 9, "iam_roles": 11},
        "findings": [
            {
                "finding_id": "OPS-222-001",
                "finding_type": "unencrypted_volume",
                "severity": "medium",
                "resource": "web-tier-data-vol-07",  # volume label, no arn
                "description": (
                    "EBS volume 'web-tier-data-vol-07' is not encrypted at "
                    "rest (no default-encryption on the region)."
                ),
            },
        ],
    },
    {
        "account_id": "333333333333",  # fictional demo id, not a real AWS account
        "name": "dev-sandbox",
        "environment": "dev",
        "region": "eu-west-1",
        "resources": {"ec2": 5, "s3_buckets": 3, "iam_roles": 6},
        "findings": [
            {
                "finding_id": "OPS-333-001",
                "finding_type": "mfa_disabled",
                "severity": "low",
                "resource": "sandbox-dev-user",  # principal name, no arn
                "description": (
                    "Privileged principal 'sandbox-dev-user' has console "
                    "access without MFA enforced (dev sandbox, low blast radius)."
                ),
            },
        ],
    },
    {
        "account_id": "444444444444",  # fictional demo id, not a real AWS account
        "name": "security-audit",
        "environment": "prod",
        "region": "us-east-1",
        "resources": {"ec2": 2, "s3_buckets": 4, "iam_roles": 8},
        # Deliberately CLEAN — a negative case so a triage agent must not
        # fabricate findings for an account that has none.
        "findings": [],
    },
]


def accounts() -> List[Dict[str, Any]]:
    """Return the fictional multi-account inventory (fresh deep copy).

    Each account is ``{account_id, name, environment, region, resources,
    findings}``. Callers may freely mutate the returned structure without
    corrupting the shared source, which is what keeps repeated queries
    deterministic. Account order is stable (definition order).
    """
    return copy.deepcopy(_ACCOUNTS)


def finding_types() -> List[str]:
    """Return the sorted, de-duplicated set of finding_type values present.

    Useful for validating a ``finding_type`` filter against the closed
    vocabulary the inventory actually uses.
    """
    seen = {
        f["finding_type"]
        for acct in _ACCOUNTS
        for f in acct["findings"]
    }
    return sorted(seen)
