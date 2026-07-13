# Architecture Decision Records (ADRs)

This directory records the **load-bearing decisions** behind `sentinel-harness` —
especially the invariants an extender must **not** "fix." Several of these look
like limitations or missing features at first glance; they are deliberate,
and undoing them breaks a security or governance property the project depends on.

Read the relevant ADR **before** you "simplify" one of these seams.

## Format

Each ADR uses the standard lightweight format: **Context** (the forces at play),
**Decision** (what we chose), **Consequences** (what follows, good and bad).
Each has a status and a stable number.

## Index

| ADR | Title | Status |
|---|---|---|
| [0001](0001-load-bearing-invariants.md) | Load-bearing invariants an extender must not "fix" | Accepted |

## Related docs

- [`docs/GOVERNANCE.md`](../GOVERNANCE.md) — Registry dual-gate, HITL, sandbox hooks, tag-guard
- [`docs/SETUP.md`](../SETUP.md) — least-privilege execution role (and why it omits `InvokeAgentRuntimeCommand`)
- [`docs/FIDELITY-REPORT.md`](../FIDELITY-REPORT.md) — honest real-vs-built self-audit
- [`docs/TROUBLESHOOTING.md`](../TROUBLESHOOTING.md) — known footguns (symptom → cause → fix)
