# Compliance control mapping

*How `sentinel-harness`'s shipped capabilities map to the control frameworks a
security team audits against: SOC 2 (Trust Services Criteria), ISO/IEC 27001:2022
Annex A, and NIST Cybersecurity Framework (CSF) 2.0.*

> **Scope & honesty.** This maps the platform's **built + tested / live-validated**
> capabilities to the controls they *support*. It is a mapping of technical
> building blocks — it is **not a certification** and not a claim that adopting
> this reference makes you compliant — compliance is an organizational program
> (policies, evidence, auditors) that this platform *supports*, not replaces.
> Every capability cited below is anchored to a real file in this repo, and
> `tests/test_compliance_mapping.py` fails the build if any anchor stops existing,
> so this document cannot drift into aspirational claims.
>
> Labels mirror the README status matrix: 🟢 live-validated / built+tested ·
> 🟡 built, partial. Nothing here is customer- or company-specific.

---

## 1. Capability anchors (machine-verified)

Each capability below is the concrete, shipped thing the control mappings lean
on. The `anchor` is a repo path the compliance test asserts exists.

| # | Capability | Status | Anchor |
|---|---|:--:|---|
| C1 | Human-in-the-loop approval gates (`inline_function`) — no high-risk action without a human | 🟢 | `sentinel_harness/loader.py` |
| C2 | Dual-gate tool/skill registry governance (live only if registry-approved ∧ code-mapped) | 🟢 | `sentinel_harness/registry.py` |
| C3 | Live AgentCore Registry control plane (DRAFT→PENDING_APPROVAL, `autoApproval=false`) | 🟢 | `sentinel_harness/registry_live.py` |
| C4 | PreToolUse sandbox hooks (path confinement / command allowlist / read-only cloud) | 🟢 | `sentinel_harness/sandbox_hooks.py` |
| C5 | Safety veto + regression guard (never promote a worse/unsafe agent) | 🟢 | `sentinel_harness/loop_safety.py` |
| C6 | Hash-chained, append-only provenance ledger | 🟢 | `sentinel_harness/provenance.py` |
| C7 | Multi-signal observability (tokens / latency / errors / HITL hits / eval score) | 🟢 | `sentinel_harness/observability.py` |
| C8 | Enterprise gateway auth — Cognito CUSTOM_JWT + interceptor/guardrail policy engine | 🟢 | `sentinel_harness/gateway.py` |
| C9 | Guardrail secret/PII masking on tool responses (live-deployed) | 🟢 | `iac-cdk/lib/guardrail-stack.ts` |
| C10 | Cognito identity stack (human aud vs M2M client) | 🟢 | `iac-cdk/lib/identity-stack.ts` |
| C11 | Private VPC + default-deny egress (no IGW / no 0.0.0.0/0 / PrivateLink-only) | 🟢 | `iac-cdk/lib/network-stack.ts` |
| C12 | CloudWatch observability + Budgets alarm stack | 🟢 | `iac-cdk/lib/observability-stack.ts` |
| C13 | Documented threat model (STRIDE + agent surface) | 🟢 | `docs/THREAT-MODEL.md` |
| C14 | Secrets-at-rest posture + token-vault refs (agent never sees plaintext) | 🟢 | `docs/SECRETS.md` |
| C15 | Vulnerability disclosure policy + supported-version SLA | 🟢 | `SECURITY.md` |
| C16 | All-domain evaluation with a hard safety gate (5 domains, force-fail unsafe) | 🟢 | `sentinel_harness/eval_datasets.py` |
| C17 | Independent adversarial reviewer (generation ≠ evaluation; no self-approval bias) | 🟢 | `specialists/adversarial-reviewer/` |
| C18 | Supply-chain integrity — SBOM + SLSA provenance + pinned deps in CI | 🟢 | `.github/workflows/release.yml` |

---

## 2. SOC 2 — Trust Services Criteria

| TSC | Criterion (abbrev.) | Supporting capabilities |
|---|---|---|
| CC5.2 | Control activities over technology | C1 HITL gates · C2/C3 registry dual-gate · C4 sandbox |
| CC6.1 | Logical access — identity & auth | C8 CUSTOM_JWT gateway · C10 Cognito identity |
| CC6.3 | Least-privilege authorization | C2 dual-gate (explicit allowlist, never `*`) · C4 read-only cloud |
| CC6.6 | Boundary protection / restrict external access | C11 private VPC + default-deny egress · C9 Guardrail masking |
| CC6.7 | Restrict data transmission / prevent leakage | C9 secret/PII masking · C11 egress allowlist · C14 token vault |
| CC7.1 | Detect & monitor for anomalies | C7 multi-signal metrics · C12 CloudWatch + Budgets |
| CC7.2 | Monitor system components | C7 observability · C6 provenance ledger |
| CC7.3 | Evaluate security events | C16 all-domain eval + safety gate · C17 adversarial reviewer |
| CC8.1 | Change management (authorize, test, approve) | C1 HITL promotion gate · C5 regression guard + safety veto · C3 registry approval |
| CC4.1 | Monitoring of controls | C6 append-only provenance · C7 eval-score metric |

## 3. ISO/IEC 27001:2022 — Annex A

| Annex A | Control | Supporting capabilities |
|---|---|---|
| A.5.15 | Access control | C8 gateway auth · C2 dual-gate |
| A.5.18 | Access rights (provision/approve) | C1 HITL · C3 registry DRAFT→approval |
| A.8.2 | Privileged access rights | C4 sandbox read-only cloud · C2 explicit allowlist |
| A.8.9 | Configuration management | C2/C3 registry governance · C6 provenance |
| A.8.15 | Logging | C7 structured multi-signal logs · C6 ledger |
| A.8.16 | Monitoring activities | C7 metrics · C12 CloudWatch/Budgets |
| A.8.20 | Network security | C11 private VPC + default-deny egress |
| A.8.23 | Web filtering / egress control | C11 egress allowlist (only web_search reaches out) |
| A.8.24 | Use of cryptography / secrets | C14 secrets-at-rest + token vault · C9 masking |
| A.8.28 | Secure coding | C17 adversarial review · C18 supply-chain integrity |
| A.5.7 | Threat intelligence / modeling | C13 threat model |
| A.5.25 | Assessment & decision on security events | C16 evaluation + safety gate · C5 safety veto |
| A.6.8 | Security event reporting | C15 vulnerability disclosure policy |

## 4. NIST CSF 2.0 — Functions & Categories

| Function | Category | Supporting capabilities |
|---|---|---|
| GOVERN (GV) | GV.SC — supply chain risk | C18 SBOM/SLSA/pinned deps · C2/C3 registry governance |
| GOVERN (GV) | GV.RM — risk management strategy | C13 threat model · C5 regression guard |
| IDENTIFY (ID) | ID.RA — risk assessment | C13 threat model · C16 evaluation coverage |
| PROTECT (PR) | PR.AA — identity & access | C8 gateway auth · C10 Cognito · C2 dual-gate |
| PROTECT (PR) | PR.DS — data security | C9 masking · C14 secrets vault |
| PROTECT (PR) | PR.PS — platform security | C4 sandbox · C11 private VPC egress control |
| PROTECT (PR) | PR.IR — technology resilience | C5 regression guard (never promote worse) |
| DETECT (DE) | DE.CM — continuous monitoring | C7 multi-signal metrics · C12 CloudWatch |
| DETECT (DE) | DE.AE — adverse event analysis | C16 all-domain eval · C17 adversarial reviewer |
| RESPOND (RS) | RS.MA — incident management | C1 HITL containment gate · C6 provenance trail |
| RESPOND (RS) | RS.AN — incident analysis | C6 append-only ledger (forensic trail) |

---

## 5. The three control themes this platform is built around

1. **Nothing high-risk happens without a human (change control).** Every
   promotion / containment / publish is an `inline_function` HITL gate (C1), a
   registry record stays `DRAFT` until approved (C3), and the self-improvement
   loop can never promote a worse or unsafe agent (C5). Maps to SOC 2 CC8.1,
   ISO A.5.18 / A.8.9, CSF PR.IR.
2. **Least privilege + isolation, enforced not asserted.** Tools are live only if
   registry-approved AND code-mapped with an explicit allowlist (C2), run behind a
   PreToolUse sandbox (C4), in a private VPC with default-deny egress (C11), with
   secret/PII masking on responses (C9). Maps to SOC 2 CC6.x, ISO A.8.2 / A.8.20 /
   A.8.23, CSF PR.AA / PR.PS.
3. **Everything is observable and provable (monitoring + auditability).**
   Multi-signal metrics (C7), an append-only hash-chained provenance ledger (C6),
   all-domain evaluation with a safety gate (C16), and an independent adversarial
   reviewer (C17). Maps to SOC 2 CC4.1 / CC7.x, ISO A.8.15 / A.8.16, CSF DE.CM /
   DE.AE.

---

## 6. What this does NOT cover (honest gaps)

- **No certification.** This is a capability mapping, not an audit result. SOC 2 /
  ISO 27001 require an organizational program (scoped policies, a control period,
  collected evidence, an external auditor) that a reference implementation cannot
  provide.
- **Org-specific controls are out of scope by design.** HR/personnel security,
  physical security, business-continuity, and vendor-management controls are
  organizational, not platform — this repo maps only the *technical* controls its
  code supports.
- **`*_LIVE` seams are the customer's boundary.** Data-plane connectors ship as
  offline mocks with a `*_LIVE` opt-in; connecting a real SIEM/asset/ticketing
  backend (and the access controls around it) is the adopter's responsibility.
