---
name: ioc-vetting
description: Standard operating procedure for vetting an indicator of compromise (file hash, domain, or IP address) before acting on it. Use when an IOC arrives from an alert, threat feed, or report and needs a reputation lookup, a confidence rating, and false-positive checks. Produces a deterministic confidence score, reputation summary, and disposition, with all enrichment fetched via reputation tools and web_search rather than raw downloads, and a human gate before any blocking action.
---

# IOC Vetting SOP

How a security operations team decides whether an indicator (hash / domain / IP) is malicious, benign, or unknown — and how confident that verdict is — before anything gets blocked. The purpose is to avoid both missed threats and self-inflicted outages from blocking legitimate infrastructure.

## Operating Principles

1. **Reputation, not a single source.** No single feed is authoritative. Confidence comes from *agreement across independent sources* plus context.
2. **Deterministic confidence.** The confidence score is computed by fixed rules from source agreement — never estimated by the model.
3. **False-positive checks are mandatory.** Every candidate-malicious verdict must pass explicit FP checks (see per-type checks) before disposition.
4. **Egress via reputation tools + `web_search`.** Query reputation through the `enrich_ioc` tool and pull context via `web_search` (text). Never download the sample, resolve-and-connect, or fetch content from the indicator.
5. **Blocking is human-gated.** This SOP produces a disposition and recommendation; a human approves before an IOC is added to a blocklist or containment fires.

## Step 1 — Normalize and classify the indicator

- **Hash**: identify algorithm (MD5/SHA1/SHA256); prefer SHA256. Reject malformed hashes.
- **Domain**: strip scheme/path; extract the registrable domain and any subdomain; note if it is a known dynamic-DNS or CDN parent.
- **IP**: validate; note if RFC1918/private, shared cloud/CDN, or a known egress/NAT range.

Record the indicator type; the FP checks differ per type.

## Step 2 — Reputation lookup

Call `enrich_ioc`. Collect from each independent source:

| Field | Meaning |
|---|---|
| `verdict` | malicious / suspicious / clean / unknown per source |
| `detection_ratio` | (hash) engines flagging / total |
| `first_seen` / `last_seen` | age and activity recency |
| `categories` | phishing, C2, malware-hosting, spam, etc. |
| `passive_dns` | (domain/IP) resolution history |
| `whois_age` | (domain) registration age |

Use `web_search` for corroborating public reporting (advisories, writeups) — cite it. Record `UNKNOWN` where a source returns nothing.

## Step 3 — Compute confidence (deterministic)

Count independent sources with a malicious/suspicious verdict as `M`; total sources queried as `N`.

- **HIGH** confidence-malicious: `M >= 3` independent sources, OR (`M >= 2` AND a reputable named source lists an active category like C2/malware-hosting), OR hash `detection_ratio >= 0.4`.
- **MEDIUM**: `M == 2`, OR hash `detection_ratio` in `0.1–0.4`, OR one reputable source with strong category + recent `last_seen`.
- **LOW**: `M == 1` and weak/stale, OR only heuristic/generic detections.
- **CLEAN**: `M == 0` and at least one reputable source explicitly clean.
- **UNKNOWN**: no source has data (`N` effectively 0 with signal).

Confidence is a function of source agreement and recency only — do not adjust it by intuition.

## Step 4 — False-positive checks (mandatory, per type)

**Hash**
- Is it a known-good / signed system or vendor binary (LOLBins, common installers)? A signed, widely-distributed file flagged by 1–2 engines is likely FP.
- Is the detection a generic/heuristic name only (e.g. `Generic.*`, `Heur.*`) with low ratio? Downgrade.

**Domain**
- Is it a shared platform (CDN, cloud storage, SaaS, URL shortener, dynamic DNS parent)? Blocking the parent domain causes collateral outage — flag for narrower scope (full URL/subdomain).
- Is it a legitimate but recently-compromised site? Note remediation likely; blocking may be temporary.
- Registration age: very old + long clean history reduces suspicion; brand-new + no history raises it.

**IP**
- Is it shared cloud/CDN/hosting infrastructure? Blocking causes collateral damage — recommend blocking the specific service/domain, not the IP.
- Is it a known egress/NAT/proxy or a security-vendor scanner? Likely FP for inbound-context alerts.
- Is it your own or a partner's infrastructure per the asset inventory? Hard FP.

Any failed FP check either downgrades confidence or changes the recommendation from "block" to "monitor / narrow scope".

## Step 5 — Disposition and recommendation

| Confidence | Disposition | Recommendation |
|---|---|---|
| HIGH (FP checks passed) | MALICIOUS | **BLOCK** candidate → human approval |
| MEDIUM | SUSPICIOUS | **MONITOR** + hunt for related activity; block only with narrowed scope + approval |
| LOW | INCONCLUSIVE | **MONITOR**; enrich further |
| CLEAN | BENIGN | **NO-ACTION** (allowlist if repeatedly re-alerting) |
| UNKNOWN | UNKNOWN | **MONITOR**; re-check later |
| FP check failed | LIKELY FALSE POSITIVE | **NO-ACTION** / narrow scope; document rationale |

## Step 6 — Emit structured output

```json
{
  "indicator": "<value>",
  "type": "hash|domain|ip",
  "sources_malicious": 0,
  "sources_total": 0,
  "detection_ratio": 0.0,
  "confidence": "HIGH|MEDIUM|LOW|CLEAN|UNKNOWN",
  "disposition": "MALICIOUS|SUSPICIOUS|INCONCLUSIVE|BENIGN|LIKELY_FALSE_POSITIVE|UNKNOWN",
  "fp_checks": [{"check": "...", "result": "pass|fail", "note": "..."}],
  "recommendation": "BLOCK|MONITOR|NO-ACTION|NARROW-SCOPE",
  "collateral_risk": "none|shared-infra|compromised-legit-site",
  "citations": ["tool:enrich_ioc", "web_search:<url>"],
  "requires_human_approval": true
}
```

## Guardrails

- Never connect to, resolve-and-fetch from, or download the indicator. Reputation lookup only.
- Never auto-add to a blocklist — blocking is a human-approved action, and shared-infra blocks can cause outages.
- Prefer narrowest-scope blocking (full URL/host over parent domain; specific service over shared IP).
- Persist the verdict and FP rationale to memory for consistency and to speed up repeat sightings.
