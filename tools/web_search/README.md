# web_search

Egress-controlled, text-only open-web search tool template for a security
operations (SecOps) team.

## Purpose

Give an agent open-web context during threat research (advisories, write-ups,
news of active exploitation) as **text only**: title, URL, and snippet per
result. Wire it into an Amazon Bedrock AgentCore Gateway as an MCP target.

## Egress-control rationale

Threat research constantly touches hostile content. A tool that could fetch
arbitrary bytes would become a malware-delivery / SSRF primitive: an
attacker-controlled page could serve a binary or exploit payload straight
into the runtime. This tool is deliberately constrained:

1. **Text only** — returns search *results* (title/url/snippet). It never
   downloads page bodies, attachments, or binaries. There is no "fetch URL"
   capability here by design.
2. **Single egress chokepoint** — all outbound access goes through one
   configured `WEB_SEARCH_ENDPOINT`, not arbitrary hosts. In a deployment
   that endpoint sits behind an egress allowlist / NAT policy.
3. **Opt-in live mode** — live search runs only when `WEB_SEARCH_LIVE=1`;
   default mode returns deterministic stub results with zero network I/O.
4. **Bounded** — query length (512 chars) and result count (max 10) are
   capped; the live response read is also size-capped.

## Signature

```python
def handler(event, context) -> dict
```

- `event`: `{"query": "Log4Shell advisory", "max_results": 5}`
- `context`: Lambda-style context (unused by the stub).

## Input validation

- `query`: non-empty string, max 512 chars.
- `max_results`: integer between 1 and 10 (default 5).
- Invalid input returns `validation_error`.

## Egress & secrets control

- Live egress only when `WEB_SEARCH_LIVE=1` and `WEB_SEARCH_ENDPOINT` is set.
- `WEB_SEARCH_API_KEY` is read from the environment only — never hardcoded,
  logged, or returned.
- Execution role / region come from `SENTINEL_EXECUTION_ROLE_ARN`,
  `SENTINEL_REGION`, and `AWS_PROFILE`. No hardcoded account IDs or ARNs.

## Run locally

```bash
python handler.py
```
