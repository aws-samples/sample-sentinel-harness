# litellm.gateway — inference-gateway skeleton

A standalone, provider-agnostic **inference gateway**: one audited chokepoint that
a specialist (or any caller) points at instead of talking to a model provider
directly. Every completion flows through a single entry-point and emits one
structured audit record (model + token usage + latency + status) — **never** a
prompt, completion, header, API key, or any provider credential.

## Real vs. skeleton

| Piece | Status | Notes |
|---|---|---|
| Audit hook (`build_audit_record` / `audit_record`) | **real** | Pure, dependency-free, fully offline-tested. Emits only non-sensitive telemetry; a hard denylist strips anything secret-ish. |
| Entry-point contract (`InferenceGateway.complete`, `complete`) | **real (surface) / skeleton (call)** | The class, audit wrapping, error path, and lazy model construction are real. The actual model invocation is a thin `LiteLLMModel` call whose exact API you wire to your `strands`/`litellm` version. |
| `LiteLLMModel` construction | **skeleton** | Heavy deps (`litellm`, `strands`) are import-guarded — imported lazily inside `InferenceGateway._model`, so this package imports and tests without them installed. |
| Provider routing / retries / rate-limits / cost caps | **not implemented** | Left to LiteLLM config + your deployment. This skeleton is the audited seam, not a full proxy server. |

The import-guard mirrors the specialists under `specialists/*`: the module is
always importable and inspectable offline; the real dependency is only touched when
you run a completion inside a container that has `litellm` installed.

## How a specialist points at it

A specialist (`specialists/*/agent_a2a.py`) builds its `Agent` with a
`LiteLLMModel` directly. To route that specialist's inference through this audited
gateway instead, replace the direct call with the gateway entry-point:

```python
# In a specialist, instead of calling LiteLLMModel(...).converse(...) directly:
from litellm.gateway import InferenceGateway

gateway = InferenceGateway(model_id=os.environ["SENTINEL_GATEWAY_MODEL"])
result = gateway.complete(messages)   # one audit record emitted per call
```

or the one-liner convenience for simple callers:

```python
from litellm.gateway import complete
result = complete(messages)           # uses the env-configured default model
```

The audit records land on the `sentinel.litellm.gateway.audit` logger — attach a
handler (or a CloudWatch sink) in your container entrypoint to ship them.

## Configuration (12-factor — no hardcoded account / ARN / model / key)

| Env var | Meaning | Default |
|---|---|---|
| `SENTINEL_GATEWAY_MODEL` | LiteLLM provider-prefixed model id | `bedrock/global.anthropic.claude-haiku-4-5-20251001-v1:0` |

Provider credentials (`AWS_*`, `OPENAI_API_KEY`, ...) are read by LiteLLM from the
standard environment variables. **This package never reads, stores, or logs them.**
