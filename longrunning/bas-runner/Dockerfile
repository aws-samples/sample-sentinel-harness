# bas-runner · long-running BAS Runtime image
# ============================================
# AgentCore Runtime images must be linux/arm64 and SHOULD run as a non-root user
# (defense-in-depth for a sandboxed adversary-emulation workload). Multi-stage so
# the runtime layer carries only what it needs.
FROM --platform=linux/arm64 public.ecr.aws/docker/library/python:3.12-slim AS base

# --- build deps into a venv we can copy into a clean final layer ---------------
FROM base AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /build
COPY requirements.txt ./
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip \
    && /opt/venv/bin/pip install -r requirements.txt

# --- runtime layer -------------------------------------------------------------
FROM base AS runtime
ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    # Local JSON checkpoints by default; set SENTINEL_BAS_S3_BUCKET to mirror to S3.
    SENTINEL_BAS_CHECKPOINT_DIR=/workspace/bas_checkpoints

COPY --from=build /opt/venv /opt/venv

# Non-root user; workspace owned by it (also the sandbox root for security hooks).
RUN useradd --create-home --uid 10001 basrunner \
    && mkdir -p /workspace/bas_checkpoints \
    && chown -R basrunner:basrunner /workspace
WORKDIR /app
COPY --chown=basrunner:basrunner . /app

USER basrunner

# AgentCore Runtime contract: HTTP server on 8080 started by app.run().
EXPOSE 8080
CMD ["python", "bedrock_entrypoint.py"]
