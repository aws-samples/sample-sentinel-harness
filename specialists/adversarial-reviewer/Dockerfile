# adversarial-reviewer A2A specialist — multi-stage, arm64, non-root, pinned base.
# AgentCore Runtime runs arm64 microVMs; build for that platform explicitly so a
# local (often x86) build does not silently produce an unbootable image.
#
# Two stages:
#   builder  — installs the pinned deps into a private venv (has build toolchain).
#   runtime  — copies ONLY the ready venv + app code into a fresh slim base, so the
#              shipped image carries no pip caches / build tools (smaller, less attack
#              surface). This is the standard multi-stage python pattern.

# --- Stage 1: builder --------------------------------------------------------
# Pinned base by full tag (not :latest) so builds are reproducible.
FROM --platform=linux/arm64 python:3.13-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Build into an isolated venv we can copy wholesale into the runtime stage.
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install deps first (layer cache): only requirements.txt busts this layer.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# --- Stage 2: runtime --------------------------------------------------------
FROM --platform=linux/arm64 python:3.13-slim AS runtime

# Never write .pyc, never buffer stdout (so container logs stream to CloudWatch).
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    SENTINEL_A2A_HOST=0.0.0.0 \
    SENTINEL_A2A_PORT=9000

WORKDIR /app

# Bring the ready-built venv over from the builder stage (no pip / build tools ship).
COPY --from=builder /opt/venv /opt/venv

# Copy the specialist code.
COPY agent_a2a.py .

# Non-root: create an unprivileged user and drop to it. The runtime microVM is
# the isolation boundary; running non-root is defence-in-depth.
RUN useradd --create-home --uid 10001 specialist \
    && chown -R specialist:specialist /app
USER specialist

# A2A JSON-RPC + /ping health both served on this port.
EXPOSE 9000

# Liveness: AgentCore polls /ping. curl is not in slim; use python one-liner.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import os,urllib.request;urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('SENTINEL_A2A_PORT','9000')+'/ping').read()"]

# serve() binds the A2AServer + FastAPI /ping (blocking).
CMD ["python", "-m", "agent_a2a"]
