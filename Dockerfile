# Pin the multi-architecture runtime base by immutable manifest digest.
FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928

ARG TARGETARCH
ARG TARGETVARIANT
ARG UV_VERSION=0.13.8

# Set the working directory in the container
WORKDIR /app

ENV UV_LINK_MODE=copy
ENV UV_COMPILE_BYTECODE=1
ENV UV_PYTHON_DOWNLOADS=0
ENV KNOCKER_CONFIG_PATH=/app/knocker.yaml

# Install system packages before running the uv installer, which requires curl.
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl firewalld && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install the official uv release artifact for each supported architecture.
# Checksums are pinned from the uv 0.13.8 release, preserving arm/v7 support
# without executing the remote installer script.
RUN set -eux; \
    case "${TARGETARCH}/${TARGETVARIANT}" in \
      "amd64/") uv_target="x86_64-unknown-linux-gnu"; uv_sha256="5acfd9177cfecf0bf87578f059728215ccc884388988f55f7a65041b57387d91" ;; \
      "arm64/") uv_target="aarch64-unknown-linux-gnu"; uv_sha256="74f2f5c6024d397481db228db8fc25eed420db192243f88438c118e7e013e585" ;; \
      "arm/v7") uv_target="armv7-unknown-linux-gnueabihf"; uv_sha256="079618cfa7110f0bf812355cc030d3f309b2ebc085c3c8bcb7c291edf874d57d" ;; \
      *) echo "Unsupported target architecture: ${TARGETARCH}/${TARGETVARIANT}" >&2; exit 1 ;; \
    esac; \
    uv_archive="uv-${uv_target}.tar.gz"; \
    curl --fail --silent --show-error --location \
      "https://github.com/astral-sh/uv/releases/download/${UV_VERSION}/${uv_archive}" \
      --output "/tmp/${uv_archive}"; \
    echo "${uv_sha256}  /tmp/${uv_archive}" | sha256sum --check --strict; \
    tar --extract --gzip --file "/tmp/${uv_archive}" --directory /tmp; \
    install -m 0755 "/tmp/uv-${uv_target}/uv" /usr/local/bin/uv; \
    install -m 0755 "/tmp/uv-${uv_target}/uvx" /usr/local/bin/uvx; \
    rm -rf "/tmp/${uv_archive}" "/tmp/uv-${uv_target}"

# Create a non-root user to run the application for better security
# NOTE: When firewalld integration is enabled, the container must run as root
# to access the system dbus. This is configured in docker-compose.yml.
RUN groupadd --gid 1001 appuser && \
    useradd --create-home --uid 1001 --gid 1001 appuser

COPY pyproject.toml uv.lock ./
RUN uv sync --locked --no-dev

# Copy the rest of the application code
COPY src ./src

# Create and change ownership of the data directory to the appuser
RUN mkdir -p /data && chown appuser:appuser /data

# Switch to the non-root user for running the application
USER appuser

ENV PATH="/app/.venv/bin:$PATH"

# Expose the port the app runs on
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl --fail --silent http://localhost:8000/health > /dev/null || exit 1


# Define the command to run the application.
# Keep Uvicorn from rewriting the direct peer from forwarded headers; Knocker
# performs its own trusted-proxy validation using server.trusted_proxies.
CMD ["uvicorn", "src.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--no-proxy-headers"]
