# Pin the multi-architecture runtime base by immutable manifest digest.
FROM python:3.13-slim@sha256:9662417aace5ae7b8e2609cce472b72a8958e134ba372808abe9cc1a0c0125e6

ARG TARGETARCH
ARG TARGETVARIANT
ARG UV_VERSION=0.11.31

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
# Checksums are pinned from the uv 0.11.31 release, preserving arm/v7 support
# without executing the remote installer script.
RUN set -eux; \
    case "${TARGETARCH}/${TARGETVARIANT}" in \
      "amd64/") uv_target="x86_64-unknown-linux-gnu"; uv_sha256="8cc1cd82d434ec565376f98bd938d4b715b5791a80ff2d3aa78821cf85091b4b" ;; \
      "arm64/") uv_target="aarch64-unknown-linux-gnu"; uv_sha256="d74f23949fd07be4970f293d06ca99d87cd2a78a341c3d7b7fc0df7bc2d8a145" ;; \
      "arm/v7") uv_target="armv7-unknown-linux-gnueabihf"; uv_sha256="de23124095c4df154d3807495b59f1985d8d9460bd70d3de61fef2034756bd61" ;; \
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
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-proxy-headers"]
