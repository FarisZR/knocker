# Use a specific, stable version of Python for reproducibility
FROM python:3.13-slim

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

# Install uv from the official installer so multi-arch builds work.
ADD https://astral.sh/uv/0.11.2/install.sh /uv-installer.sh
RUN sh /uv-installer.sh && rm /uv-installer.sh

ENV PATH="/root/.local/bin:$PATH"

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


# Define the command to run the application.
# Keep Uvicorn from rewriting the direct peer from forwarded headers; Knocker
# performs its own trusted-proxy validation using server.trusted_proxies.
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-proxy-headers"]
