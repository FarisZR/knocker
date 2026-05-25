# Use a specific, stable version of Python for reproducibility
FROM python:3.13-slim

ARG UV_VERSION=0.11.2

# Set the working directory in the container
WORKDIR /app

# Create a non-root user to run the application for better security
# NOTE: When firewalld integration is enabled, the container must run as root
# to access the system dbus. This is configured in docker-compose.yml.
RUN groupadd --gid 1001 appuser && \
    useradd --create-home --uid 1001 --gid 1001 appuser

# Copy project metadata and install locked runtime dependencies
COPY pyproject.toml uv.lock ./
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl firewalld && \
    python -m pip install --no-cache-dir "uv==${UV_VERSION}" && \
    uv sync --locked --no-dev --no-cache && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy the rest of the application code
COPY src/ /app/src/

# Create and change ownership of the data directory to the appuser
RUN mkdir -p /data && chown -R appuser:appuser /data /app

# Switch to the non-root user for running the application
USER appuser

ENV PATH="/app/.venv/bin:$PATH"

WORKDIR /app/src

# Expose the port the app runs on
EXPOSE 8000


# Define the command to run the application
# Uvicorn is run with --forwarded-allow-ips="*" to trust the X-Forwarded-For
# header from any proxy within the Docker network. This is safe because
# only Caddy is on the same network and can reach this container.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--forwarded-allow-ips", "*"]
