# Use a specific, stable version of Python for reproducibility
FROM python:3.13-slim

# Set the working directory in the container
WORKDIR /app

# Create a non-root user to run the application for better security
# NOTE: When firewalld integration is enabled, the container must run as root
# to access the system dbus. This is configured in docker-compose.yml.
RUN groupadd --gid 1001 appuser && \
    useradd --create-home --uid 1001 --gid 1001 appuser

# Copy requirements and install dependencies system-wide
COPY src/requirements.txt .
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl firewalld && \
    pip install --no-cache-dir -r requirements.txt && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy the rest of the application code
COPY src/ .

# Create and change ownership of the data directory to the appuser
RUN mkdir -p /data && chown appuser:appuser /data

# Switch to the non-root user for running the application
USER appuser

# Expose the port the app runs on
EXPOSE 8000


# Define the command to run the application.
# Keep Uvicorn from rewriting the direct peer from forwarded headers; Knocker
# performs its own trusted-proxy validation using server.trusted_proxies.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--no-proxy-headers"]
