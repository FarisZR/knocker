# Use a specific, stable version of Python for reproducibility
FROM python:slim

# Set the working directory in the container
WORKDIR /app

# Create a non-root user to run the application for better security
RUN groupadd --gid 1001 appuser && \
    useradd --create-home --uid 1001 --gid 1001 appuser

# Install system dependencies for firewalld integration
# Note: python3-firewall is the D-Bus client library for firewalld
RUN apt-get update && apt-get install -y \
    curl \
    python3-firewall \
    python3-dbus \
    dbus \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install dependencies system-wide
COPY src/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY src/ .

# Create and change ownership of the data directory to the appuser
RUN mkdir -p /data && chown appuser:appuser /data

# Switch to the non-root user for running the application
USER appuser

# Expose the port the app runs on
EXPOSE 8000

# Define the command to run the application
# Uvicorn is run with --forwarded-allow-ips="*" to trust the X-Forwarded-For
# header from any proxy within the Docker network. This is safe because
# only Caddy is on the same network and can reach this container.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--forwarded-allow-ips", "*"]