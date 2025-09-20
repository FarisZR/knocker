# Use a specific, stable version of Python for reproducibility
FROM python:3.13-slim

# Set the working directory in the container
WORKDIR /app

# Install system dependencies including firewalld and dbus
# Note: firewalld requires root privileges to manage firewall rules
RUN apt-get update && apt-get install -y \
    curl \
    firewalld \
    dbus \
    systemctl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install dependencies system-wide
COPY src/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY src/ .

# Create the data directory for persistent storage
RUN mkdir -p /data

# Note: Container must run as root for firewalld integration
# When firewalld is enabled, the service requires root privileges to:
# - Create and manage firewalld zones
# - Add/remove rich rules with runtime modifications
# - Access D-Bus system bus for firewalld communication
# 
# Security considerations:
# - Use firewalld integration only in trusted environments
# - Ensure proper network isolation of the container
# - Consider using user namespaces if additional isolation is needed

# Expose the port the app runs on
EXPOSE 8000


# Define the command to run the application
# Uvicorn is run with --forwarded-allow-ips="*" to trust the X-Forwarded-For
# header from any proxy within the Docker network. This is safe because
# only Caddy is on the same network and can reach this container.
CMD ["/bin/bash", "-c", "service dbus start && firewalld --nofork -D & uvicorn main:app --host 0.0.0.0 --port 8000 --forwarded-allow-ips '*'"]