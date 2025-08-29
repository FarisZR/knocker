# Use a specific, stable version of Python for reproducibility
FROM python:3.11.9-slim

# Set the working directory in the container
WORKDIR /app

# Create a non-root user to run the application for better security
# Using a fixed UID/GID is good practice for production environments
RUN groupadd --gid 1001 appuser && \
    useradd --create-home --uid 1001 --gid 1001 appuser

# Copy only the requirements file first to leverage Docker's layer caching
COPY --chown=appuser:appuser src/requirements.txt .

# Install dependencies as the non-root user
RUN pip install --no-cache-dir --user -r requirements.txt

# Switch to the non-root user
USER appuser

# Copy the rest of the application code
COPY --chown=appuser:appuser src/ .

# Expose the port the app runs on
EXPOSE 8000

# Define the command to run the application
# Uvicorn is run with --forwarded-allow-ips="*" to trust the X-Forwarded-For
# header from any proxy within the Docker network. This is safe because
# only Caddy is on the same network and can reach this container.
CMD ["/home/appuser/.local/bin/uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--forwarded-allow-ips", "*"]