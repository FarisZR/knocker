# Caddy Knocker - Design Decisions

This document outlines the key architectural and design decisions made during the development of the Caddy Knocker service.

### 1. Technology Stack

*   **Language**: Python 3.11
    *   **Reasoning**: Python was chosen for its rapid development capabilities, extensive libraries, and strong community support. It is more than capable of handling the performance requirements of this service.

*   **Web Framework**: FastAPI
    *   **Reasoning**: FastAPI is a modern, high-performance web framework that includes automatic data validation (via Pydantic) and API documentation generation. Its use of dependency injection was critical for creating a highly testable and maintainable application.

*   **Containerization**: Docker & Docker Compose
    *   **Reasoning**: The entire project is designed to be Docker-native. This simplifies deployment, ensures consistency across environments, and allows for seamless integration with Caddy in a containerized setup.

### 2. Development Methodology

*   **Test-Driven Development (TDD)**
    *   **Reasoning**: We adopted a strict TDD workflow using `pytest`. This means tests were written *before* the application code for every feature. This approach ensures high code quality, reduces bugs, and provides a safety net for future refactoring. Every piece of logic is covered by a verifiable test.

### 3. Caddy Integration

*   **Method**: `forward_auth` Directive
    *   **Reasoning**: We chose to use Caddy's built-in `forward_auth` directive instead of its API for integration. This creates a clean, decoupled architecture. The `knocker` service does not need access to or knowledge of Caddy's configuration. It has a single responsibility: to answer "yes" or "no" when Caddy asks for an authorization check. This is more secure, efficient, and aligns with standard Caddy practices.

### 4. Security

*   **Trusted Proxies**:
    *   **Reasoning**: Blindly trusting the `X-Forwarded-For` header is a major security vulnerability. The `trusted_proxies` mechanism was implemented to prevent IP spoofing. The service will only honor this header if the request originates from a trusted IP (i.e., the Caddy container on the same Docker network). This is a non-negotiable security feature for any proxy-facing application.

*   **Principle of Least Privilege**:
    *   **Reasoning**: The `allow_remote_whitelist` permission for API keys enforces the principle of least privilege. By default, keys can only whitelist their own IP address. The ability to whitelist arbitrary IPs is an elevated permission that must be granted explicitly, reducing the risk of misuse.

### 5. Networking

*   **IPv6 as a First-Class Citizen**:
    *   **Reasoning**: The modern internet is dual-stack. The service was designed from the ground up to handle IPv4 and IPv6 addresses and CIDR ranges interchangeably. The core logic uses Python's `ipaddress` library, and the Docker Compose file creates a dual-stack network to ensure future compatibility.

### 6. Configuration and State

*   **Configuration**: YAML file (`knocker.yaml`)
    *   **Reasoning**: YAML was chosen for its human-readability and ability to represent hierarchical data cleanly, making it ideal for managing API keys and server settings.

*   **State Management**: JSON file (`whitelist.json`)
    *   **Reasoning**: For a self-contained, single-node service typical of a homelab, a simple JSON file is a robust and sufficient solution for storing the whitelist. It requires no external dependencies (like Redis or a database), simplifying deployment. The service is designed to be stateless, with all state managed in this file, which is persisted via a Docker volume.