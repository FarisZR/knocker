# Project Coding Rules (Non-Obvious Only)

- **Configuration Loading**: All configuration is loaded from a single YAML file via the `get_settings()` function in [`src/main.py`](src/main.py:11). This function is cached with `@lru_cache`, so the config file is only read once.
- **IP Whitelisting Logic**: The core logic for adding, checking, and cleaning up whitelisted IPs is in [`src/core.py`](src/core.py:1). Do not implement this logic elsewhere.
- **Security Dependency**: The `get_client_ip` function in [`src/main.py`](src/main.py:32) relies on the `X-Forwarded-For` header. This is only secure if the `trusted_proxies` in `knocker.yaml` is correctly configured.
- **State Management**: The application's state (the IP whitelist) is managed in a single JSON file. All functions in [`src/core.py`](src/core.py:1) that modify the whitelist (`add_ip_to_whitelist`, `cleanup_expired_ips`) handle file I/O (load and save).