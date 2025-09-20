"""
Deprecated compatibility module.

This file previously acted as a compatibility shim. It now re-exports the
public API from the renamed compatibility module `firewall_compat` using an
absolute import to avoid executing package-relative imports when this file
is loaded as a top-level module (which previously caused "attempted relative
import with no known parent package" errors during import probing).

Avoid keeping a top-level module named `firewall` in the project long-term:
it shadows the system `firewall` package and prevents importing
`firewall.client`. This shim exists only for temporary backwards
compatibility and should be removed once callers migrate to `src.fw_integration`.
"""

# Use absolute import to avoid relative import execution when this file is
# loaded as a top-level module during import probes.
try:
    # This will import the sibling module file /app/src/firewall_compat.py
    from firewall_compat import (  # type: ignore
        initialize_firewall,
        add_ip_to_firewall,
        remove_ip_from_firewall,
        cleanup_expired_firewall_rules,
        is_firewalld_enabled,
        get_firewall_status,
        firewall_preflight,
    )
except Exception:
    # Fail softly: do not perform package-relative operations here that could
    # raise during import probing. Provide minimal fallbacks so importing
    # 'firewall' doesn't crash the runtime import machinery.
    def initialize_firewall(*args, **kwargs):
        return False
    def add_ip_to_firewall(*args, **kwargs):
        return False
    def remove_ip_from_firewall(*args, **kwargs):
        return False
    def cleanup_expired_firewall_rules(*args, **kwargs):
        return False
    def is_firewalld_enabled(*args, **kwargs):
        return False
    def get_firewall_status(*args, **kwargs):
        return {"available": False, "reason": "SHIM_IMPORT_FAILED", "client_path": ""}
    def firewall_preflight(*args, **kwargs):
        return