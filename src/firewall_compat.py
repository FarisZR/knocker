"""
Compatibility shim (renamed) for firewalld integration.

This file was created from the original src/firewall.py shim and renamed to
src/firewall_compat.py to avoid accidental top-level module shadowing of the
upstream 'firewall' package (which provides firewall.client).

Exports the same public API as before so external callers that import this
compat shim can continue to work for now. Internal code should import
src.fw_integration directly.
"""
from .fw_integration import (  # type: ignore F401
    initialize_firewall,
    add_ip_to_firewall,
    remove_ip_from_firewall,
    cleanup_expired_firewall_rules,
    is_firewalld_enabled,
    get_firewall_status,
    firewall_preflight,
)