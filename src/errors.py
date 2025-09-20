"""
Custom exception types for atomic firewall + whitelist operations.
"""

from typing import Optional


class FirewallApplyError(Exception):
    """
    Raised when firewall rule application fails for a whitelist operation.
    No whitelist mutation must have occurred prior to this exception.
    """
    def __init__(self, ip_or_cidr: str, message: str = "Failed to apply firewall rules", detail: Optional[str] = None):
        self.ip_or_cidr = ip_or_cidr
        self.detail = detail
        full = f"{message} for {ip_or_cidr}"
        if detail:
            full = f"{full}: {detail}"
        super().__init__(full)


class WhitelistPersistError(Exception):
    """
    Raised when persisting the whitelist to disk fails after firewall rules
    have already been applied. A rollback (best-effort removal of firewall rules)
    should be attempted by the caller before raising this exception.
    """
    def __init__(self, ip_or_cidr: str, message: str = "Failed to persist whitelist", detail: Optional[str] = None):
        self.ip_or_cidr = ip_or_cidr
        self.detail = detail
        full = f"{message} for {ip_or_cidr}"
        if detail:
            full = f"{full}: {detail}"
        super().__init__(full)


__all__ = ["FirewallApplyError", "WhitelistPersistError"]