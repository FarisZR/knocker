"""
Firewalld integration module for knocker.

This module provides functionality to create timed firewall rules that sync with
the IP whitelist. It uses firewalld's D-Bus interface via python3-firewall bindings.

NOTE:
  This file was split out from the original src/firewall.py to avoid
  shadowing the upstream 'firewall' package (firewall.client). The original
  src/firewall.py now serves only as a compatibility shim and should be
  removed once all imports are updated to use 'fw_integration'.
"""

import logging
import time
import ipaddress
from typing import Dict, List, Optional, Set, Any

# Global flag to track if firewalld is available
_firewalld_available = None
_fw = None

def _check_firewalld_availability() -> bool:
    """
    Enhanced availability check that:
    - Detects and mitigates local module name shadowing.
    - Attempts real firewall.client import with path logging.
    - Falls back to lightweight DBus client.
    - Categorizes failure reasons for diagnostics.
    """
    global _firewalld_available, _fw, _firewalld_reason, _firewalld_client_path

    # If we already determined availability (cached), return it.
    if _firewalld_available is not None:
        return _firewalld_available

    try:
        import importlib
        import importlib.util
        import sys
        import os
    except Exception as e:
        # If importing these runtime modules fails (tests may patch __import__),
        # fail gracefully and report an import-module-level failure.
        _firewalld_available = False
        _firewalld_reason = "IMPORT_MODULES_FAILED"
        _firewalld_client_path = ""
        logging.debug(f"Failed to import runtime modules for firewall check: {e}")
        return False

    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    _firewalld_reason = "UNKNOWN"
    _firewalld_client_path = ""

    try:
        # Reset client each fresh attempt
        _fw = None

        # --- Step 1: Detect shadowing before import ---
        # If 'firewall' is already imported and points to our project file (this file),
        # it will block 'firewall.client'. Remove it temporarily.
        existing = sys.modules.get('firewall')
        if existing:
            existing_file = getattr(existing, '__file__', '') or ''
            if existing_file.startswith(project_root):
                # Shadow detected
                _firewalld_reason = "SHADOWED_PREIMPORT"
                del sys.modules['firewall']

        # Build a reduced sys.path excluding project root & CWD for clean import attempt
        original_sys_path = sys.path[:]
        try:
            reduced = []
            cwd_abs = os.path.abspath(os.getcwd())
            for p in original_sys_path:
                if not p:
                    continue
                ap = os.path.abspath(p)
                if ap == project_root or ap == cwd_abs:
                    continue
                reduced.append(p)
            sys.path = reduced

            # Probe spec (without executing import)
            spec = importlib.util.find_spec('firewall.client')
        finally:
            sys.path = original_sys_path

        if spec is None:
            # Try deletion + retry once more in case shadow persisted
            existing2 = sys.modules.get('firewall')
            if existing2:
                try:
                    del sys.modules['firewall']
                except Exception:
                    pass
            # Second probe (no path mutation now – rely on current sys.path)
            spec = importlib.util.find_spec('firewall.client')

        if spec is not None:
            try:
                mod = importlib.import_module('firewall.client')
                client_cls = getattr(mod, 'FirewallClient', None)
                if client_cls is None:
                    raise ImportError("firewall.client lacks FirewallClient attribute")
                _fw = client_cls()
                _firewalld_client_path = getattr(mod, '__file__', '') or ''
            except Exception as imp_err:
                # Mark as shadowed if module file still points inside project
                shadow = False
                imp_mod = sys.modules.get('firewall')
                if imp_mod:
                    imp_file = getattr(imp_mod, '__file__', '') or ''
                    if imp_file.startswith(project_root):
                        shadow = True
                _firewalld_reason = "SHADOWED_IMPORT" if shadow else "IMPORT_FAILURE"
                logging.debug(f"Primary firewalld client import failed: {imp_err}")
                _fw = None
        else:
            if _firewalld_reason.startswith("SHADOWED"):
                # Spec absent after shadow removal attempts
                _firewalld_reason = "SHADOWED_NO_SPEC"
            else:
                _firewalld_reason = "NO_SPEC"

        # --- Step 2: DBus lightweight fallback ---
        if _fw is None:
            try:
                import dbus
                from dbus import Interface, exceptions as dbus_exc  # noqa: F401

                class _DBusFirewallClient:
                    def __init__(self):
                        self.bus = dbus.SystemBus()
                        self.obj = self.bus.get_object(
                            'org.fedoraproject.FirewallD1',
                            '/org/fedoraproject/FirewallD1'
                        )
                        self.iface = Interface(
                            self.obj,
                            dbus_interface='org.fedoraproject.FirewallD1'
                        )

                    def getDefaultZone(self):
                        return str(self.iface.getDefaultZone())

                    def getZones(self):
                        zones = self.iface.getZones()
                        return [str(z) for z in zones]

                    def addRichRule(self, zone, rule):
                        return self.iface.addRichRule(zone, rule)

                    def removeRichRule(self, zone, rule):
                        return self.iface.removeRichRule(zone, rule)

                    def getRichRules(self, zone):
                        rules = self.iface.getRichRules(zone)
                        return [str(r) for r in rules]

                    def config(self):
                        raise NotImplementedError("config() not implemented in DBus fallback")

                _fw = _DBusFirewallClient()
                _firewalld_client_path = "DBUS_FALLBACK"
            except Exception as dbus_err:
                # Attempt to categorize dbus error
                reason = "DBUS_FALLBACK_INIT_FAILED"
                try:
                    import dbus  # type: ignore
                    if isinstance(dbus_err, dbus.exceptions.DBusException):
                        name = dbus_err.get_dbus_name()
                        if name == 'org.freedesktop.DBus.Error.AccessDenied':
                            reason = "DBUS_PERMISSION"
                        elif name == 'org.freedesktop.DBus.Error.ServiceUnknown':
                            reason = "FIREWALLD_NOT_RUNNING"
                except Exception:
                    pass
                _firewalld_reason = reason
                logging.debug(f"DBus fallback initialization failed: {dbus_err}")
                _fw = None

        if _fw is None:
            if _firewalld_reason in ("UNKNOWN", "SHADOWED_PREIMPORT"):
                # If still unknown, set generic reason
                _firewalld_reason = _firewalld_reason or "UNAVAILABLE"
            _firewalld_available = False
            logging.warning(f"Firewalld unavailable reason={_firewalld_reason}")
            return False

        # Smoke test connection
        try:
            _fw.getDefaultZone()
        except Exception as probe_err:
            # Determine run-state issue
            probe_reason = "FIREWALLD_NOT_RUNNING"
            pr_text = str(probe_err)
            if "AccessDenied" in pr_text:
                probe_reason = "DBUS_PERMISSION"
            _firewalld_reason = probe_reason
            _firewalld_available = False
            logging.warning(f"Firewalld probe failed reason={probe_reason} detail={probe_err}")
            return False

        _firewalld_available = True
        _firewalld_reason = "SUCCESS"
        logging.info(f"Firewalld available client_path={_firewalld_client_path}")
        return True

    except Exception as e:
        _firewalld_available = False
        if _firewalld_reason == "UNKNOWN":
            _firewalld_reason = "EXCEPTION"
        logging.warning(f"Firewalld availability check exception reason={_firewalld_reason} detail={e}")
        return False


def get_firewall_status() -> Dict[str, Any]:
    """
    Returns structured status about firewalld integration.
    Keys: available(bool), reason(str), client_path(str)
    """
    # Trigger availability check if not yet performed
    _check_firewalld_availability()
    return {
        "available": bool(_firewalld_available),
        "reason": _firewalld_reason,
        "client_path": _firewalld_client_path
    }


def firewall_preflight(settings: Dict[str, Any]):
    """
    Run a one-time preflight and log a concise structured summary.
    Safe to call multiple times (uses cached status).
    """
    if not is_firewalld_enabled(settings):
        logging.info("FIREWALL_PRECHECK firewall_disabled=true")
        return
    import os
    status = get_firewall_status()
    logging.info(
        "FIREWALL_PRECHECK available=%s reason=%s client_path=%s dbus_addr=%s",
        status["available"],
        status["reason"],
        status["client_path"],
        os.getenv("DBUS_SYSTEM_BUS_ADDRESS", "(default)")
    )

def is_firewalld_enabled(settings: Dict[str, Any]) -> bool:
    """Check if firewall integration is enabled in configuration."""
    firewall_config = settings.get("firewall", {})
    return firewall_config.get("enabled", False)

def get_monitored_ports(settings: Dict[str, Any]) -> List[str]:
    """Get the list of monitored ports from configuration."""
    firewall_config = settings.get("firewall", {})
    return firewall_config.get("monitored_ports", [])

def get_knocker_zone_name() -> str:
    """Get the name of the KNOCKER firewalld zone."""
    return "knocker"

def initialize_firewall(settings: Dict[str, Any]) -> bool:
    """
    Initialize firewall integration.
    
    Creates the KNOCKER zone if it doesn't exist and sets up base rules.
    Returns True if successful, False otherwise.
    """
    if not is_firewalld_enabled(settings):
        logging.info("Firewall integration is disabled")
        return False
        
    if not _check_firewalld_availability():
        logging.error("Cannot initialize firewall: firewalld is not available")
        return False
    
    try:
        zone_name = get_knocker_zone_name()
        monitored_ports = get_monitored_ports(settings)
        
        # Create KNOCKER zone if it doesn't exist
        if not _zone_exists(zone_name):
            _create_knocker_zone(zone_name, monitored_ports, settings)
            logging.info(f"Created firewall zone '{zone_name}'")
        else:
            logging.info(f"Firewall zone '{zone_name}' already exists")
            
        # Sync existing rules with whitelist
        _sync_firewall_rules_with_whitelist(settings)
        
        return True
        
    except Exception as e:
        logging.error(f"Failed to initialize firewall: {e}")
        return False

def add_ip_to_firewall(ip_or_cidr: str, expiry_time: int, settings: Dict[str, Any]) -> bool:
    """
    Add an IP or CIDR to the firewall allow rules.
    
    Returns True if successful, False otherwise.
    """
    if not is_firewalld_enabled(settings) or not _check_firewalld_availability():
        return False
        
    try:
        zone_name = get_knocker_zone_name()
        monitored_ports = get_monitored_ports(settings)
        
        for port in monitored_ports:
            _add_rich_rule_for_ip_port(zone_name, ip_or_cidr, port, expiry_time)
            
        logging.info(f"Added firewall rules for {ip_or_cidr} until {expiry_time}")
        return True
        
    except Exception as e:
        logging.error(f"Failed to add firewall rules for {ip_or_cidr}: {e}")
        return False

def remove_ip_from_firewall(ip_or_cidr: str, settings: Dict[str, Any]) -> bool:
    """
    Remove an IP or CIDR from the firewall allow rules.
    
    Returns True if successful, False otherwise.
    """
    if not is_firewalld_enabled(settings) or not _check_firewalld_availability():
        return False
        
    try:
        zone_name = get_knocker_zone_name()
        monitored_ports = get_monitored_ports(settings)
        
        for port in monitored_ports:
            _remove_rich_rule_for_ip_port(zone_name, ip_or_cidr, port)
            
        logging.info(f"Removed firewall rules for {ip_or_cidr}")
        return True
        
    except Exception as e:
        logging.error(f"Failed to remove firewall rules for {ip_or_cidr}: {e}")
        return False

def cleanup_expired_firewall_rules(settings: Dict[str, Any]) -> bool:
    """
    Remove expired firewall rules and sync with current whitelist.
    
    Returns True if successful, False otherwise.
    """
    if not is_firewalld_enabled(settings) or not _check_firewalld_availability():
        return False
        
    try:
        _sync_firewall_rules_with_whitelist(settings)
        return True
    except Exception as e:
        logging.error(f"Failed to cleanup expired firewall rules: {e}")
        return False

# Private helper functions

def _zone_exists(zone_name: str) -> bool:
    """Check if a firewalld zone exists."""
    try:
        zones = _fw.getZones()
        return zone_name in zones
    except Exception:
        return False

def _create_knocker_zone(zone_name: str, monitored_ports: List[str], settings: Dict[str, Any]):
    """Create the KNOCKER firewalld zone with base configuration."""
    try:
        # Create the zone with basic configuration
        zone_config = _fw.config().addZone2(zone_name, {
            'version': '1.0',
            'short': 'Knocker Dynamic Access',
            'description': 'Zone for knocker dynamic IP access rules',
            'target': 'DROP',  # Default deny
            'interfaces': [],
            'sources': [],
            'services': [],
            'ports': [],
            'protocols': [],
            'masquerade': False,
            'forward_ports': [],
            'source_ports': [],
            'icmp_blocks': [],
            'rich_rules': []
        })
        
        # Set highest priority (lower number = higher priority)
        zone_config.setPriority(-1)
        
    except Exception as e:
        # Fallback: try simpler zone creation method
        logging.warning(f"Advanced zone creation failed, trying simple method: {e}")
        try:
            _fw.config().addZone(zone_name)
            # Get the zone and configure it
            zone_obj = _fw.config().getZoneByName(zone_name)
            zone_obj.setTarget('DROP')
            zone_obj.setPriority(-1)
        except Exception as e2:
            logging.error(f"Failed to create zone with fallback method: {e2}")
            raise
    
    # Add always allowed IPs to the zone
    always_allowed_ips = settings.get("security", {}).get("always_allowed_ips", [])
    for ip in always_allowed_ips:
        for port in monitored_ports:
            try:
                _add_rich_rule_for_ip_port(zone_name, ip, port, None)  # No expiry for always allowed
            except Exception as e:
                logging.warning(f"Failed to add always allowed rule for {ip}:{port}: {e}")

def _add_rich_rule_for_ip_port(zone_name: str, ip_or_cidr: str, port: str, expiry_time: Optional[int]):
    """Add a rich rule to allow IP/CIDR access to a specific port."""
    # Create rich rule syntax: rule family="ipv4" source address="x.x.x.x" port port="80" protocol="tcp" accept
    family = "ipv6" if ":" in ip_or_cidr else "ipv4"
    
    # Parse port specification (e.g., "80/tcp", "443", etc.)
    if "/" in port:
        port_num, protocol = port.split("/", 1)
    else:
        port_num, protocol = port, "tcp"
    
    rich_rule = f'rule family="{family}" source address="{ip_or_cidr}" port port="{port_num}" protocol="{protocol}" accept'
    
    # Add rule to runtime (immediate effect)
    _fw.addRichRule(zone_name, rich_rule)
    
    logging.debug(f"Added rich rule to zone {zone_name}: {rich_rule}")

def _remove_rich_rule_for_ip_port(zone_name: str, ip_or_cidr: str, port: str):
    """Remove a rich rule for IP/CIDR access to a specific port."""
    family = "ipv6" if ":" in ip_or_cidr else "ipv4"
    
    if "/" in port:
        port_num, protocol = port.split("/", 1)
    else:
        port_num, protocol = port, "tcp"
    
    rich_rule = f'rule family="{family}" source address="{ip_or_cidr}" port port="{port_num}" protocol="{protocol}" accept'
    
    try:
        # Remove rule from runtime
        _fw.removeRichRule(zone_name, rich_rule)
        logging.debug(f"Removed rich rule from zone {zone_name}: {rich_rule}")
    except Exception as e:
        # Rule might not exist, which is OK
        logging.debug(f"Could not remove rich rule (may not exist): {e}")

def _sync_firewall_rules_with_whitelist(settings: Dict[str, Any]):
    """Sync firewall rules with the current whitelist state."""
    # Import here to avoid circular imports
    try:
        from . import core
    except ImportError:
        import core
    
    zone_name = get_knocker_zone_name()
    monitored_ports = get_monitored_ports(settings)
    
    # Get current whitelist
    whitelist = core.load_whitelist(settings)
    now = int(time.time())
    
    # Get currently active IPs from whitelist
    active_ips = set()
    for ip, expiry in whitelist.items():
        if expiry > now:
            active_ips.add(ip)
    
    # Add always allowed IPs
    always_allowed_ips = settings.get("security", {}).get("always_allowed_ips", [])
    for ip in always_allowed_ips:
        active_ips.add(ip)
    
    # Get existing firewall rules
    existing_rules = _get_existing_firewall_rules(zone_name, monitored_ports)
    
    # Add missing rules
    for ip in active_ips:
        if ip not in existing_rules:
            for port in monitored_ports:
                _add_rich_rule_for_ip_port(zone_name, ip, port, None)
    
    # Remove orphaned rules (IPs that are in firewall but not in active whitelist)
    for ip in existing_rules:
        if ip not in active_ips:
            for port in monitored_ports:
                _remove_rich_rule_for_ip_port(zone_name, ip, port)

def _get_existing_firewall_rules(zone_name: str, monitored_ports: List[str]) -> Set[str]:
    """Get the set of IP addresses that currently have firewall rules."""
    try:
        rich_rules = _fw.getRichRules(zone_name)
        active_ips = set()
        
        for rule in rich_rules:
            # Parse rich rule to extract IP address
            # Example: rule family="ipv4" source address="192.168.1.1" port port="80" protocol="tcp" accept
            if 'source address=' in rule and ' accept' in rule:
                # Extract IP address from rule
                start = rule.find('source address="') + len('source address="')
                end = rule.find('"', start)
                if start > 0 and end > start:
                    ip = rule[start:end]
                    active_ips.add(ip)
        
        return active_ips
        
    except Exception as e:
        logging.error(f"Failed to get existing firewall rules: {e}")
        return set()