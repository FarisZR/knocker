"""
Firewalld integration module for knocker.

This module provides functionality to create timed firewall rules that sync with
the IP whitelist. It uses firewalld's D-Bus interface via python3-firewall bindings.
"""

import logging
import time
import ipaddress
from typing import Dict, List, Optional, Set, Any

# Global flag to track if firewalld is available
_firewalld_available = None
_fw = None

def _check_firewalld_availability() -> bool:
    """Check if firewalld is available and can be used."""
    global _firewalld_available, _fw
    
    if _firewalld_available is not None:
        return _firewalld_available
    
    try:
        # Try to import firewall.client from python3-firewall package
        import firewall.client
        _fw = firewall.client.FirewallClient()
        _fw.getDefaultZone()  # Test connection
        _firewalld_available = True
        logging.info("Firewalld is available and accessible")
        return True
    except ImportError as e:
        _firewalld_available = False
        logging.warning(f"Firewalld python3-firewall package is not available: {e}")
        return False
    except Exception as e:
        _firewalld_available = False
        logging.warning(f"Firewalld is not available: {e}")
        return False

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
    # Create the zone
    _fw.config().addZone(zone_name, {
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
    _fw.config().getZoneByName(zone_name).setPriority(-1)
    
    # Add always allowed IPs to the zone
    always_allowed_ips = settings.get("security", {}).get("always_allowed_ips", [])
    for ip in always_allowed_ips:
        for port in monitored_ports:
            _add_rich_rule_for_ip_port(zone_name, ip, port, None)  # No expiry for always allowed

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
    from . import core  # Import here to avoid circular imports
    
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