"""
Firewalld integration for dynamic firewall rule management.

This module provides integration with firewalld to create timed firewall rules
that automatically expire based on TTL values from knock requests.
"""
import logging
import time
import uuid
import ipaddress
from typing import Dict, Any, Optional, List
import threading

# Thread lock for firewalld operations
_firewalld_lock = threading.Lock()

# Initialize D-Bus and firewalld imports, handle graceful degradation
try:
    import dbus
    HAS_DBUS = True
except ImportError:
    HAS_DBUS = False
    logging.warning("D-Bus not available. Firewalld integration will be disabled.")

# Import core functions for IP validation and always-allowed checks
from core import is_valid_ip_or_cidr, is_ip_whitelisted


class FirewalldError(Exception):
    """Exception raised for firewalld-related errors."""
    pass


class FirewalldManager:
    """
    Manages firewalld integration for dynamic rule creation and expiry.
    
    This class handles:
    - Creation and management of the KNOCKER firewalld zone
    - Adding timed rules with automatic expiry
    - Cleanup of expired rules
    - Startup synchronization with existing rules
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the FirewalldManager.
        
        Args:
            config: Application configuration dictionary
            
        Raises:
            FirewalldError: If firewalld is enabled but D-Bus/firewalld is unavailable
        """
        self.config = config
        self.firewalld_config = config.get("firewalld", {})
        self.enabled = self.firewalld_config.get("enabled", False)
        
        # Initialize attributes
        self.zone_name = self.firewalld_config.get("zone_name", "KNOCKER")
        self.monitored_ports = self.firewalld_config.get("monitored_ports", [])
        self.priority = self.firewalld_config.get("priority", 100)
        self.active_rules: Dict[str, Dict[str, Any]] = {}
        
        # Skip D-Bus initialization if disabled
        if not self.enabled:
            logging.info("Firewalld integration is disabled")
            return
            
        if not HAS_DBUS:
            raise FirewalldError("Firewalld integration enabled but D-Bus is not available")
            
        try:
            # Initialize D-Bus connection
            self.bus = dbus.SystemBus()
            self.firewalld = self.bus.get_object("org.fedoraproject.FirewallD1",
                                               "/org/fedoraproject/FirewallD1")
            
            # Test connection by getting firewalld state
            state = self.firewalld.state()
            logging.info(f"Connected to firewalld, state: {state}")
            
            # Ensure our zone exists
            self.ensure_zone_exists()
            
        except Exception as e:
            raise FirewalldError(f"Failed to connect to firewalld: {e}")
    
    def ensure_zone_exists(self) -> None:
        """
        Ensure the KNOCKER zone exists with proper configuration.
        
        Creates the zone if it doesn't exist and configures it with:
        - High priority to override default rules
        - Deny-all policy for monitored ports
        - Allow rules for always-allowed IPs
        """
        if not self.enabled:
            return
            
        with _firewalld_lock:
            try:
                # Check if zone exists
                zones = self.firewalld.getZones()
                if self.zone_name not in zones:
                    logging.info(f"Creating firewalld zone: {self.zone_name}")
                    
                    # Create zone with settings
                    zone_settings = {
                        "version": "1.0",
                        "short": "Knocker",
                        "description": "Dynamic firewall rules managed by Knocker",
                        "target": "default",
                        "services": [],
                        "ports": [],
                        "icmp_blocks": [],
                        "masquerade": False,
                        "forward_ports": [],
                        "interfaces": [],
                        "sources": [],
                        "rules": [],
                        "protocols": [],
                        "source_ports": []
                    }
                    
                    self.firewalld.addZone(self.zone_name, zone_settings)
                    
                    # Set zone priority if supported
                    try:
                        self.firewalld.setZonePriority(self.zone_name, self.priority)
                    except Exception as e:
                        logging.warning(f"Could not set zone priority: {e}")
                    
                    # Add deny rules for monitored ports
                    self._setup_default_deny_rules()
                    
                    # Add allow rules for always-allowed IPs
                    self._setup_always_allowed_rules()
                    
                else:
                    logging.info(f"Firewalld zone {self.zone_name} already exists")
                    
            except Exception as e:
                raise FirewalldError(f"Failed to ensure zone exists: {e}")
    
    def _setup_default_deny_rules(self) -> None:
        """Set up default deny rules for monitored ports."""
        for port in self.monitored_ports:
            try:
                # Create rich rule to deny access to this port by default
                rich_rule = f'rule port port="{port}" protocol="tcp" reject'
                self.firewalld.addRichRule(self.zone_name, rich_rule, 0)  # 0 = permanent
                logging.info(f"Added default deny rule for port {port}")
            except Exception as e:
                logging.warning(f"Failed to add deny rule for port {port}: {e}")
    
    def _setup_always_allowed_rules(self) -> None:
        """Set up allow rules for always-allowed IPs."""
        always_allowed_ips = self.config.get("security", {}).get("always_allowed_ips", [])
        
        for ip_or_cidr in always_allowed_ips:
            if not is_valid_ip_or_cidr(ip_or_cidr):
                logging.warning(f"Invalid always-allowed IP/CIDR: {ip_or_cidr}")
                continue
                
            try:
                # Determine address family
                network = ipaddress.ip_network(ip_or_cidr, strict=False)
                family = "ipv4" if network.version == 4 else "ipv6"
                
                # Create rich rule to allow always-allowed IPs to monitored ports
                for port in self.monitored_ports:
                    rich_rule = (f'rule family="{family}" source address="{ip_or_cidr}" '
                               f'port port="{port}" protocol="tcp" accept')
                    self.firewalld.addRichRule(self.zone_name, rich_rule, 0)  # 0 = permanent
                    
                logging.info(f"Added always-allowed rule for {ip_or_cidr}")
            except Exception as e:
                logging.warning(f"Failed to add always-allowed rule for {ip_or_cidr}: {e}")
    
    def add_timed_rule(self, ip_or_cidr: str, ttl: int) -> Optional[str]:
        """
        Add a timed firewall rule that expires after TTL seconds.
        
        Args:
            ip_or_cidr: IP address or CIDR range to allow
            ttl: Time to live in seconds
            
        Returns:
            Rule ID if rule was created, None if not needed or failed
            
        Raises:
            FirewalldError: If rule creation fails
        """
        if not self.enabled:
            return None
            
        # Check if IP is always allowed (no need for firewalld rule)
        dummy_whitelist = {}  # We're only checking always_allowed_ips
        if is_ip_whitelisted(ip_or_cidr.split('/')[0], dummy_whitelist, self.config):
            # This IP is in always_allowed_ips, no need for firewalld rule
            return None
            
        if not is_valid_ip_or_cidr(ip_or_cidr):
            raise FirewalldError(f"Invalid IP or CIDR: {ip_or_cidr}")
        
        with _firewalld_lock:
            try:
                # Generate unique rule ID
                rule_id = str(uuid.uuid4())
                
                # Determine address family
                network = ipaddress.ip_network(ip_or_cidr, strict=False)
                family = "ipv4" if network.version == 4 else "ipv6"
                
                # Create rich rules for each monitored port
                rich_rules = []
                for port in self.monitored_ports:
                    rich_rule = (f'rule family="{family}" source address="{ip_or_cidr}" '
                               f'port port="{port}" protocol="tcp" accept')
                    rich_rules.append(rich_rule)
                    
                    # Add rule to firewalld (runtime only, not permanent)
                    self.firewalld.addRichRule(self.zone_name, rich_rule, 1)  # 1 = runtime only
                
                # Track the rule
                expires_at = int(time.time()) + ttl
                self.active_rules[rule_id] = {
                    "ip": ip_or_cidr,
                    "expires_at": expires_at,
                    "rich_rules": rich_rules,
                    "created_at": int(time.time())
                }
                
                logging.info(f"Added timed firewalld rule for {ip_or_cidr} (expires in {ttl}s)")
                return rule_id
                
            except Exception as e:
                raise FirewalldError(f"Failed to add timed rule for {ip_or_cidr}: {e}")
    
    def cleanup_expired_rules(self) -> None:
        """Remove expired firewall rules from firewalld and internal tracking."""
        if not self.enabled:
            return
            
        current_time = int(time.time())
        expired_rules = []
        
        # Find expired rules
        for rule_id, rule_info in self.active_rules.items():
            if rule_info["expires_at"] <= current_time:
                expired_rules.append(rule_id)
        
        # Remove expired rules
        with _firewalld_lock:
            for rule_id in expired_rules:
                try:
                    rule_info = self.active_rules[rule_id]
                    
                    # Remove each rich rule from firewalld
                    for rich_rule in rule_info["rich_rules"]:
                        try:
                            self.firewalld.removeRichRule(self.zone_name, rich_rule)
                        except Exception as e:
                            logging.warning(f"Failed to remove rich rule: {e}")
                    
                    # Remove from tracking
                    del self.active_rules[rule_id]
                    
                    logging.info(f"Removed expired firewalld rule for {rule_info['ip']}")
                    
                except Exception as e:
                    logging.error(f"Failed to cleanup expired rule {rule_id}: {e}")
    
    def synchronize_on_startup(self) -> None:
        """
        Synchronize internal state with existing firewalld rules on startup.
        
        This checks for existing rules in the KNOCKER zone and attempts to
        match them with internal tracking. Rules that can't be matched or
        have expired are cleaned up.
        """
        if not self.enabled:
            return
            
        try:
            with _firewalld_lock:
                # Get existing rich rules from our zone
                existing_rules = self.firewalld.getRichRules(self.zone_name)
                
                logging.info(f"Found {len(existing_rules)} existing rules in {self.zone_name} zone")
                
                # For now, we'll clean up all dynamic rules on startup since we can't
                # reliably determine their expiry times from firewalld alone
                # In a production system, you might want to store rule metadata externally
                
                for rule in existing_rules:
                    # Skip permanent rules (always-allowed IPs and default denies)
                    if self._is_dynamic_rule(rule):
                        try:
                            self.firewalld.removeRichRule(self.zone_name, rule)
                            logging.info(f"Cleaned up orphaned rule on startup: {rule}")
                        except Exception as e:
                            logging.warning(f"Failed to clean up rule {rule}: {e}")
                
                # Clear internal tracking (fresh start)
                self.active_rules.clear()
                
        except Exception as e:
            logging.error(f"Failed to synchronize on startup: {e}")
    
    def _is_dynamic_rule(self, rich_rule: str) -> bool:
        """
        Determine if a rich rule is a dynamic (timed) rule vs permanent rule.
        
        Dynamic rules are those created by add_timed_rule(), as opposed to
        permanent rules for always-allowed IPs or default denies.
        """
        # This is a heuristic - dynamic rules should have:
        # 1. source address (not a deny-all rule)
        # 2. accept action (not reject/deny)
        # 3. port specification (for monitored ports)
        
        return ("source address=" in rich_rule and 
                "accept" in rich_rule and 
                "port=" in rich_rule)
    
    def get_active_rules_count(self) -> int:
        """Get the number of currently active timed rules."""
        return len(self.active_rules)
    
    def get_rule_info(self, rule_id: str) -> Optional[Dict[str, Any]]:
        """Get information about a specific rule."""
        return self.active_rules.get(rule_id)


# Singleton instance for application use
_firewalld_manager: Optional[FirewalldManager] = None


def initialize_firewalld(config: Dict[str, Any]) -> None:
    """Initialize the global FirewalldManager instance."""
    global _firewalld_manager
    _firewalld_manager = FirewalldManager(config)


def get_firewalld_manager() -> Optional[FirewalldManager]:
    """Get the global FirewalldManager instance."""
    return _firewalld_manager


def add_firewalld_rule(ip_or_cidr: str, ttl: int) -> Optional[str]:
    """
    Convenience function to add a firewalld rule via the global manager.
    
    Args:
        ip_or_cidr: IP address or CIDR range to allow
        ttl: Time to live in seconds
        
    Returns:
        Rule ID if rule was created, None otherwise
    """
    manager = get_firewalld_manager()
    if manager:
        return manager.add_timed_rule(ip_or_cidr, ttl)
    return None


def cleanup_firewalld_rules() -> None:
    """Convenience function to cleanup expired firewalld rules."""
    manager = get_firewalld_manager()
    if manager:
        manager.cleanup_expired_rules()