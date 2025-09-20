"""
Firewalld integration module for Knocker.

This module handles all firewalld operations including:
- Creating and managing the knocker firewall zone
- Adding/removing timed rules for IP whitelisting
- Startup rule recovery and synchronization
- Integration with the existing whitelist system
"""

import logging
import subprocess
import json
import time
from typing import Dict, Any, List, Tuple, Optional
from dataclasses import dataclass


@dataclass
class FirewalldRule:
    """Represents a firewalld rule for an IP/port combination."""
    ip_address: str
    port: int
    protocol: str
    expiry_time: int
    
    def __str__(self):
        return f"{self.ip_address}:{self.port}/{self.protocol} (expires: {self.expiry_time})"


class FirewalldIntegration:
    """Handles all firewalld operations for Knocker."""
    
    def __init__(self, settings: Dict[str, Any]):
        """Initialize firewalld integration with configuration settings."""
        self.settings = settings
        self.firewalld_config = settings.get("firewalld", {})
        self.enabled = self.firewalld_config.get("enabled", False)
        self.zone_name = self.firewalld_config.get("zone_name", "knocker")
        self.monitored_ports = self.firewalld_config.get("monitored_ports", [])
        self.monitored_ips = self.firewalld_config.get("monitored_ips", [])
        self.zone_priority = self.firewalld_config.get("zone_priority", 100)
        
        self.logger = logging.getLogger(__name__)
        
    def is_enabled(self) -> bool:
        """Check if firewalld integration is enabled."""
        return self.enabled
        
    def _run_firewall_cmd(self, args: List[str], check: bool = True) -> Tuple[bool, str, str]:
        """
        Run firewall-cmd with given arguments.
        
        Returns:
            Tuple of (success, stdout, stderr)
        """
        cmd = ["firewall-cmd"] + args
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                check=check
            )
            return True, result.stdout.strip(), result.stderr.strip()
        except subprocess.CalledProcessError as e:
            self.logger.error(f"firewall-cmd failed: {e.stderr}")
            return False, e.stdout.strip() if e.stdout else "", e.stderr.strip() if e.stderr else ""
        except subprocess.TimeoutExpired:
            self.logger.error("firewall-cmd command timed out")
            return False, "", "Command timed out"
        except Exception as e:
            self.logger.error(f"Unexpected error running firewall-cmd: {e}")
            return False, "", str(e)
            
    def is_firewalld_available(self) -> bool:
        """Check if firewalld is available and running."""
        success, stdout, stderr = self._run_firewall_cmd(["--state"], check=False)
        if success and "running" in stdout:
            return True
        
        self.logger.warning(f"Firewalld not available: {stderr}")
        return False
        
    def setup_knocker_zone(self) -> bool:
        """
        Create and configure the knocker firewalld zone.
        
        Returns:
            True if successful, False otherwise
        """
        if not self.is_enabled():
            return True
            
        if not self.is_firewalld_available():
            return False
            
        try:
            # Check if zone already exists
            success, _, _ = self._run_firewall_cmd([f"--zone={self.zone_name}", "--list-all"], check=False)
            if not success:
                # Create the zone
                success, stdout, stderr = self._run_firewall_cmd([
                    f"--new-zone={self.zone_name}", "--permanent"
                ])
                if not success:
                    self.logger.error(f"Failed to create zone {self.zone_name}: {stderr}")
                    return False
                    
                self.logger.info(f"Created firewalld zone: {self.zone_name}")
            
            # Set zone priority (higher number = higher priority)
            success, _, stderr = self._run_firewall_cmd([
                f"--zone={self.zone_name}", f"--set-priority={self.zone_priority}", "--permanent"
            ])
            if not success:
                self.logger.warning(f"Failed to set zone priority: {stderr}")
            
            # Set default target to DROP for security
            success, _, stderr = self._run_firewall_cmd([
                f"--zone={self.zone_name}", "--set-target=DROP", "--permanent"
            ])
            if not success:
                self.logger.error(f"Failed to set zone target to DROP: {stderr}")
                return False
            
            # Add monitored IP ranges to the zone
            for ip_range in self.monitored_ips:
                success, _, stderr = self._run_firewall_cmd([
                    f"--zone={self.zone_name}", f"--add-source={ip_range}", "--permanent"
                ])
                if not success:
                    self.logger.warning(f"Failed to add source {ip_range} to zone: {stderr}")
            
            # Apply drop rules for monitored ports by default
            for port_config in self.monitored_ports:
                port = port_config.get("port")
                protocol = port_config.get("protocol", "tcp")
                
                # Note: We don't add services/ports to the zone by default since target=DROP
                # Rules will be added dynamically for whitelisted IPs
                
            # Reload to apply permanent changes
            success, _, stderr = self._run_firewall_cmd(["--reload"])
            if not success:
                self.logger.error(f"Failed to reload firewall: {stderr}")
                return False
                
            self.logger.info(f"Knocker firewalld zone '{self.zone_name}' configured successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Exception during zone setup: {e}")
            return False
            
    def add_whitelist_rule(self, ip_address: str, expiry_time: int) -> bool:
        """
        Add firewalld rules to allow an IP access to monitored ports.
        
        Args:
            ip_address: IP address or CIDR to whitelist
            expiry_time: Unix timestamp when rule should expire
            
        Returns:
            True if all rules added successfully, False otherwise
        """
        if not self.is_enabled():
            return True
            
        if not self.is_firewalld_available():
            self.logger.error("Firewalld not available for adding whitelist rule")
            return False
            
        success_count = 0
        total_rules = len(self.monitored_ports)
        
        for port_config in self.monitored_ports:
            port = port_config.get("port")
            protocol = port_config.get("protocol", "tcp")
            
            # Add rich rule to allow this IP to access the port
            # Rich rules have higher precedence and can override zone target
            rich_rule = f'rule family="ipv4" source address="{ip_address}" port protocol="{protocol}" port="{port}" accept'
            
            success, stdout, stderr = self._run_firewall_cmd([
                f"--zone={self.zone_name}", f"--add-rich-rule={rich_rule}", f"--timeout={expiry_time - int(time.time())}"
            ])
            
            if success:
                success_count += 1
                self.logger.info(f"Added firewalld rule for {ip_address}:{port}/{protocol}")
            else:
                self.logger.error(f"Failed to add firewalld rule for {ip_address}:{port}/{protocol}: {stderr}")
        
        if success_count == total_rules:
            self.logger.info(f"Successfully added all {total_rules} firewalld rules for {ip_address}")
            return True
        else:
            self.logger.error(f"Only {success_count}/{total_rules} firewalld rules added for {ip_address}")
            return False
    
    def remove_whitelist_rule(self, ip_address: str) -> bool:
        """
        Remove firewalld rules for an IP address.
        
        Args:
            ip_address: IP address or CIDR to remove from whitelist
            
        Returns:
            True if rules removed successfully, False otherwise
        """
        if not self.is_enabled():
            return True
            
        if not self.is_firewalld_available():
            self.logger.error("Firewalld not available for removing whitelist rule")
            return False
            
        success_count = 0
        total_rules = len(self.monitored_ports)
        
        for port_config in self.monitored_ports:
            port = port_config.get("port")
            protocol = port_config.get("protocol", "tcp")
            
            # Remove rich rule
            rich_rule = f'rule family="ipv4" source address="{ip_address}" port protocol="{protocol}" port="{port}" accept'
            
            success, stdout, stderr = self._run_firewall_cmd([
                f"--zone={self.zone_name}", f"--remove-rich-rule={rich_rule}"
            ], check=False)
            
            if success:
                success_count += 1
                self.logger.info(f"Removed firewalld rule for {ip_address}:{port}/{protocol}")
            else:
                # Don't log as error if rule doesn't exist (might have expired)
                self.logger.debug(f"Could not remove firewalld rule for {ip_address}:{port}/{protocol}: {stderr}")
        
        self.logger.info(f"Processed {success_count}/{total_rules} firewalld rule removals for {ip_address}")
        return True  # Return True even if some rules weren't found (they may have expired)
    
    def get_active_rules(self) -> List[FirewalldRule]:
        """
        Get list of currently active firewalld rules in the knocker zone.
        
        Returns:
            List of FirewalldRule objects representing active rules
        """
        if not self.is_enabled() or not self.is_firewalld_available():
            return []
            
        active_rules = []
        
        # Get rich rules from the zone
        success, stdout, stderr = self._run_firewall_cmd([
            f"--zone={self.zone_name}", "--list-rich-rules"
        ], check=False)
        
        if not success:
            self.logger.warning(f"Failed to get active rules: {stderr}")
            return []
        
        # Parse rich rules (this is a simplified parser)
        # Format: rule family="ipv4" source address="1.2.3.4" port protocol="tcp" port="80" accept
        for line in stdout.split('\n'):
            if line.strip() and 'source address=' in line and 'port=' in line:
                try:
                    # Extract IP address
                    ip_start = line.find('source address="') + 16
                    ip_end = line.find('"', ip_start)
                    ip_address = line[ip_start:ip_end]
                    
                    # Extract port
                    port_start = line.rfind('port="') + 6
                    port_end = line.find('"', port_start)
                    port = int(line[port_start:port_end])
                    
                    # Extract protocol
                    proto_start = line.find('protocol="') + 10
                    proto_end = line.find('"', proto_start)
                    protocol = line[proto_start:proto_end]
                    
                    # For now, we can't easily get expiry time from firewalld
                    # We'll need to cross-reference with whitelist.json
                    rule = FirewalldRule(ip_address, port, protocol, 0)
                    active_rules.append(rule)
                    
                except (ValueError, IndexError) as e:
                    self.logger.warning(f"Failed to parse firewalld rule: {line} - {e}")
                    continue
        
        return active_rules
    
    def restore_missing_rules(self, whitelist: Dict[str, int]) -> bool:
        """
        Compare whitelist.json with active firewalld rules and restore missing ones.
        
        Args:
            whitelist: Dictionary of IP addresses to expiry times from whitelist.json
            
        Returns:
            True if all missing rules restored successfully, False otherwise
        """
        if not self.is_enabled():
            return True
            
        current_time = int(time.time())
        active_rules = self.get_active_rules()
        
        # Create a set of (ip, port, protocol) tuples for active rules
        active_rule_set = set()
        for rule in active_rules:
            active_rule_set.add((rule.ip_address, rule.port, rule.protocol))
        
        missing_rules = 0
        restored_rules = 0
        
        # Check each whitelist entry
        for ip_address, expiry_time in whitelist.items():
            # Skip expired entries
            if expiry_time <= current_time:
                continue
                
            # Check if rules exist for this IP for all monitored ports
            for port_config in self.monitored_ports:
                port = port_config.get("port")
                protocol = port_config.get("protocol", "tcp")
                
                rule_tuple = (ip_address, port, protocol)
                if rule_tuple not in active_rule_set:
                    missing_rules += 1
                    self.logger.info(f"Missing firewalld rule detected: {ip_address}:{port}/{protocol}")
                    
                    # Restore the rule with remaining TTL
                    remaining_ttl = expiry_time - current_time
                    if self._add_single_rule(ip_address, port, protocol, remaining_ttl):
                        restored_rules += 1
        
        if missing_rules > 0:
            self.logger.info(f"Restored {restored_rules}/{missing_rules} missing firewalld rules")
        else:
            self.logger.info("No missing firewalld rules detected")
        
        return restored_rules == missing_rules
    
    def _add_single_rule(self, ip_address: str, port: int, protocol: str, timeout_seconds: int) -> bool:
        """Add a single firewalld rule with timeout."""
        rich_rule = f'rule family="ipv4" source address="{ip_address}" port protocol="{protocol}" port="{port}" accept'
        
        success, stdout, stderr = self._run_firewall_cmd([
            f"--zone={self.zone_name}", f"--add-rich-rule={rich_rule}", f"--timeout={timeout_seconds}"
        ])
        
        if success:
            self.logger.info(f"Restored firewalld rule: {ip_address}:{port}/{protocol} (TTL: {timeout_seconds}s)")
            return True
        else:
            self.logger.error(f"Failed to restore rule {ip_address}:{port}/{protocol}: {stderr}")
            return False


# Global instance (will be initialized in main.py)
firewalld_integration: Optional[FirewalldIntegration] = None


def get_firewalld_integration() -> Optional[FirewalldIntegration]:
    """Get the global firewalld integration instance."""
    return firewalld_integration


def initialize_firewalld(settings: Dict[str, Any]) -> Optional[FirewalldIntegration]:
    """Initialize the global firewalld integration instance."""
    global firewalld_integration
    firewalld_integration = FirewalldIntegration(settings)
    return firewalld_integration