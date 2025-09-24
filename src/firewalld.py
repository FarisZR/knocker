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
import ipaddress
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
        self.zone_priority = self.firewalld_config.get("zone_priority", -100)
        self.default_action = self.firewalld_config.get("default_action", "drop")
        self.monitored_ports = self.firewalld_config.get("monitored_ports", [])
        self.monitored_ips = self.firewalld_config.get("monitored_ips", [])
        
        self.logger = logging.getLogger(__name__)
        
        # Validate monitored IPs have proper CIDR notation
        if self.enabled:
            self._validate_monitored_ips()
            
            # Validate default action
            if self.default_action not in ["drop", "reject"]:
                raise ValueError(f"Invalid default_action '{self.default_action}'. Must be 'drop' or 'reject'")
        
    def _validate_monitored_ips(self):
        """Validate that all monitored IPs have proper CIDR notation."""
        for ip_str in self.monitored_ips:
            try:
                network = ipaddress.ip_network(ip_str, strict=False)
                # Check if it's a single host without explicit netmask
                if '/' not in ip_str:
                    if network.version == 4:
                        raise ValueError(f"IPv4 address '{ip_str}' must include network mask (e.g., '{ip_str}/32' for single host)")
                    else:
                        raise ValueError(f"IPv6 address '{ip_str}' must include network mask (e.g., '{ip_str}/128' for single host)")
            except ValueError as e:
                self.logger.error(f"Invalid monitored IP '{ip_str}': {e}")
                raise ValueError(f"Invalid monitored IP configuration: {e}")
        
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
        # At DEBUG level, log the exact command that will be executed.
        # This is controlled by the top-level `logging.level` setting in knocker.yaml.
        # Note: DEBUG logging may expose IP addresses and full rule text in logs.
        self.logger.debug("Executing firewall-cmd: %s", " ".join(cmd))

        # Some deployments (uvicorn, gunicorn) attach their own loggers/handlers.
        # Also emit to the common uvicorn error logger at DEBUG so it appears when
        # running under typical ASGI servers that route logs through uvicorn.
        try:
            logging.getLogger("uvicorn.error").debug("Executing firewall-cmd: %s", " ".join(cmd))
        except Exception:
            # Best-effort only; don't fail if uvicorn logger isn't available.
            pass

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
    
    def _build_rich_rule(self, ip_address: str, port: int, protocol: str) -> Optional[str]:
        """
        Build a properly formatted rich rule for firewalld.
        
        Args:
            ip_address: IP address or CIDR to whitelist
            port: Port number
            protocol: Protocol (tcp/udp)
            
        Returns:
            Formatted rich rule string, or None if validation fails
        """
        try:
            # Validate and normalize the IP address/CIDR
            network = ipaddress.ip_network(ip_address, strict=False)
            
            # Determine IP family (ipv4 or ipv6)
            family = "ipv4" if network.version == 4 else "ipv6"
            
            # Format source address - use with_prefixlen for CIDR, just the address for single hosts
            if network.num_addresses == 1:
                source_addr = str(network.network_address)
            else:
                source_addr = str(network)
            
            # Validate port
            if not isinstance(port, int) or port < 1 or port > 65535:
                self.logger.error(f"Invalid port number: {port}")
                return None
            
            # Validate protocol
            if protocol not in ["tcp", "udp"]:
                self.logger.error(f"Invalid protocol: {protocol}")
                return None
            
            # Build the rich rule with high priority (low number = 1000) to override DROP rules
            rich_rule = f'rule family="{family}" source address="{source_addr}" port protocol="{protocol}" port="{port}" accept priority="1000"'
            return rich_rule
            
        except (ValueError, ipaddress.AddressValueError) as e:
            self.logger.error(f"Invalid IP address or CIDR '{ip_address}': {e}")
            return None
            
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
            success, stdout, _ = self._run_firewall_cmd(["--get-zones"], check=False)
            zone_exists = success and self.zone_name in stdout
            if not zone_exists:
                # Create the zone
                success, stdout, stderr = self._run_firewall_cmd([
                    "--permanent", f"--new-zone={self.zone_name}"
                ])
                if not success:
                    self.logger.error(f"Failed to create zone {self.zone_name}: {stderr}")
                    return False
                    
                self.logger.info(f"Created firewalld zone: {self.zone_name}")
            
            # Set zone priority (negative numbers have higher priority)
            success, _, stderr = self._run_firewall_cmd([
                "--permanent", f"--zone={self.zone_name}", f"--set-priority={self.zone_priority}"
            ])
            if not success:
                self.logger.warning(f"Failed to set zone priority: {stderr}")
            
            # Don't set DROP as default target - instead use specific port rules
            # This ensures only monitored ports are affected, not all traffic
            
            # Add monitored IP ranges to the zone
            for ip_range in self.monitored_ips:
                success, _, stderr = self._run_firewall_cmd([
                    "--permanent", f"--zone={self.zone_name}", f"--add-source={ip_range}"
                ])
                if not success:
                    self.logger.warning(f"Failed to add source {ip_range} to zone: {stderr}")
            
            # Add default action rules for monitored ports with low priority (high number)
            # These will be overridden by whitelist rules with higher priority (lower number)
            for port_config in self.monitored_ports:
                port = port_config.get("port")
                protocol = port_config.get("protocol", "tcp")
                
                # Add default action rules for both IPv4 and IPv6 with low priority (high number = 9999)
                for family in ["ipv4", "ipv6"]:
                    default_rule = f'rule family="{family}" port protocol="{protocol}" port="{port}" {self.default_action} priority="9999"'
                    success, _, stderr = self._run_firewall_cmd([
                        "--permanent", f"--zone={self.zone_name}", f"--add-rich-rule={default_rule}"
                    ])
                    if not success:
                        self.logger.warning(f"Failed to add {self.default_action.upper()} rule for {port}/{protocol} ({family}): {stderr}")
                    else:
                        self.logger.info(f"Added {self.default_action.upper()} rule for port {port}/{protocol} ({family})")

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
            
    def _add_or_replace_rule(self, ip_address: str, port: int, protocol: str, timeout_seconds: int) -> bool:
        """
        Try to add a rich rule with timeout. If firewalld reports the rule is already enabled
        (ALREADY_ENABLED / 'already in'), remove the existing rule and attempt to re-add it to
        ensure the timeout (TTL) is updated.
        """
        # Build rich rule using helper function
        rich_rule = self._build_rich_rule(ip_address, port, protocol)
        if not rich_rule:
            self.logger.error(f"Failed to build rich rule for {ip_address}:{port}/{protocol}")
            return False

        add_args = [f"--zone={self.zone_name}", f"--add-rich-rule={rich_rule}", f"--timeout={timeout_seconds}"]

        success, stdout, stderr = self._run_firewall_cmd(add_args)
        combined_output = " ".join(filter(None, [stdout, stderr])).upper()

        # If add succeeded and no warnings, we're done
        if success and "ALREADY_ENABLED" not in combined_output and "ALREADY IN" not in combined_output and "ALREADY" not in combined_output:
            self.logger.info(f"Added firewalld rule for {ip_address}:{port}/{protocol}")
            return True

        # If the command succeeded but indicates the rule already exists, attempt replace
        if success and ("ALREADY_ENABLED" in combined_output or "ALREADY IN" in combined_output or ("ALREADY" in combined_output and "IN" in combined_output)):
            self.logger.warning(f"firewall-cmd reported rule already exists for {ip_address}:{port}/{protocol}: {stderr or stdout}. Attempting to replace it to update TTL.")
            # Try to remove the existing rule (don't fail the whole operation on remove failure)
            rem_args = [f"--zone={self.zone_name}", f"--remove-rich-rule={rich_rule}"]
            rem_success, rem_stdout, rem_stderr = self._run_firewall_cmd(rem_args, check=False)
            if not rem_success:
                self.logger.warning(f"Failed to remove existing rule for {ip_address}:{port}/{protocol}: {rem_stderr or rem_stdout}")

            # Re-add with requested timeout
            readd_success, readd_stdout, readd_stderr = self._run_firewall_cmd(add_args)
            if readd_success:
                self.logger.info(f"Replaced firewalld rule for {ip_address}:{port}/{protocol} with new TTL={timeout_seconds}s")
                return True
            else:
                self.logger.error(f"Failed to re-add firewalld rule for {ip_address}:{port}/{protocol} after removal: {readd_stderr}")
                return False

        # If initial add failed (non-zero exit), log and return False
        if not success:
            self.logger.error(f"Failed to add firewalld rule for {ip_address}:{port}/{protocol}: {stderr}")
            return False

        # Fallback success
        self.logger.info(f"Added firewalld rule for {ip_address}:{port}/{protocol} (warning present)")
        return True

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

        # Calculate timeout - ensure it's positive
        timeout_seconds = expiry_time - int(time.time())
        if timeout_seconds <= 0:
            self.logger.error(f"Invalid timeout calculated: {timeout_seconds} seconds (expiry: {expiry_time}, current: {int(time.time())})")
            return False

        success_count = 0
        total_rules = len(self.monitored_ports)
        added_rules = []  # Track successfully added rules for potential rollback

        for port_config in self.monitored_ports:
            port = port_config.get("port")
            protocol = port_config.get("protocol", "tcp")

            # Attempt to add (and replace if needed) the rule
            ok = self._add_or_replace_rule(ip_address, port, protocol, timeout_seconds)
            if ok:
                success_count += 1
                # Track the canonical rich rule text for rollback
                rich_rule = self._build_rich_rule(ip_address, port, protocol)
                if rich_rule:
                    added_rules.append(rich_rule)
            else:
                self.logger.error(f"Failed to ensure firewalld rule for {ip_address}:{port}/{protocol}")

        if success_count == total_rules:
            self.logger.info(f"Successfully added all {total_rules} firewalld rules for {ip_address}")
            return True
        else:
            # Partial failure - rollback added rules
            self.logger.error(f"Only {success_count}/{total_rules} firewalld rules added for {ip_address}")
            self._rollback_rules(added_rules, ip_address)
            return False
    
    def _rollback_rules(self, rules: List[str], ip_address: str):
        """Roll back successfully added rules on partial failure."""
        self.logger.info(f"Rolling back {len(rules)} firewalld rules for {ip_address}")
        for rule in rules:
            success, stdout, stderr = self._run_firewall_cmd([
                f"--zone={self.zone_name}", f"--remove-rich-rule={rule}"
            ], check=False)
            if not success:
                self.logger.warning(f"Failed to rollback rule '{rule}': {stderr}")
    
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
            
            # Build rich rule using helper function
            rich_rule = self._build_rich_rule(ip_address, port, protocol)
            if not rich_rule:
                self.logger.warning(f"Failed to build rich rule for removal: {ip_address}:{port}/{protocol}")
                continue
            
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
        # Validate timeout
        if timeout_seconds <= 0:
            self.logger.error(f"Invalid timeout for rule restoration: {timeout_seconds} seconds")
            return False
            
        # Build rich rule using helper function
        rich_rule = self._build_rich_rule(ip_address, port, protocol)
        if not rich_rule:
            self.logger.error(f"Failed to build rich rule for restoration: {ip_address}:{port}/{protocol}")
            return False
        
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