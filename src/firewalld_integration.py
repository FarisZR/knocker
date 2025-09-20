"""
Firewalld integration module for knocker.

Provides functionality to:
- Create and manage a dedicated firewalld zone
- Add/remove timed allow rules for specific IP/CIDR + port combinations
- Reconcile state on startup (restore missing rules if still valid)
- Background cleanup of expired rules
"""

import json
import time
import logging
import subprocess
import threading
import ipaddress
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

# Thread lock for firewalld state operations
_firewalld_state_lock = threading.Lock()

logger = logging.getLogger(__name__)

@dataclass
class FirewalldRule:
    """Represents a firewalld rule with metadata."""
    ip_or_cidr: str
    ports: List[str]  # Format: ["22/tcp", "443/tcp"]
    expires_at: int
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip_or_cidr": self.ip_or_cidr,
            "ports": self.ports,
            "expires_at": self.expires_at
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'FirewalldRule':
        return cls(
            ip_or_cidr=data["ip_or_cidr"],
            ports=data["ports"],
            expires_at=data["expires_at"]
        )

class FirewalldIntegration:
    """Manages firewalld zone and rules for knocker."""
    
    def __init__(self, settings: Dict[str, Any]):
        """Initialize firewalld integration with settings."""
        self.settings = settings
        self.firewalld_config = settings.get("security", {}).get("firewalld", {})
        self.enabled = self.firewalld_config.get("enabled", False)
        
        if not self.enabled:
            logger.info("Firewalld integration is disabled")
            return
            
        self.zone_name = self.firewalld_config.get("zone_name", "knocker")
        self.monitored_ports = self.firewalld_config.get("monitored_ports", [])
        self.monitored_sources = self.firewalld_config.get("monitored_sources", [])
        self.state_storage_path = self.firewalld_config.get("state_storage_path", "/data/firewalld_state.json")
        self.reconcile_interval = self.firewalld_config.get("reconcile_interval_seconds", 30)
        self.cleanup_on_exit = self.firewalld_config.get("cleanup_on_exit", True)
        
        # Validate configuration
        self._validate_config()
        
        # Initialize firewalld setup
        self._initialize_zone()
        
        # Start background reconciliation thread
        self._start_reconciliation_thread()
        
        logger.info(f"Firewalld integration initialized with zone '{self.zone_name}'")
    
    def _validate_config(self):
        """Validate firewalld configuration."""
        if not isinstance(self.monitored_ports, list):
            raise ValueError("monitored_ports must be a list")
            
        if len(self.monitored_ports) > 200:
            raise ValueError("Too many monitored ports (max 200)")
            
        for port in self.monitored_ports:
            if not isinstance(port, str) or not self._is_valid_port_spec(port):
                raise ValueError(f"Invalid port specification: {port}")
        
        # Remove duplicates
        self.monitored_ports = list(set(self.monitored_ports))
        
        if not isinstance(self.monitored_sources, list):
            raise ValueError("monitored_sources must be a list")
            
        for source in self.monitored_sources:
            try:
                ipaddress.ip_network(source, strict=False)
            except ValueError:
                raise ValueError(f"Invalid CIDR in monitored_sources: {source}")
    
    def _is_valid_port_spec(self, port_spec: str) -> bool:
        """Validate port specification format (e.g., '22/tcp', '443/udp')."""
        try:
            if '/' not in port_spec:
                return False
            port_str, protocol = port_spec.split('/', 1)
            port_num = int(port_str)
            return 1 <= port_num <= 65535 and protocol.lower() in ['tcp', 'udp']
        except (ValueError, IndexError):
            return False
    
    def _run_firewall_cmd(self, args: List[str], timeout: int = 30) -> subprocess.CompletedProcess:
        """Run firewall-cmd with error handling and logging."""
        cmd = ["firewall-cmd"] + args
        try:
            logger.debug(f"Running firewall-cmd: {' '.join(cmd)}")
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=timeout,
                check=False
            )
            
            if result.returncode != 0:
                logger.error(f"firewall-cmd failed with return code {result.returncode}")
                logger.error(f"Command: {' '.join(cmd)}")
                logger.error(f"Stderr: {result.stderr}")
                logger.debug(f"Stdout: {result.stdout}")
            else:
                logger.debug(f"firewall-cmd succeeded: {result.stdout.strip()}")
            
            return result
        except subprocess.TimeoutExpired:
            logger.error(f"firewall-cmd timed out after {timeout}s: {' '.join(cmd)}")
            raise
        except FileNotFoundError:
            logger.error("firewall-cmd not found. Is firewalld installed?")
            raise
    
    def _initialize_zone(self):
        """Create and configure the knocker firewalld zone."""
        try:
            # Check if zone already exists
            result = self._run_firewall_cmd(["--get-zones"])
            if result.returncode == 0 and self.zone_name in result.stdout:
                logger.info(f"Zone '{self.zone_name}' already exists")
            else:
                # Create new zone
                logger.info(f"Creating firewalld zone '{self.zone_name}'")
                result = self._run_firewall_cmd(["--permanent", "--new-zone", self.zone_name])
                if result.returncode != 0:
                    raise RuntimeError(f"Failed to create zone '{self.zone_name}'")
            
            # Configure zone with drop target (deny by default)
            self._run_firewall_cmd(["--permanent", "--zone", self.zone_name, "--set-target", "DROP"])
            
            # Add monitored ports as services to the zone (but with DROP target, they're blocked by default)
            for port_spec in self.monitored_ports:
                self._run_firewall_cmd([
                    "--permanent", "--zone", self.zone_name, 
                    "--add-port", port_spec
                ])
            
            # Reload to apply permanent changes
            result = self._run_firewall_cmd(["--reload"])
            if result.returncode != 0:
                raise RuntimeError("Failed to reload firewalld configuration")
                
            logger.info(f"Firewalld zone '{self.zone_name}' configured successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize firewalld zone: {e}")
            raise
    
    def add_allow_rule(self, ip_or_cidr: str, ttl_seconds: int) -> bool:
        """
        Add a timed allow rule for the given IP/CIDR.
        
        Returns True on success, False on failure.
        Only updates state metadata after successful firewalld rule addition.
        """
        if not self.enabled:
            return True  # No-op if disabled
            
        if ttl_seconds <= 0:
            logger.warning(f"Invalid TTL {ttl_seconds} for firewalld rule")
            return False
        
        try:
            # Determine IP family for rich rule
            try:
                network = ipaddress.ip_network(ip_or_cidr, strict=False)
                family = "ipv6" if network.version == 6 else "ipv4"
            except ValueError:
                logger.error(f"Invalid IP/CIDR for firewalld rule: {ip_or_cidr}")
                return False
            
            # Check if we should restrict to monitored sources
            if self.monitored_sources and not self._is_source_allowed(ip_or_cidr):
                logger.warning(f"IP/CIDR {ip_or_cidr} not in monitored_sources, skipping firewalld rule")
                return False
            
            expires_at = int(time.time()) + ttl_seconds
            
            # Add rich rules for each monitored port
            success_count = 0
            failed_ports = []
            
            for port_spec in self.monitored_ports:
                port, protocol = port_spec.split('/')
                
                # Create rich rule: allow specific source to specific port
                rich_rule = f'rule family="{family}" source address="{ip_or_cidr}" port port="{port}" protocol="{protocol}" accept'
                
                result = self._run_firewall_cmd([
                    "--zone", self.zone_name,
                    "--add-rich-rule", rich_rule,
                    f"--timeout={ttl_seconds}"
                ])
                
                if result.returncode == 0:
                    success_count += 1
                    logger.debug(f"Added firewalld rule for {ip_or_cidr}:{port_spec} with {ttl_seconds}s timeout")
                else:
                    failed_ports.append(port_spec)
                    logger.error(f"Failed to add firewalld rule for {ip_or_cidr}:{port_spec}")
            
            # Only consider it successful if ALL ports were added
            if success_count == len(self.monitored_ports):
                # Update state metadata
                self._update_state_metadata(ip_or_cidr, self.monitored_ports, expires_at)
                logger.info(f"Successfully added firewalld rules for {ip_or_cidr} (expires in {ttl_seconds}s)")
                return True
            else:
                logger.error(f"Failed to add firewalld rules for ports: {failed_ports}")
                # Try to clean up any partial rules that were added
                self._cleanup_partial_rules(ip_or_cidr, [p for p in self.monitored_ports if p not in failed_ports])
                return False
                
        except Exception as e:
            logger.error(f"Exception adding firewalld rule for {ip_or_cidr}: {e}")
            return False
    
    def _is_source_allowed(self, ip_or_cidr: str) -> bool:
        """Check if IP/CIDR is within monitored_sources (if configured)."""
        if not self.monitored_sources:
            return True  # No restrictions if empty
        
        try:
            target_network = ipaddress.ip_network(ip_or_cidr, strict=False)
            for source_cidr in self.monitored_sources:
                source_network = ipaddress.ip_network(source_cidr, strict=False)
                if target_network.subnet_of(source_network) or target_network == source_network:
                    return True
            return False
        except ValueError:
            return False
    
    def _cleanup_partial_rules(self, ip_or_cidr: str, successful_ports: List[str]):
        """Remove any successfully added rules when partial addition fails."""
        try:
            network = ipaddress.ip_network(ip_or_cidr, strict=False)
            family = "ipv6" if network.version == 6 else "ipv4"
            
            for port_spec in successful_ports:
                port, protocol = port_spec.split('/')
                rich_rule = f'rule family="{family}" source address="{ip_or_cidr}" port port="{port}" protocol="{protocol}" accept'
                
                self._run_firewall_cmd([
                    "--zone", self.zone_name,
                    "--remove-rich-rule", rich_rule
                ])
                logger.debug(f"Cleaned up partial rule for {ip_or_cidr}:{port_spec}")
        except Exception as e:
            logger.error(f"Failed to cleanup partial rules for {ip_or_cidr}: {e}")
    
    def _load_state_metadata(self) -> Dict[str, FirewalldRule]:
        """Load firewalld state metadata from JSON file."""
        with _firewalld_state_lock:
            state_path = Path(self.state_storage_path)
            if not state_path.exists():
                return {}
            
            try:
                with open(state_path, 'r') as f:
                    data = json.load(f)
                
                rules = {}
                for key, rule_data in data.items():
                    rules[key] = FirewalldRule.from_dict(rule_data)
                
                return rules
            except (json.JSONDecodeError, KeyError, TypeError) as e:
                logger.error(f"Failed to load firewalld state metadata: {e}")
                return {}
    
    def _save_state_metadata(self, rules: Dict[str, FirewalldRule]):
        """Save firewalld state metadata to JSON file."""
        with _firewalld_state_lock:
            state_path = Path(self.state_storage_path)
            state_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Convert rules to serializable format
            data = {key: rule.to_dict() for key, rule in rules.items()}
            
            # Write to temporary file first, then atomically rename
            temp_path = state_path.with_suffix('.tmp')
            try:
                with open(temp_path, 'w') as f:
                    json.dump(data, f, indent=2)
                
                # Atomic rename
                temp_path.rename(state_path)
            except Exception as e:
                if temp_path.exists():
                    temp_path.unlink()
                raise e
    
    def _update_state_metadata(self, ip_or_cidr: str, ports: List[str], expires_at: int):
        """Update state metadata for a rule."""
        rules = self._load_state_metadata()
        rules[ip_or_cidr] = FirewalldRule(ip_or_cidr, ports, expires_at)
        self._save_state_metadata(rules)
    
    def reconcile_state(self):
        """Reconcile firewalld runtime state with stored metadata on startup."""
        if not self.enabled:
            return
            
        logger.info("Starting firewalld state reconciliation")
        rules = self._load_state_metadata()
        now = int(time.time())
        
        restored_count = 0
        expired_count = 0
        
        for ip_or_cidr, rule in rules.items():
            if rule.expires_at <= now:
                # Rule has expired, remove from metadata
                expired_count += 1
                continue
            
            # Rule is still valid, check if it exists in firewalld runtime
            remaining_ttl = rule.expires_at - now
            if self._restore_rule_if_missing(rule, remaining_ttl):
                restored_count += 1
        
        # Clean up expired rules from metadata
        if expired_count > 0:
            active_rules = {k: v for k, v in rules.items() if v.expires_at > now}
            self._save_state_metadata(active_rules)
        
        logger.info(f"Firewalld state reconciliation complete: {restored_count} restored, {expired_count} expired")
    
    def _restore_rule_if_missing(self, rule: FirewalldRule, remaining_ttl: int) -> bool:
        """Restore a rule if it's missing from firewalld runtime."""
        try:
            # Check if any rules exist for this IP (simplified check)
            network = ipaddress.ip_network(rule.ip_or_cidr, strict=False)
            family = "ipv6" if network.version == 6 else "ipv4"
            
            # Get current rich rules for the zone
            result = self._run_firewall_cmd(["--zone", self.zone_name, "--list-rich-rules"])
            if result.returncode != 0:
                return False
            
            current_rules = result.stdout.strip()
            
            # Check if our rule exists (simple string search)
            rule_exists = False
            for port_spec in rule.ports:
                port, protocol = port_spec.split('/')
                expected_rule_fragment = f'source address="{rule.ip_or_cidr}" port port="{port}" protocol="{protocol}"'
                if expected_rule_fragment in current_rules:
                    rule_exists = True
                    break
            
            if not rule_exists:
                # Rule is missing, restore it
                logger.info(f"Restoring missing firewalld rule for {rule.ip_or_cidr} with {remaining_ttl}s TTL")
                return self._add_runtime_rule(rule.ip_or_cidr, remaining_ttl, rule.ports)
            
            return False  # Rule already exists
            
        except Exception as e:
            logger.error(f"Failed to restore rule for {rule.ip_or_cidr}: {e}")
            return False
    
    def _add_runtime_rule(self, ip_or_cidr: str, ttl_seconds: int, ports: List[str]) -> bool:
        """Add runtime rule without updating metadata (used for restoration)."""
        try:
            network = ipaddress.ip_network(ip_or_cidr, strict=False)
            family = "ipv6" if network.version == 6 else "ipv4"
            
            success_count = 0
            for port_spec in ports:
                port, protocol = port_spec.split('/')
                rich_rule = f'rule family="{family}" source address="{ip_or_cidr}" port port="{port}" protocol="{protocol}" accept'
                
                result = self._run_firewall_cmd([
                    "--zone", self.zone_name,
                    "--add-rich-rule", rich_rule,
                    f"--timeout={ttl_seconds}"
                ])
                
                if result.returncode == 0:
                    success_count += 1
            
            return success_count == len(ports)
            
        except Exception as e:
            logger.error(f"Failed to add runtime rule for {ip_or_cidr}: {e}")
            return False
    
    def cleanup_expired_rules(self):
        """Clean up expired rules from metadata and attempt removal from firewalld."""
        if not self.enabled:
            return
            
        rules = self._load_state_metadata()
        now = int(time.time())
        
        active_rules = {}
        expired_ips = []
        
        for ip_or_cidr, rule in rules.items():
            if rule.expires_at <= now:
                expired_ips.append(ip_or_cidr)
            else:
                active_rules[ip_or_cidr] = rule
        
        if expired_ips:
            # Update metadata (remove expired entries)
            self._save_state_metadata(active_rules)
            
            # Attempt to remove expired rules from firewalld (best effort)
            for ip_or_cidr in expired_ips:
                try:
                    self._remove_expired_firewalld_rules(ip_or_cidr)
                except Exception as e:
                    # Log error but continue (firewalld timeout should handle cleanup anyway)
                    logger.debug(f"Failed to manually remove expired firewalld rules for {ip_or_cidr}: {e}")
            
            logger.info(f"Cleaned up {len(expired_ips)} expired firewalld rules from metadata")
    
    def _remove_expired_firewalld_rules(self, ip_or_cidr: str):
        """Remove firewalld rules for an IP (best effort, since timeout should handle it)."""
        try:
            network = ipaddress.ip_network(ip_or_cidr, strict=False)
            family = "ipv6" if network.version == 6 else "ipv4"
            
            for port_spec in self.monitored_ports:
                port, protocol = port_spec.split('/')
                rich_rule = f'rule family="{family}" source address="{ip_or_cidr}" port port="{port}" protocol="{protocol}" accept'
                
                # Try to remove rule (may already be gone due to timeout)
                self._run_firewall_cmd([
                    "--zone", self.zone_name,
                    "--remove-rich-rule", rich_rule
                ])
        except Exception:
            pass  # Ignore errors - timeout should have handled it
    
    def _start_reconciliation_thread(self):
        """Start background thread for periodic reconciliation and cleanup."""
        if not self.enabled:
            return
            
        def reconciliation_worker():
            while True:
                try:
                    time.sleep(self.reconcile_interval)
                    self.cleanup_expired_rules()
                except Exception as e:
                    logger.error(f"Error in firewalld reconciliation thread: {e}")
        
        thread = threading.Thread(target=reconciliation_worker, daemon=True)
        thread.start()
        logger.info(f"Started firewalld reconciliation thread (interval: {self.reconcile_interval}s)")
    
    def cleanup_on_shutdown(self):
        """Clean up zone and rules when service shuts down (if configured)."""
        if not self.enabled or not self.cleanup_on_exit:
            return
            
        logger.info(f"Cleaning up firewalld zone '{self.zone_name}' on shutdown")
        try:
            # Remove the zone entirely (this removes all rules too)
            result = self._run_firewall_cmd(["--permanent", "--delete-zone", self.zone_name])
            if result.returncode == 0:
                self._run_firewall_cmd(["--reload"])
                logger.info("Firewalld zone cleaned up successfully")
            else:
                logger.warning("Failed to clean up firewalld zone on shutdown")
        except Exception as e:
            logger.error(f"Exception during firewalld cleanup: {e}")

# Global instance (will be initialized by main.py)
firewalld_integration: Optional[FirewalldIntegration] = None

def initialize_firewalld(settings: Dict[str, Any]):
    """Initialize the global firewalld integration instance."""
    global firewalld_integration
    firewalld_config = settings.get("security", {}).get("firewalld", {})
    
    if firewalld_config.get("enabled", False):
        try:
            firewalld_integration = FirewalldIntegration(settings)
            # Perform initial reconciliation
            firewalld_integration.reconcile_state()
        except Exception as e:
            logger.error(f"Failed to initialize firewalld integration: {e}")
            # Disable integration on failure
            firewalld_integration = None
            raise
    else:
        logger.info("Firewalld integration is disabled in configuration")

def add_firewalld_rule(ip_or_cidr: str, ttl_seconds: int) -> bool:
    """
    Add firewalld rule if integration is enabled.
    Returns True on success or if disabled, False on failure.
    """
    if firewalld_integration is None:
        return True  # No-op if disabled
    
    return firewalld_integration.add_allow_rule(ip_or_cidr, ttl_seconds)

def cleanup_firewalld():
    """Clean up firewalld integration on shutdown."""
    if firewalld_integration is not None:
        firewalld_integration.cleanup_on_shutdown()