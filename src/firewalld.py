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
import time
import ipaddress
import asyncio
import concurrent.futures
import threading
import re
from typing import Any, Dict, List, Mapping, Optional, Tuple, override
from dataclasses import dataclass

if __package__ in (None, ""):  # pragma: no cover - fallback for direct module execution
    from config import FirewalldPortSettings, FirewalldSettings, SettingsLike
else:
    from .config import FirewalldPortSettings, FirewalldSettings, SettingsLike


@dataclass
class FirewalldRule:
    """Represents a firewalld rule for an IP/port combination."""

    ip_address: str
    port: int
    protocol: str
    expiry_time: int

    @override
    def __str__(self):
        return f"{self.ip_address}:{self.port}/{self.protocol} (expires: {self.expiry_time})"


def _parse_rich_rule(line: str) -> Optional[FirewalldRule]:
    """Parse a source-and-port rich rule, ignoring unrelated zone rules."""
    if not line.strip() or "source address=" not in line or "port=" not in line:
        return None

    match = re.search(r'source address="([^"]+)".*?protocol="([^"]+)".*?port="([^"]+)"', line)
    if match is None:
        raise ValueError("missing rich-rule fields")

    ip_address, protocol, port_text = match.groups()
    return FirewalldRule(ip_address, int(port_text), protocol, 0)


class MutationQueueUnavailable(RuntimeError):
    """Raised when the bounded firewall mutation queue cannot accept work."""


class SerializedMutationExecutor:
    """Run blocking firewall mutations through one bounded worker."""

    def __init__(self, max_pending: int = 32):
        if max_pending <= 0:
            raise ValueError("firewalld.mutation_queue_capacity must be positive")
        self._executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=1, thread_name_prefix="knocker-firewall"
        )
        self._slots = threading.BoundedSemaphore(max_pending + 1)
        self._closed = False
        self._lock = threading.Lock()

    async def run(self, operation):
        with self._lock:
            if self._closed or not self._slots.acquire(blocking=False):
                raise MutationQueueUnavailable("Firewall mutation queue is unavailable")
            try:
                future = self._executor.submit(operation)
            except RuntimeError as exc:
                self._slots.release()
                raise MutationQueueUnavailable("Firewall mutation worker is unavailable") from exc

        wrapped = asyncio.wrap_future(future)
        try:
            return await wrapped
        finally:
            self._slots.release()

    def shutdown(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
        self._executor.shutdown(wait=True, cancel_futures=False)


class FirewalldIntegration:
    """Handles all firewalld operations for Knocker."""

    def __init__(self, firewalld_config: FirewalldSettings | Mapping[str, Any]):
        """Initialize firewalld integration from validated settings."""
        if not isinstance(firewalld_config, FirewalldSettings):
            if "firewalld" in firewalld_config and "enabled" not in firewalld_config:
                firewalld_config = firewalld_config["firewalld"]
            firewalld_config = FirewalldSettings.model_validate(firewalld_config)
        self.firewalld_config = firewalld_config
        self.enabled = firewalld_config.enabled
        self.zone_name = firewalld_config.zone_name
        self.zone_priority = firewalld_config.zone_priority
        self.default_action = firewalld_config.default_action
        self.zone_target = firewalld_config.zone_target
        self.monitored_ports = firewalld_config.monitored_ports
        self.monitored_ips = firewalld_config.monitored_ips

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
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=check)
            stdout = result.stdout.strip()
            stderr = result.stderr.strip()
            success = result.returncode == 0
            if not success:
                self.logger.error(
                    "firewall-cmd exited with status %s: %s", result.returncode, stderr or stdout
                )
            return success, stdout, stderr
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
            if not isinstance(protocol, str) or protocol not in ["tcp", "udp"]:
                self.logger.error(f"Invalid protocol: {protocol}")
                return None

            # Build the rich rule with high priority (low number = 1000) to override DROP rules
            rich_rule = f'rule family="{family}" source address="{source_addr}" port protocol="{protocol}" port="{port}" accept priority="1000"'
            return rich_rule

        except (ValueError, ipaddress.AddressValueError) as e:
            self.logger.error(f"Invalid IP address or CIDR '{ip_address}': {e}")
            return None

    def _rich_rule_args(
        self,
        operation: str,
        rich_rule: str,
        *,
        timeout: Optional[int] = None,
        permanent: bool = False,
    ) -> List[str]:
        args = ["--permanent"] if permanent else []
        args.extend(
            [
                f"--zone={self.zone_name}",
            ]
        )
        if operation == "list":
            args.append("--list-rich-rules")
        else:
            args.append(f"--{operation}-rich-rule={rich_rule}")
        if timeout is not None:
            args.append(f"--timeout={timeout}")
        return args

    def _default_rich_rule(self, family: str, port_config: FirewalldPortSettings) -> str:
        protocol = port_config.protocol
        port = port_config.port
        return (
            f'rule family="{family}" port protocol="{protocol}" port="{port}" '
            f'{self.default_action} priority="9999"'
        )

    def _parse_rich_rules(self, output: str, *, strict: bool) -> Optional[List[FirewalldRule]]:
        rules: List[FirewalldRule] = []
        for line in output.splitlines():
            try:
                rule = _parse_rich_rule(line)
                if rule is not None:
                    rules.append(rule)
            except (ValueError, IndexError) as exc:
                if strict:
                    self.logger.error("Failed to parse active firewalld rule: %s", line)
                    return None
                self.logger.warning("Failed to parse firewalld rule: %s - %s", line, exc)
        return rules

    def _list_rich_rules(self, *, strict: bool) -> Optional[List[FirewalldRule]]:
        success, stdout, stderr = self._run_firewall_cmd(
            self._rich_rule_args("list", ""), check=False
        )
        if not success:
            message = "Failed to get active rules: %s"
            if strict:
                self.logger.error(message, stderr)
            else:
                self.logger.warning(message, stderr)
            return None
        return self._parse_rich_rules(stdout, strict=strict)

    def is_firewalld_available(self) -> bool:
        """Check if firewalld is available and running."""
        success, stdout, stderr = self._run_firewall_cmd(["--state"], check=False)
        if success and stdout.strip().lower() == "running":
            return True

        self.logger.warning(f"Firewalld not available: {stderr}")
        return False

    def _check_firewalld_version(self) -> bool:
        """
        Ensure the installed firewalld version is >= 2.0.0.

        Uses `firewall-cmd --version` output (via _run_firewall_cmd) and
        performs a simple semantic-version comparison on the first numeric token.
        Returns True if compatible, False otherwise. Logs errors on failure.
        """
        success, stdout, stderr = self._run_firewall_cmd(["--version"], check=False)
        if not success:
            # Couldn't determine version; treat as incompatible
            self.logger.error(f"Failed to determine firewalld version: {stderr}")
            return False

        # Typical outputs:
        #  - "firewall-cmd 2.9.0"
        #  - "2.9.0"
        ver_text = stdout.strip()
        if not ver_text:
            self.logger.error("Empty output from firewall-cmd --version; cannot determine version")
            return False

        # Extract the first token that looks like a version (starts with a digit)
        tokens = ver_text.split()
        version_str = None
        for t in tokens:
            if t and t[0].isdigit():
                version_str = t
                break
        if not version_str:
            version_str = ver_text

        try:
            parts = version_str.split(".")
            major = int(parts[0]) if len(parts) > 0 and parts[0].isdigit() else 0
            minor = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
            patch = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0

            if (major, minor, patch) < (2, 0, 0):
                self.logger.error("knocker requires Firewalld 2.0 or newer.")
                return False

            return True
        except Exception as e:
            self.logger.error(f"Unable to parse firewalld version from output '{stdout}': {e}")
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

        if not self._check_firewalld_version():
            self.logger.error(
                "Firewalld 2.0 or newer is required before configuring zone priority."
            )
            return False

        try:
            # Check if zone already exists
            success, stdout, _ = self._run_firewall_cmd(["--get-zones"], check=False)
            if not success:
                self.logger.error("Failed to enumerate firewalld zones")
                return False
            zone_exists = self.zone_name in stdout.split()
            if not zone_exists:
                # Create the zone
                success, stdout, stderr = self._run_firewall_cmd(
                    ["--permanent", f"--new-zone={self.zone_name}"]
                )
                if not success:
                    self.logger.error(f"Failed to create zone {self.zone_name}: {stderr}")
                    return False

                self.logger.info(f"Created firewalld zone: {self.zone_name}")

            # Set zone priority (negative numbers have higher priority)
            success, _, stderr = self._run_firewall_cmd(
                ["--permanent", f"--zone={self.zone_name}", f"--set-priority={self.zone_priority}"]
            )
            if not success:
                self.logger.error(f"Failed to set zone priority: {stderr}")
                return False

            # Set zone target if specified
            if self.zone_target is not None:
                success, _, stderr = self._run_firewall_cmd(
                    ["--permanent", f"--zone={self.zone_name}", f"--set-target={self.zone_target}"]
                )
                if not success:
                    self.logger.error(f"Failed to set zone target: {stderr}")
                    return False
                else:
                    self.logger.info(f"Set zone target to: {self.zone_target}")

            # Don't set DROP as default target - instead use specific port rules
            # This ensures only monitored ports are affected, not all traffic

            # Add monitored IP ranges to the zone
            for ip_range in self.monitored_ips:
                success, _, stderr = self._run_firewall_cmd(
                    ["--permanent", f"--zone={self.zone_name}", f"--add-source={ip_range}"]
                )
                if not success:
                    self.logger.error(f"Failed to add source {ip_range} to zone: {stderr}")
                    return False

            # Add default action rules for monitored ports with low priority (high number)
            # These will be overridden by whitelist rules with higher priority (lower number)
            for port_config in self.monitored_ports:
                port = port_config.port
                protocol = port_config.protocol

                # Add default action rules for both IPv4 and IPv6 with low priority (high number = 9999)
                for family in ["ipv4", "ipv6"]:
                    default_rule = self._default_rich_rule(family, port_config)
                    success, _, stderr = self._run_firewall_cmd(
                        self._rich_rule_args("add", default_rule, permanent=True)
                    )
                    if not success:
                        self.logger.error(
                            f"Failed to add {self.default_action.upper()} rule for {port}/{protocol} ({family}): {stderr}"
                        )
                        return False
                    else:
                        self.logger.info(
                            f"Added {self.default_action.upper()} rule for port {port}/{protocol} ({family})"
                        )

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

    def _required_default_rules(self) -> set[str]:
        return {
            self._default_rich_rule(family, port_config)
            for port_config in self.monitored_ports
            for family in ("ipv4", "ipv6")
        }

    def verify_protection(self) -> bool:
        """Verify active firewalld protection without changing persistent state."""
        if not self.is_enabled():
            return True
        if not self.is_firewalld_available() or not self._check_firewalld_version():
            return False

        success, stdout, stderr = self._run_firewall_cmd(["--get-zones"], check=False)
        if not success or self.zone_name not in stdout.split():
            self.logger.error("Required firewalld zone is missing: %s", stderr)
            return False

        success, stdout, stderr = self._run_firewall_cmd(
            ["--permanent", f"--zone={self.zone_name}", "--get-priority"], check=False
        )
        if not success or stdout.strip() != str(self.zone_priority):
            self.logger.error("Firewalld zone priority verification failed: %s", stderr or stdout)
            return False

        if self.zone_target is not None:
            success, stdout, stderr = self._run_firewall_cmd(
                ["--permanent", f"--zone={self.zone_name}", "--get-target"], check=False
            )
            if not success or stdout.strip() != self.zone_target:
                self.logger.error("Firewalld zone target verification failed: %s", stderr or stdout)
                return False

        success, stdout, stderr = self._run_firewall_cmd(
            [f"--zone={self.zone_name}", "--list-sources"], check=False
        )
        if not success or not set(self.monitored_ips).issubset(set(stdout.split())):
            self.logger.error("Firewalld source verification failed: %s", stderr or stdout)
            return False

        # A zone with no configured sources is valid when it is bound to an
        # interface by the host (for example the existing public zone). In that
        # mode, existence alone is insufficient: an inactive zone protects no traffic.
        if not self.monitored_ips:
            success, stdout, stderr = self._run_firewall_cmd(["--get-active-zones"], check=False)
            active_zone_names = {
                line.split()[0].rstrip(":")
                for line in stdout.splitlines()
                if line and not line[0].isspace() and line.split()
            }
            if not success or self.zone_name not in active_zone_names:
                self.logger.error("Firewalld zone is not active: %s", stderr or stdout)
                return False

        missing_rules: list[str] = []
        for rich_rule in sorted(self._required_default_rules()):
            success, stdout, stderr = self._run_firewall_cmd(
                self._rich_rule_args("query", rich_rule), check=False
            )
            if not success or stdout.strip().lower() != "yes":
                self.logger.error(
                    "Required firewalld rule verification failed for %s: %s",
                    rich_rule,
                    stderr or stdout,
                )
                missing_rules.append(rich_rule)
        if missing_rules:
            self.logger.error("Missing required firewalld rules: %s", missing_rules)
            return False
        return True

    def _add_or_replace_rule(
        self, ip_address: str, port: int, protocol: str, timeout_seconds: int
    ) -> bool:
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

        add_args = self._rich_rule_args("add", rich_rule, timeout=timeout_seconds)

        success, stdout, stderr = self._run_firewall_cmd(add_args)
        combined_output = " ".join(filter(None, [stdout, stderr])).upper()

        # If add succeeded and no warnings, we're done
        if (
            success
            and "ALREADY_ENABLED" not in combined_output
            and "ALREADY IN" not in combined_output
            and "ALREADY" not in combined_output
        ):
            self.logger.info(f"Added firewalld rule for {ip_address}:{port}/{protocol}")
            return True

        # Attempt replace whenever firewalld indicates the rule already exists, even if
        # it returned a non-zero exit status.
        if (
            "ALREADY_ENABLED" in combined_output
            or "ALREADY IN" in combined_output
            or ("ALREADY" in combined_output and "IN" in combined_output)
        ):
            self.logger.warning(
                f"firewall-cmd reported rule already exists for {ip_address}:{port}/{protocol}: {stderr or stdout}. Attempting to replace it to update TTL."
            )
            # Try to remove the existing rule (don't fail the whole operation on remove failure)
            rem_args = self._rich_rule_args("remove", rich_rule)
            rem_success, rem_stdout, rem_stderr = self._run_firewall_cmd(rem_args, check=False)
            if not rem_success:
                self.logger.warning(
                    f"Failed to remove existing rule for {ip_address}:{port}/{protocol}: {rem_stderr or rem_stdout}"
                )

            # Re-add with requested timeout
            readd_success, readd_stdout, readd_stderr = self._run_firewall_cmd(add_args)
            if readd_success:
                self.logger.info(
                    f"Replaced firewalld rule for {ip_address}:{port}/{protocol} with new TTL={timeout_seconds}s"
                )
                return True
            else:
                self.logger.error(
                    f"Failed to re-add firewalld rule for {ip_address}:{port}/{protocol} after removal: {readd_stderr}"
                )
                return False

        # If initial add failed (non-zero exit), log and return False
        if not success:
            self.logger.error(
                f"Failed to add firewalld rule for {ip_address}:{port}/{protocol}: {stderr}"
            )
            return False

        # Fallback success
        self.logger.info(
            f"Added firewalld rule for {ip_address}:{port}/{protocol} (warning present)"
        )
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
            self.logger.error(
                f"Invalid timeout calculated: {timeout_seconds} seconds (expiry: {expiry_time}, current: {int(time.time())})"
            )
            return False

        success_count = 0
        total_rules = len(self.monitored_ports)
        added_rules = []  # Track successfully added rules for potential rollback

        for port_config in self.monitored_ports:
            port = port_config.port
            protocol = port_config.protocol

            # Attempt to add (and replace if needed) the rule
            ok = self._add_or_replace_rule(ip_address, port, protocol, timeout_seconds)
            if ok:
                success_count += 1
                # Track the canonical rich rule text for rollback
                rich_rule = self._build_rich_rule(ip_address, port, protocol)
                if rich_rule:
                    added_rules.append(rich_rule)
            else:
                self.logger.error(
                    f"Failed to ensure firewalld rule for {ip_address}:{port}/{protocol}"
                )

        if success_count == total_rules:
            self.logger.info(
                f"Successfully added all {total_rules} firewalld rules for {ip_address}"
            )
            return True
        else:
            # Partial failure - rollback added rules
            self.logger.error(
                f"Only {success_count}/{total_rules} firewalld rules added for {ip_address}"
            )
            self._rollback_rules(added_rules, ip_address)
            return False

    def _rollback_rules(self, rules: List[str], ip_address: str):
        """Roll back successfully added rules on partial failure."""
        self.logger.info(f"Rolling back {len(rules)} firewalld rules for {ip_address}")
        for rule in rules:
            success, stdout, stderr = self._run_firewall_cmd(
                self._rich_rule_args("remove", rule), check=False
            )
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
            port = port_config.port
            protocol = port_config.protocol

            # Build rich rule using helper function
            rich_rule = self._build_rich_rule(ip_address, port, protocol)
            if not rich_rule:
                self.logger.warning(
                    f"Failed to build rich rule for removal: {ip_address}:{port}/{protocol}"
                )
                continue

            success, stdout, stderr = self._run_firewall_cmd(
                self._rich_rule_args("remove", rich_rule), check=False
            )

            if success:
                success_count += 1
                self.logger.info(f"Removed firewalld rule for {ip_address}:{port}/{protocol}")
            else:
                # Don't log as error if rule doesn't exist (might have expired)
                self.logger.debug(
                    f"Could not remove firewalld rule for {ip_address}:{port}/{protocol}: {stderr}"
                )

        self.logger.info(
            f"Processed {success_count}/{total_rules} firewalld rule removals for {ip_address}"
        )
        return True  # Return True even if some rules weren't found (they may have expired)

    def get_active_rules(self) -> List[FirewalldRule]:
        """
        Get list of currently active firewalld rules in the knocker zone.

        Returns:
            List of FirewalldRule objects representing active rules
        """
        if not self.is_enabled() or not self.is_firewalld_available():
            return []

        return self._list_rich_rules(strict=False) or []

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
        if not self.is_firewalld_available():
            return False
        active_rules = self._get_active_rules()
        if active_rules is None:
            return False

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
                port = port_config.port
                protocol = port_config.protocol

                rule_tuple = (ip_address, port, protocol)
                if rule_tuple not in active_rule_set:
                    missing_rules += 1
                    self.logger.info(
                        f"Missing firewalld rule detected: {ip_address}:{port}/{protocol}"
                    )

                    # Restore the rule with remaining TTL
                    remaining_ttl = expiry_time - current_time
                    if self._add_single_rule(ip_address, port, protocol, remaining_ttl):
                        restored_rules += 1

        if missing_rules > 0:
            self.logger.info(f"Restored {restored_rules}/{missing_rules} missing firewalld rules")
        else:
            self.logger.info("No missing firewalld rules detected")

        return restored_rules == missing_rules

    def _get_active_rules(self) -> Optional[List[FirewalldRule]]:
        """Return active rules, or None when firewalld could not be queried."""
        return self._list_rich_rules(strict=True)

    def _add_single_rule(
        self, ip_address: str, port: int, protocol: str, timeout_seconds: int
    ) -> bool:
        """Add a single firewalld rule with timeout.

        This now delegates to _add_or_replace_rule so that behavior for handling
        "ALREADY_ENABLED" warnings is consistent between normal adds and restoration.
        """
        # Validate timeout
        if timeout_seconds <= 0:
            self.logger.error(f"Invalid timeout for rule restoration: {timeout_seconds} seconds")
            return False

        # Delegate to add-or-replace helper which handles ALREADY_ENABLED collisions
        return self._add_or_replace_rule(ip_address, port, protocol, timeout_seconds)


# Global instance (will be initialized in main.py)
firewalld_integration: Optional[FirewalldIntegration] = None
mutation_executor: Optional[SerializedMutationExecutor] = None


def get_firewalld_integration() -> Optional[FirewalldIntegration]:
    """Get the global firewalld integration instance."""
    return firewalld_integration


def _firewalld_config(settings: SettingsLike) -> FirewalldSettings:
    if isinstance(settings, Mapping):
        return FirewalldSettings.model_validate(settings.get("firewalld", {}) or {})
    return settings.firewalld


def initialize_firewalld(settings: SettingsLike) -> Optional[FirewalldIntegration]:
    """Initialize the global firewalld integration instance."""
    global firewalld_integration
    firewalld_integration = FirewalldIntegration(_firewalld_config(settings))
    return firewalld_integration


def initialize_mutation_executor(settings: SettingsLike) -> SerializedMutationExecutor:
    """Create the process-local bounded firewall mutation worker."""
    global mutation_executor
    shutdown_mutation_executor()
    mutation_executor = SerializedMutationExecutor(
        _firewalld_config(settings).mutation_queue_capacity
    )
    return mutation_executor


def get_mutation_executor(settings: Optional[SettingsLike] = None) -> SerializedMutationExecutor:
    global mutation_executor
    if mutation_executor is None:
        capacity = 32
        if settings is not None:
            capacity = _firewalld_config(settings).mutation_queue_capacity
        mutation_executor = SerializedMutationExecutor(capacity)
    return mutation_executor


async def run_mutation(operation, settings: Optional[SettingsLike] = None):
    """Submit one blocking mutation and await its result."""
    return await get_mutation_executor(settings).run(operation)


def shutdown_mutation_executor() -> None:
    global mutation_executor
    if mutation_executor is not None:
        mutation_executor.shutdown()
        mutation_executor = None
