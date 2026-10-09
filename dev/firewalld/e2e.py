"""FirewallD E2E controller. All packet probes originate in client containers.

Run through dev/firewalld_integration_test.sh, never against a host daemon.
This deliberately lives outside tests/ so ordinary pytest needs no privileges.
"""

import ipaddress
import json
import os
from pathlib import Path
import subprocess
import time
import unittest

ADMIN_KEY = "dev-only-admin-9c2f4a6d0d4b8f17e6a1c5b9d3f7a2e8"
PERSONAL_KEY = "dev-only-phone-4b7e1a9d2c6f8e3a5d0b7c1f9a4e6d2b"
PROJECT = os.environ["COMPOSE_PROJECT_NAME"]
TIME_SCALE = float(os.environ.get("KNOCKER_E2E_TIME_SCALE", "1"))
assert TIME_SCALE >= 1, "KNOCKER_E2E_TIME_SCALE must be at least 1"
COMPOSE = [
    "docker",
    "compose",
    "--project-name",
    PROJECT,
    "-f",
    str(Path(__file__).resolve().parents[1] / "docker-compose.yml"),
]
PORTS = (("tcp", 9000), ("udp", 9001))


def command(args, *, data=None, check=True):
    result = subprocess.run(
        args, input=data, text=True, capture_output=True, check=False, timeout=90 * TIME_SCALE
    )
    if check and result.returncode != 0:
        raise RuntimeError(
            f"Command failed ({result.returncode}): {' '.join(args)}\n"
            f"{result.stdout}\n{result.stderr}"
        )
    return result


def execute(service, *args, data=None, check=True):
    return command([*COMPOSE, "exec", "-T", service, *args], data=data, check=check)


def firewall(*args, check=True):
    return execute("knocker", "firewall-cmd", *args, check=check).stdout.strip()


def link_address(service):
    lines = execute(service, "cat", "/proc/net/if_inet6").stdout.splitlines()
    addresses = [
        str(ipaddress.IPv6Address(int(line.split()[0], 16)))
        for line in lines
        if line.split()[-1] == "eth0" and line.split()[3] == "20"
    ]
    if len(addresses) != 1:
        raise RuntimeError(f"{service} needs exactly one IPv6 link-local address")
    return addresses[0]


def rule(ip, protocol, port):
    family = "ipv6" if ":" in ip else "ipv4"
    return (
        f'rule family="{family}" source address="{ip}" '
        f'port protocol="{protocol}" port="{port}" accept priority="1000"'
    )


class FirewallEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.addresses = {}
        namespaces = {os.readlink("/proc/self/ns/net")}
        for service in ("knocker", "client", "stranger"):
            container_id = command([*COMPOSE, "ps", "-q", service]).stdout.strip()
            info = json.loads(command(["docker", "inspect", container_id]).stdout)[0]
            config = info["HostConfig"]
            assert not config["Privileged"], service
            assert config["NetworkMode"] != "host", service
            assert not config["PortBindings"], service
            for mount in info["Mounts"]:
                assert mount["Destination"] not in (
                    "/run/dbus/system_bus_socket",
                    "/var/run/dbus/system_bus_socket",
                    "/var/run/docker.sock",
                ), mount
            if service == "knocker":
                added = [cap.removeprefix("CAP_") for cap in config["CapAdd"] or []]
                assert added == ["NET_ADMIN"], config["CapAdd"]
            else:
                assert not config["CapAdd"], service
                dropped = [cap.removeprefix("CAP_") for cap in config["CapDrop"] or []]
                assert dropped == ["ALL"], config["CapDrop"]
            networks = info["NetworkSettings"]["Networks"]
            assert len(networks) == 1
            network = next(iter(networks.values()))
            cls.addresses[service] = {4: network["IPAddress"], 6: link_address(service)}
            assert all(cls.addresses[service].values()), "IPv4 and IPv6 must both be enabled"
            ns = execute(service, "readlink", "/proc/self/ns/net").stdout.strip()
            assert ns not in namespaces, f"{service} shares another network namespace"
            namespaces.add(ns)
        network_info = json.loads(
            command(["docker", "network", "inspect", f"{PROJECT}_test_net"]).stdout
        )[0]
        assert network_info["Internal"]
        # Probe full readiness once, rather than spawning firewall-cmd repeatedly
        # through a background liveness check throughout the packet tests.
        execute("knocker", "curl", "--fail", "--silent", "http://localhost:8000/ready")
        print(
            "Verified: isolated server, two client namespaces, IPv4/IPv6, no host sockets/ports",
            flush=True,
        )

    def probe(self, service, family, **request):
        result = execute(
            service,
            "python",
            "/test/probe.py",
            data=json.dumps(
                {
                    "host": self.addresses["knocker"][family] + ("%eth0" if family == 6 else ""),
                    "time_scale": TIME_SCALE,
                    **request,
                }
            ),
        )
        return json.loads(result.stdout)

    def http(self, family=4, service="client", path="/knock", key=PERSONAL_KEY, **body):
        if "ttl" in body:
            body["ttl"] = int(body["ttl"] * TIME_SCALE)
        headers = {"X-Api-Key": key}
        result = self.probe(
            service, family, kind="http", path=path, method="POST", headers=headers, body=body
        )
        return result

    def access(self, allowed, family, service="client"):
        # The control service distinguishes firewall blocking from an unreachable server.
        control = self.probe(service, family, kind="tcp", port=9002)
        self.assertTrue(control["allowed"], control)
        for protocol, port in PORTS:
            with self.subTest(service=service, family=family, protocol=protocol):
                result = self.probe(service, family, kind=protocol, port=port)
                self.assertEqual(result["allowed"], allowed, result)
                if not allowed:
                    self.assertEqual(result["error"], "timeout", result)

    def expires(self, family, service="client", deadline=None):
        deadline = deadline or time.monotonic() + 20 * TIME_SCALE
        # Inspect the real daemon, then verify its expiry actually blocks packets.
        ip = self.addresses[service][family]
        while ip in firewall("--zone=knocker", "--list-rich-rules"):
            self.assertLess(time.monotonic(), deadline, "Timed rules did not expire")
            time.sleep(0.25)
        self.access(False, family, service)

    def restart(self):
        command([*COMPOSE, "restart", "knocker"])
        deadline = time.monotonic() + 90 * TIME_SCALE
        while True:
            result = execute(
                "knocker", "curl", "--fail", "--silent", "http://localhost:8000/ready", check=False
            )
            if result.returncode == 0:
                # Recent Docker versions regenerate a container's MAC on
                # restart, which changes its IPv6 link-local address.
                container_id = command([*COMPOSE, "ps", "-q", "knocker"]).stdout.strip()
                info = json.loads(command(["docker", "inspect", container_id]).stdout)[0]
                network = next(iter(info["NetworkSettings"]["Networks"].values()))
                self.addresses["knocker"] = {
                    4: network["IPAddress"],
                    6: link_address("knocker"),
                }
                return
            self.assertLess(time.monotonic(), deadline, result.stderr)
            time.sleep(0.5)

    def test_01_closed_ports_and_rejected_knocks(self):
        self.assertEqual(firewall("--state"), "running")
        self.assertEqual(firewall("--permanent", "--zone=knocker", "--get-target"), "ACCEPT")
        self.assertEqual(firewall("--permanent", "--zone=knocker", "--get-priority"), "-100")
        for family in (4, 6):
            self.access(False, family)
            self.access(False, family, "stranger")
            response = self.http(family, key="invalid")
            self.assertEqual(response["status"], 401, response)
            response = self.http(family, ip_address=self.addresses["stranger"][family])
            self.assertEqual(response["status"], 403, response)
        self.assertNotIn("source address=", firewall("--zone=knocker", "--list-rich-rules"))

    def test_02_ipv4_knock_and_expiry(self):
        self.knock_cycle(4)

    def test_03_ipv6_knock_and_expiry(self):
        self.knock_cycle(6)

    def knock_cycle(self, family):
        # A spoofed forwarded header must not authorize the other client's IP.
        response = self.probe(
            "client",
            family,
            kind="http",
            path="/knock",
            method="POST",
            headers={
                "X-Api-Key": PERSONAL_KEY,
                "X-Forwarded-For": self.addresses["stranger"][family],
            },
            body={"ttl": int(8 * TIME_SCALE)},
        )
        self.assertEqual(response["status"], 200, response)
        self.assertEqual(response["body"]["whitelisted_entry"], self.addresses["client"][family])
        self.access(True, family)
        self.access(False, family, "stranger")
        self.expires(family)

    def test_04_remote_whitelist_and_cidr(self):
        response = self.http(key=ADMIN_KEY, ip_address=self.addresses["stranger"][4], ttl=8)
        self.assertEqual(response["status"], 200, response)
        self.access(True, 4, "stranger")
        self.access(False, 4)
        self.expires(4, "stranger")

        # Both clients are on the same private IPv6 link.
        cidr = str(ipaddress.ip_network(self.addresses["client"][6] + "/64", strict=False))
        self.assertIn(
            ipaddress.ip_address(self.addresses["stranger"][6]), ipaddress.ip_network(cidr)
        )
        response = self.http(key=ADMIN_KEY, ip_address=cidr, ttl=8)
        self.assertEqual(response["status"], 200, response)
        self.access(True, 6)
        self.access(True, 6, "stranger")
        deadline = time.monotonic() + 20 * TIME_SCALE
        while cidr in firewall("--zone=knocker", "--list-rich-rules"):
            self.assertLess(time.monotonic(), deadline, "CIDR rules did not expire")
            time.sleep(0.25)
        self.access(False, 6)
        self.access(False, 6, "stranger")

    def test_05_shorter_ttl_replaces_existing_rules(self):
        self.assertEqual(self.http(ttl=120)["status"], 200)
        response = self.http(ttl=6)
        self.assertEqual(response["status"], 200, response)
        self.access(True, 4)
        self.expires(4, deadline=time.monotonic() + 15 * TIME_SCALE)

    def test_06_restart_restores_all_missing_rules(self):
        expiry = {}
        for family in (4, 6):
            response = self.http(family, ttl=120)
            self.assertEqual(response["status"], 200, response)
            expiry[self.addresses["client"][family]] = response["body"]["expires_at"]
            for protocol, port in PORTS:
                exact = rule(self.addresses["client"][family], protocol, port)
                self.assertEqual(firewall("--zone=knocker", f"--query-rich-rule={exact}"), "yes")
                firewall("--zone=knocker", f"--remove-rich-rule={exact}")
                self.assertEqual(
                    firewall("--zone=knocker", f"--query-rich-rule={exact}", check=False), "no"
                )
            self.access(False, family)
        # A real reload flushes runtime state; persistence must restore it on startup.
        firewall("--reload")
        self.restart()
        for family in (4, 6):
            self.access(True, family)
            self.access(False, family, "stranger")
        persisted = json.loads(execute("knocker", "cat", "/data/whitelist.json").stdout)
        for ip, timestamp in expiry.items():
            self.assertEqual(persisted[ip], timestamp, "Restart extended the original TTL")

    def test_07_readiness_detects_missing_protection(self):
        default_rule = 'rule family="ipv4" port port="9000" protocol="tcp" drop priority="9999"'
        firewall("--zone=knocker", f"--remove-rich-rule={default_rule}")
        try:
            ready = self.probe("client", 4, kind="http", path="/ready")
            self.assertEqual(ready["status"], 503, ready)
            health = self.probe("client", 4, kind="http", path="/health")
            self.assertEqual(health["status"], 200, health)
        finally:
            firewall("--zone=knocker", f"--add-rich-rule={default_rule}")
        self.assertEqual(self.probe("client", 4, kind="http", path="/ready")["status"], 200)

    def test_08_daemon_failure_does_not_persist_access(self):
        execute(
            "knocker",
            "python",
            "-c",
            "import os, signal; "
            "os.kill(int(open('/run/test-firewalld.pid').read()), signal.SIGTERM)",
        )
        deadline = time.monotonic() + 15 * TIME_SCALE
        while execute("knocker", "firewall-cmd", "--state", check=False).returncode == 0:
            self.assertLess(time.monotonic(), deadline, "FirewallD did not stop")
            time.sleep(0.25)
        response = self.http(service="stranger", ttl=60)
        self.assertEqual(response["status"], 500, response)
        persisted = json.loads(execute("knocker", "cat", "/data/whitelist.json").stdout)
        self.assertNotIn(self.addresses["stranger"][4], persisted)
        self.assertEqual(self.probe("client", 4, kind="http", path="/ready")["status"], 503)
        self.assertEqual(self.probe("client", 4, kind="http", path="/health")["status"], 200)
        self.access(False, 4, "stranger")
        self.restart()
        self.access(False, 4, "stranger")


if __name__ == "__main__":
    # These scenarios share one ordered fixture. Stop on a broken precondition.
    unittest.main(verbosity=2, failfast=True)
